#![cfg_attr(not(feature = "std"), no_std)]

//! A module using offchain workers to fetch the crypto price and expose
//! it to other modules.

use codec::{Decode, Encode};
use frame_support::{
    debug, decl_error, decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    traits::{Currency, Get},
    Parameter,
};
use session::historical::IdentificationTuple;
use sp_application_crypto::RuntimeAppPublic;
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
    traits::{CheckedAdd, CheckedDiv, Convert, Member},
    transaction_validity::{
        InvalidTransaction, TransactionPriority, TransactionValidity, ValidTransaction,
    },
    Perbill, RuntimeDebug,
};
use sp_staking::offence::ReportOffence;
use sp_std::{convert::TryInto, prelude::*};
use system::offchain::SubmitUnsignedTransaction;
use system::{self as system, ensure_none};

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"pric");
pub mod sr25519 {
    mod app_sr25519 {
        use crate::KEY_TYPE;
        use sp_application_crypto::{app_crypto, sr25519};
        app_crypto!(sr25519, KEY_TYPE);
    }

    //sp_application_crypto::with_pair! {
    //    /// A price oracle keypair using sr25519 as its crypto.
    //    pub type AuthorityPair = app_sr25519::Pair;
    //}

    #[cfg(feature = "std")]
    pub type AuthorityPair = app_sr25519::Pair;

    /// A price oracle signature using sr25519 as its crypto.
    pub type AuthoritySignature = app_sr25519::Signature;

    /// A price oracle identifier using sr25519 as its crypto.
    pub type AuthorityId = app_sr25519::Public;
}

pub mod offences {
    use sp_runtime::{Perbill, RuntimeDebug};
    use sp_staking::{
        offence::{Kind, Offence},
        SessionIndex,
    };

    /// An offence that is filed if a validator didn't report a price.
    pub type UnresponsivenessOffence<Offender> = GenericOffense<Offender>;
    pub type SuspiciousSlippageOffence<Offender> = GenericOffense<Offender>;

    #[derive(RuntimeDebug)]
    #[cfg_attr(feature = "std", derive(Clone, PartialEq, Eq))]
    pub struct GenericOffense<Offender> {
        /// The current session index in which we report the unresponsive validators.
        pub session_index: SessionIndex,
        /// The size of the validator set in current session/era.
        pub validator_set_count: u32,
        /// Authorities that were unresponsive during the current era.
        pub offenders: Vec<Offender>,
    }

    impl<Offender: Clone> Offence<Offender> for GenericOffense<Offender> {
        const ID: Kind = *b"price-oracle:off";
        type TimeSlot = SessionIndex;

        fn offenders(&self) -> Vec<Offender> {
            self.offenders.clone()
        }

        fn session_index(&self) -> SessionIndex {
            self.session_index
        }

        fn validator_set_count(&self) -> u32 {
            self.validator_set_count
        }

        fn time_slot(&self) -> Self::TimeSlot {
            self.session_index
        }

        fn slash_fraction(_offenders: u32, _validator_set_count: u32) -> Perbill {
            // TODO: investigate if a better slashing can be implemented
            Perbill::from_percent(5)
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PriceReport<ValidatorId, AuthorityId, Price> {
    /// The account linked to the authority id.
    pub validator_id: ValidatorId,
    /// An index of the authority on the list of validators.
    pub authority_id: AuthorityId,
    /// The price as reported.
    pub price: Price,
}

type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

/// The module's configuration trait.
pub trait Trait: system::Trait + session::historical::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Call: From<Call<Self>>;
    type AuthorityId: Member + Parameter + RuntimeAppPublic + Default + Ord;
    type SubmitTransaction: SubmitUnsignedTransaction<Self, <Self as Trait>::Call>;
    type Currency: Currency<Self::AccountId>;

    /// How often we should run the offchain worker in blocks.
    type PriceFetchDelay: Get<<Self as system::Trait>::BlockNumber>;
    /// How often we should aggregate prices in blocks.
    type PriceAggregationDelay: Get<<Self as system::Trait>::BlockNumber>;

    /// Hook to report validators not submitting prices.
    type ReportUnresponsiveness: ReportOffence<
        Self::AccountId,
        IdentificationTuple<Self>,
        offences::UnresponsivenessOffence<IdentificationTuple<Self>>,
    >;

    /// Hook to report validators submitting prices that are too far from
    /// the median price reported.
    type ReportSuspiciousSlippage: ReportOffence<
        Self::AccountId,
        IdentificationTuple<Self>,
        offences::SuspiciousSlippageOffence<IdentificationTuple<Self>>,
    >;
    /// How much slippage we tolerate
    type ToleratedSlippage: Get<Perbill>;
}

decl_storage! {
    trait Store for Module<T: Trait> as PriceOracle {
        /// Different price reports from the authorities
        PriceReported get(price_reported): Vec<(T::AuthorityId, BalanceOf<T>)>;
        /// The token price aggregated from all different sources
        Price get(price): BalanceOf<T>;
        /// Current set of keys that can fetch and propose prices
        Keys get(fn keys): Vec<(T::ValidatorId, T::AuthorityId)>;
    }
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        fn report_price(
            origin,
            report: PriceReport<T::ValidatorId, T::AuthorityId, BalanceOf<T>>,
            // since signature verification is done in `validate_unsigned`
            // we can skip doing it here again.
            _signature: <T::AuthorityId as RuntimeAppPublic>::Signature
        ) -> DispatchResult {
            ensure_none(origin)?;

            match Self::first_report_for_authority(report.authority_id.clone()) {
                Some(_) => Err(Error::<T>::AlreadyReported)?,
                None => {
                    <PriceReported<T>>::mutate(|m| m.push((report.authority_id.clone(), report.price.clone())));
                    Self::deposit_event(RawEvent::PriceReported(report.authority_id, report.price));
                    Ok(())
                },
            }
        }

        fn offchain_worker(now: T::BlockNumber) {
            if sp_io::offchain::is_validator() && now % T::PriceFetchDelay::get() == 0.into() {
                Self::local_authority_keys()
                    .map(|(validator_id, authority_id)| {
                        let price = Self::fetch_token_price();
                        let data = PriceReport {
                            validator_id: validator_id,
                            authority_id: authority_id.clone(),
                            price: price
                        };

                        match authority_id.sign(&data.encode()) {
                            Some(signature) => {
                                let call = Call::report_price(data, signature);

                                debug::info!(
                                    target: "price-oracle",
                                    "Reporting price {:?} at block: {:?}: {:?}",
                                    price,
                                    now,
                                    call,
                                );

                                let res = T::SubmitTransaction::submit_unsigned(call);
                                debug::info!(
                                    target: "price-oracle",
                                    "Unsigned submission result at block {:?}: {:?}",
                                    now,
                                    res,
                                )
                            },
                            None => debug::info!(
                                target: "price-oracle",
                                "Unable to sign price report",
                            ),
                        };
                    });
            } else {
                debug::trace!(
                    target: "price-oracle",
                    "Skipping price fetching. validator: {:?}, block: {:?}",
                    sp_io::offchain::is_validator(),
                    now
                )
            }
        }

        fn on_initialize(now: T::BlockNumber) {
            if now % T::PriceAggregationDelay::get() == 0.into() {
                // For every reports:
                // 1. update average
                // 2. update median

                // For every authority key we have
                // 1. if price not reported, mem offence
                // 2. if price reported but slipping too much, mem offence

                // If have offences to report, report x2 + event
                // Else event AllGood

                // END: update price + event
                // END: cleanup report

                let mut sorted_reports = <PriceReported<T>>::get();
                sorted_reports.sort();

                // We can cast a u32 to a Balance more easily
                let nb_reports = sorted_reports.len() as u32;

                let price_average = sorted_reports.clone()
                    .into_iter()
                    .map(|(_id, price)| price)
                    .fold(0.into(), |acc: BalanceOf<T>, p| acc + p)
                    .checked_div(&nb_reports.into())
                    .unwrap_or(1.into());
                let price_median = sorted_reports.clone()
                    .into_iter()
                    .map(|(_id, price)| price)
                    .nth(sorted_reports.len() / 2)
                    .unwrap_or(0.into());

                // Go through authorities and report offences
                let hundred_percent = Perbill::from_percent(100);
                let mut slippage_offenders: Vec<IdentificationTuple<T>> = vec![];
                let mut unresponsive_offenders: Vec<IdentificationTuple<T>> = vec![];
                let keys = <Keys<T>>::get();
                keys.clone()
                    .into_iter()
                    .map(|(validator_id, authority_id)| (
                        validator_id.clone(),
                        authority_id,
                        T::FullIdentificationOf::convert(validator_id.clone())
                    )) // Enrich data + avoid dual fetching
                    .for_each(|(validator_id, authority_id, full_identification)| {
                        if !full_identification.is_some() {
                            return
                        }

                        match Self::first_report_for_authority(authority_id) {
                            Some(reported_price) => {
                                let mut difference: BalanceOf<T> = 0.into();
                                if reported_price > price_median {
                                    difference = reported_price - price_median;
                                } else {
                                    difference = price_median - reported_price;
                                }

                                let average: BalanceOf<T> = reported_price
                                    .checked_add(&price_median).unwrap_or(1.into())
                                    .checked_div(&2.into()).unwrap_or(1.into());
                                let slippage: BalanceOf<T> = difference.checked_div(&average).unwrap_or(0.into());
                                let slippage_pct = hundred_percent * slippage;

                                if slippage_pct > T::ToleratedSlippage::get() * price_median {
                                    // TODO: shall we update the average by removing the slipping value?
                                    slippage_offenders.push((validator_id, full_identification.unwrap()));
                                }
                            },
                            None => unresponsive_offenders.push((validator_id, full_identification.unwrap())),
                        };
                    });

                if slippage_offenders.len() == 0 && unresponsive_offenders.len() == 0 {
                    Self::deposit_event(RawEvent::AllGood);
                } else {
                    let session_index = <session::Module<T>>::current_index();
                    let number_of_validators = keys.len() as u32;

                    if slippage_offenders.len() > 0 {
                        let offence = offences::SuspiciousSlippageOffence{
                            session_index: session_index,
                            validator_set_count: number_of_validators,
                            offenders: slippage_offenders.clone(),
                        };

                        T::ReportSuspiciousSlippage::report_offence(vec![], offence);
                        Self::deposit_event(RawEvent::PriceSlippageReported(slippage_offenders));
                    }

                    if unresponsive_offenders.len() > 0 {
                        let offence = offences::UnresponsivenessOffence{
                            session_index: session_index,
                            validator_set_count: number_of_validators,
                            offenders: unresponsive_offenders.clone(),
                        };

                        T::ReportUnresponsiveness::report_offence(vec![], offence);
                        Self::deposit_event(RawEvent::PriceNotReported(unresponsive_offenders));
                    }
                }

                <Price<T>>::put(price_average);
                <PriceReported<T>>::kill(); // Reset for the next batch
            }
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        AuthorityId = <T as Trait>::AuthorityId,
        Price = BalanceOf<T>,
        IdentificationTuple = IdentificationTuple<T>,
    {
        /// We updated the price of the token.
        PriceUpdated(Price),
        /// An offchain worker reported a new price.
        PriceReported(AuthorityId, Price),
        /// Some validators didn't report a price
        PriceNotReported(Vec<IdentificationTuple>),
        /// Some validators reported an untolerable slipping price
        PriceSlippageReported(Vec<IdentificationTuple>),
        /// Nothing to report
        AllGood,
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// Already reported a price
        AlreadyReported,
    }
}

impl<T: Trait> Module<T> {
    fn local_authority_keys() -> impl Iterator<Item = (T::ValidatorId, T::AuthorityId)> {
        let authorities = Keys::<T>::get();
        let mut local_keys = T::AuthorityId::all();
        local_keys.sort();

        authorities.into_iter().filter_map(move |keys| {
            local_keys
                .binary_search(&keys.1)
                .ok()
                .map(|location| (keys.0, local_keys[location].clone()))
        })
    }

    /// Fetch the token price from external sources such as exchanges and average them
    fn fetch_token_price() -> BalanceOf<T> {
        // TODO: at the moment the Nodle Cash is not listed
        1.into()
    }

    fn first_report_for_authority(auth: T::AuthorityId) -> Option<BalanceOf<T>> {
        for (authority, price) in <PriceReported<T>>::get() {
            if authority == auth {
                return Some(price);
            }
        }

        None
    }
}

impl<T: Trait> sp_runtime::BoundToRuntimeAppPublic for Module<T> {
    type Public = T::AuthorityId;
}

/// Custom session handler to save which keys  can fetch and propose prices
impl<T: Trait> session::OneSessionHandler<T::ValidatorId> for Module<T> {
    type Key = T::AuthorityId;

    fn on_genesis_session<'a, I: 'a>(validators: I)
    where
        I: Iterator<Item = (&'a T::ValidatorId, T::AuthorityId)>,
    {
        Keys::<T>::put(validators.collect::<Vec<_>>());
    }

    fn on_new_session<'a, I: 'a>(_changed: bool, validators: I, _queued_validators: I)
    where
        I: Iterator<Item = (&'a T::ValidatorId, T::AuthorityId)>,
    {
        // Remember who the authorities are for the new session.
        Keys::<T>::put(validators.collect::<Vec<_>>());
    }

    fn on_before_session_ending() {}
    fn on_disabled(_i: usize) {}
}

impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
    type Call = Call<T>;

    fn validate_unsigned(call: &Self::Call) -> TransactionValidity {
        if let Call::report_price(data, signature) = call {
            // verify that the incoming (unverified) pubkey is actually an authority id
            let keys = Keys::<T>::get();
            let matching_autority_keys: Vec<(T::ValidatorId, T::AuthorityId)> = keys
                .into_iter()
                .filter(|(_v, a)| *a == data.authority_id)
                .collect();
            if matching_autority_keys.len() != 1 {
                return InvalidTransaction::BadProof.into();
            }
            let authority_id = &matching_autority_keys[0].1;

            // check signature (this is expensive so we do it last).
            let signature_valid =
                data.using_encoded(|encoded| authority_id.verify(&encoded, &signature));

            if !signature_valid {
                return InvalidTransaction::BadProof.into();
            }

            Ok(ValidTransaction {
                priority: TransactionPriority::max_value(),
                requires: vec![],
                provides: vec![authority_id.encode()],
                longevity: TryInto::<u64>::try_into(T::PriceFetchDelay::get() / 2.into())
                    .unwrap_or(64_u64),
                propagate: true,
            })
        } else {
            InvalidTransaction::Call.into()
        }
    }
}
