#![cfg_attr(not(feature = "std"), no_std)]

//! A module using offchain workers to fetch the crypto price and expose
//! it to other modules. Heavily tied to the Nodle Cash, but should be easy
//! to adapt to other tickers.

use frame_support::{
    decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    traits::{Currency, ExistenceRequirement, Imbalance, OnUnbalanced},
};
use sp_runtime::{
    traits::{AccountIdConversion, EnsureOrigin},
    ModuleId,
};
use system::ensure_signed;

/// The module's configuration trait.
pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// How we represent the token price
    type Price: Parameter
        + Member
        + AtLeast32Bit
        + Codec
        + Default
        + Copy
        + MaybeSerializeDeserialize
        + Debug;
}

decl_storage! {
    trait Store for Module<T: Trait> as PriceOracle {}
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        // TODO.
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
        Price = <T as system::Trait>::Price,
    {
        /// We updated the price of the token.
        PriceUpdated(Price),
        /// An offchain worker reported a new price.
        PriceReported(AccountId, Price),
    }
);
