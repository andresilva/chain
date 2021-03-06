/*
 * This file is part of the Nodle Chain distributed at https://github.com/NodleCode/chain
 * Copyright (C) 2020  Nodle International
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use crate::chain_spec;
use crate::cli::Cli;
use crate::service;
use sc_cli::VersionInfo;

/// Parse and run command line arguments
pub fn run(version: VersionInfo) -> sc_cli::Result<()> {
    let opt = sc_cli::from_args::<Cli>(&version);

    let mut config = sc_service::Configuration::from_version(&version);

    match opt.subcommand {
        Some(subcommand) => {
            subcommand.init(&version)?;
            subcommand.update_config(&mut config, chain_spec::load_spec, &version)?;
            subcommand.run(config, |config: _| Ok(new_full_start!(config).0))
        }
        None => {
            opt.run.init(&version)?;
            opt.run
                .update_config(&mut config, chain_spec::load_spec, &version)?;
            opt.run
                .run(config, service::new_light, service::new_full, &version)
        }
    }
}
