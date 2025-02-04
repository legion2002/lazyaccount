use alloy::primitives::{Address, FixedBytes};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use toml;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub general: GeneralConfig,
}
#[derive(Deserialize, Debug)]
pub struct GeneralConfig {
    pub account_address: Option<Address>,
    pub validator_modules: Vec<Address>,
    pub account_salt: FixedBytes<32>,
    pub owners: Vec<Address>,
}

pub fn parse_config(file_path: PathBuf) -> Result<Config, Box<dyn std::error::Error>> {
    // Read the contents of the file
    let contents = fs::read_to_string(file_path)?;

    // Parse the TOML content
    let config: Config = toml::from_str(&contents)?;

    Ok(config)
}
