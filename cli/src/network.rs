use std::str::FromStr;

use anyhow::{Result, bail};

pub const EDGE_SCANNER_ROOT: &str = "https://edge.provable.com/api/scanner";
pub const EDGE_PROVER_ROOT: &str = "https://edge.provable.com/api/prove";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AleoNetwork {
    Mainnet,
    Testnet,
}

impl AleoNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    pub fn prover_endpoint(self) -> String {
        format!("{EDGE_PROVER_ROOT}/{}", self.as_str())
    }
}

impl FromStr for AleoNetwork {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => bail!("ALEO_NETWORK must be either mainnet or testnet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_is_strict() {
        assert_eq!(
            "mainnet".parse::<AleoNetwork>().unwrap(),
            AleoNetwork::Mainnet
        );
        assert_eq!(
            "TESTNET".parse::<AleoNetwork>().unwrap(),
            AleoNetwork::Testnet
        );
        assert!("devnet".parse::<AleoNetwork>().is_err());
        assert_eq!(
            AleoNetwork::Mainnet.prover_endpoint(),
            "https://edge.provable.com/api/prove/mainnet"
        );
    }
}
