use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{PublicKey, aead::OsRng};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use snarkvm_circuit_network::Aleo;
use snarkvm_console::{
    account::PrivateKey,
    prelude::Network,
    program::{Identifier, Value as ProgramValue},
};
use snarkvm_synthesizer::{Process, Program};
use zeroize::Zeroizing;

use crate::{http::decode_response, network::AleoNetwork, records::OwnedRecord};

#[derive(Clone)]
pub struct DelegatedProverClient {
    client: Client,
    base_url: String,
    token: Option<Zeroizing<String>>,
}

#[derive(Debug, Deserialize)]
struct PubkeyResponse {
    key_id: String,
    public_key: String,
}

impl DelegatedProverClient {
    pub fn new(base_url: String, token: Option<Zeroizing<String>>) -> Self {
        Self {
            client: Client::new(),
            base_url,
            token,
        }
    }

    pub async fn prove_and_broadcast<N: Network, A: Aleo<Network = N>>(
        &self,
        private_key: &PrivateKey<N>,
        network: AleoNetwork,
        records: &[&OwnedRecord],
    ) -> Result<Value> {
        let (program_id, function_name) = credits_join_call(records.len())
            .context("credits join size must be between 2 and 16")?;
        let source_url = format!(
            "https://api.explorer.provable.com/v2/{}/program/{program_id}",
            network.as_str()
        );
        let source_response = self.client.get(source_url).send().await?;
        let source: String = decode_response(source_response, "Autojoin-program fetch").await?;
        let authorization = authorize::<N, A>(private_key, records, &source, function_name)?;
        let request = json!({
            "broadcast": true,
            "job_id": format!("{:032x}", rand::random::<u128>()),
            "payload": {
                "type": "authorization",
                "authorization": authorization,
            }
        });
        self.submit(request).await
    }

    async fn submit(&self, request: Value) -> Result<Value> {
        let mut pubkey_request = self.client.get(format!("{}/pubkey", self.base_url));
        if let Some(token) = &self.token {
            pubkey_request = pubkey_request.bearer_auth(token.as_str());
        }
        let pubkey_response = pubkey_request.send().await?;
        let cookie = pubkey_response
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::to_owned);
        let pubkey: PubkeyResponse =
            decode_response(pubkey_response, "Delegated-prover public-key request").await?;
        let public_key: [u8; 32] = STANDARD
            .decode(pubkey.public_key)?
            .try_into()
            .map_err(|_| anyhow!("delegated prover public key must be 32 bytes"))?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&request)?);
        let ciphertext = PublicKey::from(public_key)
            .seal(&mut OsRng, &plaintext)
            .map_err(|error| anyhow!("failed to encrypt delegated proving request: {error}"))?;

        let mut prove_request = self
            .client
            .post(format!("{}/prove", self.base_url))
            .json(&json!({
                "key_id": pubkey.key_id,
                "ciphertext": STANDARD.encode(ciphertext),
            }));
        if let Some(token) = &self.token {
            prove_request = prove_request.bearer_auth(token.as_str());
        }
        if let Some(cookie) = cookie {
            prove_request = prove_request.header(reqwest::header::COOKIE, cookie);
        }
        let result: Value =
            decode_response(prove_request.send().await?, "Delegated proving").await?;
        if !broadcast_accepted(&result) {
            bail!(
                "delegated prover did not accept the broadcast: {}",
                result["broadcast_result"]
            );
        }
        Ok(result)
    }
}

fn authorize<N: Network, A: Aleo<Network = N>>(
    private_key: &PrivateKey<N>,
    records: &[&OwnedRecord],
    source: &str,
    function_name: &str,
) -> Result<snarkvm_synthesizer::Authorization<N>> {
    let program = Program::<N>::from_str(source).context("invalid deployed autojoin program")?;
    let process = Process::<N>::load().context("failed to initialize authorization process")?;
    process
        .lock()
        .add_program(&program)
        .with_context(|| format!("failed to load {}", program.id()))?;
    let inputs = records
        .iter()
        .map(|record| {
            ProgramValue::<N>::from_str(
                record
                    .record_plaintext
                    .as_deref()
                    .expect("credits records were validated"),
            )
            .context("scanner returned an invalid credits record plaintext")
        })
        .collect::<Result<Vec<_>>>()?;
    process
        .authorize::<A, _>(
            private_key,
            program.id(),
            Identifier::<N>::from_str(function_name)?,
            inputs.iter(),
            &mut rand::rng(),
        )
        .context("failed to authorize autojoin call")
}

fn broadcast_accepted(result: &Value) -> bool {
    result.get("broadcast_result").is_some_and(|broadcast| {
        broadcast.get("Accepted").is_some()
            || broadcast
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status.eq_ignore_ascii_case("accepted"))
    })
}

pub const fn credits_join_call(count: usize) -> Option<(&'static str, &'static str)> {
    let program = match count {
        2..=10 => "autojoin_credits_2_10.aleo",
        11..=14 => "autojoin_credits_11_14.aleo",
        15..=16 => "autojoin_credits_15_16.aleo",
        _ => return None,
    };
    let function = match count {
        2 => "join_2",
        3 => "join_3",
        4 => "join_4",
        5 => "join_5",
        6 => "join_6",
        7 => "join_7",
        8 => "join_8",
        9 => "join_9",
        10 => "join_10",
        11 => "join_11",
        12 => "join_12",
        13 => "join_13",
        14 => "join_14",
        15 => "join_15",
        16 => "join_16",
        _ => return None,
    };
    Some((program, function))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_program_bands_are_exact() {
        assert_eq!(
            credits_join_call(2),
            Some(("autojoin_credits_2_10.aleo", "join_2"))
        );
        assert_eq!(
            credits_join_call(10).unwrap().0,
            "autojoin_credits_2_10.aleo"
        );
        assert_eq!(
            credits_join_call(11).unwrap().0,
            "autojoin_credits_11_14.aleo"
        );
        assert_eq!(
            credits_join_call(14).unwrap().0,
            "autojoin_credits_11_14.aleo"
        );
        assert_eq!(
            credits_join_call(15).unwrap().0,
            "autojoin_credits_15_16.aleo"
        );
        assert_eq!(
            credits_join_call(16),
            Some(("autojoin_credits_15_16.aleo", "join_16"))
        );
        assert_eq!(credits_join_call(1), None);
        assert_eq!(credits_join_call(17), None);
    }
}
