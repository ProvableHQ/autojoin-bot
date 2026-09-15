use std::{collections::HashMap, str::FromStr};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{PublicKey, aead::OsRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snarkvm_circuit_network::Aleo;
use snarkvm_console::{
    account::PrivateKey,
    prelude::Network,
    program::{Identifier, Value as ProgramValue},
};
use snarkvm_synthesizer::{Process, Program};
use zeroize::Zeroizing;

use crate::{
    http::decode_response,
    network::AleoNetwork,
    records::{OwnedRecord, RecordFamily},
};

#[derive(Clone)]
pub struct DelegatedProverClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct PubkeyResponse {
    key_id: String,
    public_key: String,
}

#[derive(Serialize)]
struct AuthorizationProvingRequest<T> {
    broadcast: bool,
    payload: AuthorizationPayload<T>,
}

#[derive(Serialize)]
struct AuthorizationPayload<T> {
    #[serde(rename = "type")]
    payload_type: &'static str,
    authorization: T,
}

fn authorization_proving_request<T>(authorization: T) -> AuthorizationProvingRequest<T> {
    AuthorizationProvingRequest {
        broadcast: true,
        payload: AuthorizationPayload {
            payload_type: "authorization",
            authorization,
        },
    }
}

impl DelegatedProverClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    fn pubkey_url(&self) -> String {
        format!("{}/pubkey", self.base_url)
    }

    fn prove_url(&self) -> String {
        format!("{}/prove", self.base_url)
    }

    pub async fn prove_and_broadcast<N: Network, A: Aleo<Network = N>>(
        &self,
        private_key: &PrivateKey<N>,
        network: AleoNetwork,
        family: RecordFamily,
        records: &[&OwnedRecord],
    ) -> Result<Value> {
        let (program_id, function_name) =
            join_call(family, network, records.len()).with_context(|| {
                format!(
                    "{} join size must be between 2 and {} for {}",
                    family.name(),
                    family.max_batch(),
                    network.as_str()
                )
            })?;
        let mut roots = vec![program_id];
        if family.token_identifier(network).is_some() {
            roots.push(
                family
                    .record_program(network)
                    .context("ARC20 autojoin is not configured for this network")?,
            );
        }
        let programs = self.fetch_program_graph::<N>(network, &roots).await?;
        let authorization = authorize::<N, A>(
            private_key,
            family,
            network,
            records,
            &programs,
            program_id,
            function_name,
        )?;
        let request = authorization_proving_request(authorization);
        self.submit(request).await
    }

    async fn fetch_program_graph<N: Network>(
        &self,
        network: AleoNetwork,
        root_programs: &[&str],
    ) -> Result<Vec<Program<N>>> {
        let mut pending = root_programs
            .iter()
            .map(|program| (*program).to_owned())
            .collect::<Vec<_>>();
        let mut programs = HashMap::new();

        while let Some(program_id) = pending.pop() {
            if program_id == "credits.aleo" || programs.contains_key(&program_id) {
                continue;
            }
            let source_url = format!(
                "https://api.explorer.provable.com/v2/{}/program/{program_id}",
                network.as_str()
            );
            let response = self.client.get(source_url).send().await?;
            let source: String = decode_response(response, "Autojoin-program fetch").await?;
            let program = Program::<N>::from_str(&source)
                .with_context(|| format!("invalid deployed program source for {program_id}"))?;
            pending.extend(program.imports().keys().map(ToString::to_string));
            programs.insert(program_id, program);
        }

        topological_programs(programs)
    }

    async fn submit(&self, request: impl Serialize) -> Result<Value> {
        let pubkey_response = self.client.get(self.pubkey_url()).send().await?;
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

        let prove_request = self.client.post(self.prove_url()).json(&json!({
            "key_id": pubkey.key_id,
            "ciphertext": STANDARD.encode(ciphertext),
        }));
        let prove_request = if let Some(cookie) = cookie {
            prove_request.header(reqwest::header::COOKIE, cookie)
        } else {
            prove_request
        };
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
    family: RecordFamily,
    network: AleoNetwork,
    records: &[&OwnedRecord],
    programs: &[Program<N>],
    root_program: &str,
    function_name: &str,
) -> Result<snarkvm_synthesizer::Authorization<N>> {
    let program = programs
        .iter()
        .find(|program| program.id().to_string() == root_program)
        .context("autojoin root program is missing")?;
    let process = Process::<N>::load().context("failed to initialize authorization process")?;
    for dependency in programs {
        process
            .lock()
            .add_program(dependency)
            .with_context(|| format!("failed to load {}", dependency.id()))?;
    }
    let mut inputs =
        Vec::with_capacity(records.len() + usize::from(family.token_identifier(network).is_some()));
    if let Some(token_identifier) = family.token_identifier(network) {
        inputs.push(
            ProgramValue::<N>::from_str(&format!("'{token_identifier}'"))
                .context("invalid ARC20 token program identifier")?,
        );
    }
    inputs.extend(
        records
            .iter()
            .map(|record| {
                let plaintext = record
                    .record_plaintext
                    .as_deref()
                    .context("owned record is missing a decrypted plaintext")?;
                ProgramValue::<N>::from_str(plaintext)
                    .context("scanner returned an invalid record plaintext")
            })
            .collect::<Result<Vec<_>>>()?,
    );
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

fn topological_programs<N: Network>(
    mut programs: HashMap<String, Program<N>>,
) -> Result<Vec<Program<N>>> {
    let mut ordered = Vec::with_capacity(programs.len());
    let mut loaded = std::collections::HashSet::from(["credits.aleo".to_owned()]);

    while !programs.is_empty() {
        let ready = programs.iter().find_map(|(id, program)| {
            program
                .imports()
                .keys()
                .all(|dependency| loaded.contains(&dependency.to_string()))
                .then(|| id.clone())
        });
        let id = ready.context("autojoin program imports contain a cycle or missing dependency")?;
        let program = programs.remove(&id).expect("selected from map");
        loaded.insert(id);
        ordered.push(program);
    }

    Ok(ordered)
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
    join_call(RecordFamily::Credits, AleoNetwork::Mainnet, count)
}

pub const fn join_call(
    family: RecordFamily,
    network: AleoNetwork,
    count: usize,
) -> Option<(&'static str, &'static str)> {
    let program = match (family, network, count) {
        (RecordFamily::Credits, _, 2..=10) => "autojoin_credits_2_10.aleo",
        (RecordFamily::Credits, _, 11..=14) => "autojoin_credits_11_14.aleo",
        (RecordFamily::Credits, _, 15..=16) => "autojoin_credits_15_16.aleo",
        (RecordFamily::Usdcx, AleoNetwork::Mainnet, 2..=10) => "aj_usdcx_stablecoin_2_10.aleo",
        (RecordFamily::Usdcx, AleoNetwork::Mainnet, 11..=14) => "aj_usdcx_stablecoin_11_14.aleo",
        (RecordFamily::Usdcx, AleoNetwork::Mainnet, 15..=16) => "aj_usdcx_stablecoin_15_16.aleo",
        (RecordFamily::Usdcx, AleoNetwork::Testnet, 2..=10) => "aj_test_usdcx_stablecoin_2_10.aleo",
        (RecordFamily::Usdcx, AleoNetwork::Testnet, 11..=14) => {
            "aj_test_usdcx_stablecoin_11_14.aleo"
        }
        (RecordFamily::Usdcx, AleoNetwork::Testnet, 15..=16) => {
            "aj_test_usdcx_stablecoin_15_16.aleo"
        }
        (
            RecordFamily::Arc20Eth | RecordFamily::Arc20Sol | RecordFamily::Arc20Wbtc,
            AleoNetwork::Mainnet,
            2..=15,
        ) => "main_aj_arc20_2_15.aleo",
        (
            RecordFamily::Arc20Eth | RecordFamily::Arc20Sol | RecordFamily::Arc20Wbtc,
            AleoNetwork::Testnet,
            2..=15,
        ) => "test_aj_arc20_2_15.aleo",
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
    fn edge_routes_are_network_scoped() {
        let client = DelegatedProverClient::new(AleoNetwork::Mainnet.prover_endpoint());
        assert_eq!(
            client.pubkey_url(),
            "https://edge.provable.com/api/prove/mainnet/pubkey"
        );
        assert_eq!(
            client.prove_url(),
            "https://edge.provable.com/api/prove/mainnet/prove"
        );
    }

    #[test]
    fn proving_request_omits_optional_job_id_for_edge_compatibility() {
        let request = serde_json::to_value(authorization_proving_request(json!({
            "requests": [],
            "transitions": [],
        })))
        .unwrap();

        assert_eq!(request["broadcast"], true);
        assert_eq!(request["payload"]["type"], "authorization");
        assert!(request.get("job_id").is_none());
    }

    use snarkvm_console::prelude::TestnetV0;

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
        assert_eq!(
            join_call(RecordFamily::Usdcx, AleoNetwork::Mainnet, 2),
            Some(("aj_usdcx_stablecoin_2_10.aleo", "join_2"))
        );
        assert_eq!(
            join_call(RecordFamily::Usdcx, AleoNetwork::Testnet, 11)
                .unwrap()
                .0,
            "aj_test_usdcx_stablecoin_11_14.aleo"
        );
        assert_eq!(
            join_call(RecordFamily::Usdcx, AleoNetwork::Testnet, 16),
            Some(("aj_test_usdcx_stablecoin_15_16.aleo", "join_16"))
        );
        assert_eq!(
            join_call(RecordFamily::Arc20Eth, AleoNetwork::Mainnet, 15),
            Some(("main_aj_arc20_2_15.aleo", "join_15"))
        );
        assert_eq!(
            join_call(RecordFamily::Arc20Wbtc, AleoNetwork::Mainnet, 16),
            None
        );
        assert_eq!(
            join_call(RecordFamily::Arc20Sol, AleoNetwork::Testnet, 2),
            Some(("test_aj_arc20_2_15.aleo", "join_2"))
        );
    }

    #[test]
    fn import_graph_is_ordered_before_root() {
        let dependency = Program::<TestnetV0>::from_str(
            "program dependency.aleo;\n\nfunction noop:\n    input r0 as u8.public;\n    output r0 as u8.public;\n",
        )
        .unwrap();
        let root = Program::<TestnetV0>::from_str(
            "import dependency.aleo;\n\nprogram root.aleo;\n\nfunction noop:\n    input r0 as u8.public;\n    output r0 as u8.public;\n",
        )
        .unwrap();
        let programs = HashMap::from([
            ("root.aleo".to_owned(), root),
            ("dependency.aleo".to_owned(), dependency),
        ]);
        let ordered = topological_programs(programs).unwrap();
        assert_eq!(ordered[0].id().to_string(), "dependency.aleo");
        assert_eq!(ordered[1].id().to_string(), "root.aleo");
    }

    #[test]
    fn arc20_program_identifier_is_a_valid_public_input() {
        assert!(ProgramValue::<TestnetV0>::from_str("'arc20_eth'").is_ok());
    }
}
