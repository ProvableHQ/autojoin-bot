use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub(crate) async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    action: &str,
) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("{action} failed (HTTP {status}): {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("{action} returned invalid JSON"))
}
