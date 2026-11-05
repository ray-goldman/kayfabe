use reqwest::Client;
use std::time::Duration;
fn main() -> Result<(), reqwest::Error> {
    let builder = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5));
    let _client = builder.danger_accept_invalid_certs(false).build()?;
    Ok(())
}
