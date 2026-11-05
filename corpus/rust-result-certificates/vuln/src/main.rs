use reqwest::Client;
fn main() -> Result<(), reqwest::Error> {
    let _client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    Ok(())
}
