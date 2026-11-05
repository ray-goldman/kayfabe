use reqwest::Client;
fn main() -> Result<(), reqwest::Error> {
    let builder = Client::builder().danger_accept_invalid_hostnames(true);
    let _client = builder.use_native_tls().danger_accept_invalid_hostnames(false).build()?;
    Ok(())
}
