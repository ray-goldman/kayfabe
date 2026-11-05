fn main() -> Result<(), reqwest::Error> {
    let _client = reqwest::Client::builder()
        .use_native_tls()
        .danger_accept_invalid_hostnames(false)
        .build()?;
    Ok(())
}
