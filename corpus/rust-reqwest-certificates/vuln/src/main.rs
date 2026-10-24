use reqwest::Client;
fn main() {
    let _client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build().expect("client configuration");
}
