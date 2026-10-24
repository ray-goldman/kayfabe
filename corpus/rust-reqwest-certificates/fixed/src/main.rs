use reqwest::Client;
fn main() {
    let _client = Client::builder()
        .danger_accept_invalid_certs(false)
        .build().expect("client configuration");
}
