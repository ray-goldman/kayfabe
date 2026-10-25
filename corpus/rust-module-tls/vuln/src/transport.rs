use reqwest::Client;
pub fn client() {
    let _client = Client::builder().danger_accept_invalid_certs(true)
        .build().expect("client configuration");
}
