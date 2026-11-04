use reqwest::Client;
pub fn client() {
    let _client = Client::builder().danger_accept_invalid_certs(false)
        .build().expect("client configuration");
}
