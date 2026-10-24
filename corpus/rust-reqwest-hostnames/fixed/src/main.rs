use reqwest::{Client as Http};
fn main() {
    let _client = Http::builder().use_native_tls()
        .danger_accept_invalid_hostnames(false)
        .build().expect("client configuration");
}
