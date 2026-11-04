mod transport {
    use reqwest::Client;
    #[cfg(all())]
    pub fn client() {
        let _client = Client::builder().use_native_tls()
            .danger_accept_invalid_hostnames(false).build().expect("client configuration");
    }
    #[cfg(any())]
    fn disabled_control() {
        let _client = Client::builder().use_native_tls()
            .danger_accept_invalid_hostnames(true).build().expect("inactive configuration");
    }
}
fn main() { transport::client(); }
