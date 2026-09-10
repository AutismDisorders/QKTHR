use crate::module::Module;
use crate::response::Response;
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::time::Duration;

/// HTTP fuzz module – same capabilities as the generic HTTP module.
pub struct HttpFuzzModule {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    follow_redirects: bool,
    timeout: u64,
}

impl HttpFuzzModule {
    pub fn new() -> Self {
        Self {
            url: String::new(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            follow_redirects: true,
            timeout: 10,
        }
    }

    pub fn url(mut self, url: &str) -> Self {
        self.url = url.to_string();
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Module for HttpFuzzModule {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    fn initialize(&mut self) {
        if self.url.is_empty() {
            panic!("URL must be set for HTTP fuzz module");
        }
    }

    fn attack(&self, payload: String) -> Result<Response, String> {
        // Re‑use the same logic as HttpModule
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(self.timeout))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let mut req = client
            .request(
                self.method
                    .parse::<reqwest::Method>()
                    .unwrap_or(reqwest::Method::GET),
                &self.url,
            )
            .timeout(Duration::from_secs(self.timeout));

        for (k, v) in &self.headers {
            req = req.header(k, v);
        }

        if let Some(b) = &self.body {
            req = req.body(b.clone());
        } else if !payload.is_empty() {
            req = req.body(payload);
        }

        let resp = req.send().map_err(|e| format!("HTTP request failed: {}", e))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .map_err(|e| format!("Failed to read HTTP response body: {}", e))?;

        Ok(Response::new(Some(status), body.to_vec()))
    }

    fn finalize(&self) {
        // nothing to clean up
    }
}