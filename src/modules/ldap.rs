use crate::module::Module;
use crate::response::Response;
use ldap3::LdapConn;
use std::time::Duration;

/// LDAP authentication module
pub struct LdapModule {
    /// LDAP server URL
    ldap_url: String,
    /// Username to test
    user: String,
    /// Password to test (will be replaced with payload)
    password_template: String,
    /// Timeout in seconds
    timeout: u64,
}

impl LdapModule {
    /// Create a new LDAP module with default settings
    pub fn new() -> Self {
        Self {
            ldap_url: String::new(),
            user: String::new(),
            password_template: String::new(),
            timeout: 10,
        }
    }

    /// Set the LDAP server URL
    pub fn ldap_url(mut self, url: &str) -> Self {
        self.ldap_url = url.to_string();
        self
    }

    /// Set the username to test
    pub fn user(mut self, user: &str) -> Self {
        self.user = user.to_string();
        self
    }

    /// Set the password template (will be replaced with payload)
    pub fn password_template(mut self, template: &str) -> Self {
        self.password_template = template.to_string();
        self
    }

    /// Set the timeout in seconds
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Module for LdapModule {
    /// Create a new instance of the module
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    /// Initialize the module before starting the fuzzing process
    fn initialize(&mut self) {
        if self.ldap_url.is_empty() {
            panic!("LDAP URL must be set for LDAP module");
        }
    }

    /// Perform an attack with the given payload
    ///
    /// Returns a Response containing the result of the attack, or an error message.
    fn attack(&self, payload: String) -> Result<Response, String> {
        // Format payload as password
        let password = payload.trim();
        if password.is_empty() {
            return Err("Empty payload".to_string());
        }

        // Build the DN for the user
        let dn = if self.user.contains("=") {
            // User already provided as full DN
            self.user.clone()
        } else {
            // Assume simple username, construct basic DN
            format!("cn={},{}", self.user, self.ldap_url)
        };

        // Connect to LDAP server with the provided credentials
        let mut ldap = LdapConn::new(&self.ldap_url)
            .map_err(|e| format!("Failed to connect to LDAP server: {}", e))?;

        // Set timeout
        ldap.with_timeout(Duration::from_secs(self.timeout));

        // Try to bind with the provided password
        let result = ldap.simple_bind(&dn, password);

        match result {
            Ok(_) => {
                // Successful bind
                let body = format!("LDAP bind successful for user: {}", dn);
                Ok(Response::new(Some(200), body.as_bytes().to_vec()))
            }
            Err(e) => {
                // Bind failed
                let body = format!("LDAP bind failed for user {}: {}", dn, e);
                Ok(Response::new(Some(401), body.as_bytes().to_vec()))
            }
        }
    }

    /// Finalize the module after the fuzzing process is complete
    fn finalize(&self) {
        // Clean up resources if needed
    }
}
