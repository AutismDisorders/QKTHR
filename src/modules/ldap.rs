use crate::module::Module;

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

    fn initialize(&mut self) {
        if self.ldap_url.is_empty() {
            panic!("LDAP URL must be set for LDAP module");
        }
    }
}
