mod cli;
mod engine;
mod module;
mod modules;
mod response;
mod tcp_cache;
mod utils;

use cli::getopts;
use engine::{FuzzConfig, FuzzEngine};
use module::Module;
use modules::{
    ajp_fuzz::AjpFuzzModule, dns_forward::DnsForwardModule, dns_reverse::DnsReverseModule,
    dummy_test::DummyTestModule, finger::FingerModule, ftp::FtpModule, http::HttpModule,
    http_fuzz::HttpFuzzModule, ike_enum::IkeEnumModule, imap::ImapModule,
    keystore_pass::KeystoreModule, ldap::LdapModule, mysql::MysqlModule, pgsql::PgsqlModule,
    pop3::Pop3Module, rdp_login::RdpLoginModule, rlogin::RloginModule, smb::SmbModule,
    smtp::SmtpModule, snmp::SnmpModule, sqlcipher_pass::SqlcipherModule, ssh::SshModule,
    tcp_fuzz::TcpFuzzModule, telnet::TelnetModule, umbraco_crack::UmbracoModule,
    unzip_pass::UnzipModule, vmauthd_login::VmauthdModule,
};
use std::boxed::Box;

fn main() {
    // Initialize logging
    env_logger::init();

    let matches = getopts();

    let module_name = matches.get_one::<String>("module").expect("required");
    let module_args: Vec<String> = matches
        .get_many("module_args")
        .unwrap_or_default()
        .cloned()
        .collect();
    let _actions: Vec<String> = matches
        .get_many("actions")
        .unwrap_or_default()
        .cloned()
        .collect();
    let _start = *matches.get_one::<usize>("start").unwrap();
    let _stop = matches.get_one::<usize>("stop").copied();
    let _resume = matches.get_one::<String>("resume").cloned();
    let _encodings: Vec<String> = matches
        .get_many("encodings")
        .unwrap_or_default()
        .cloned()
        .collect();
    let combo_delim = matches.get_one::<String>("combo_delim").unwrap().as_str();
    let condition_delim = matches
        .get_one::<String>("condition_delim")
        .unwrap()
        .as_str();
    let allow_ignore_failures = matches.get_flag("allow_ignore_failures");
    let assume_yes = matches.get_flag("assume_yes");
    let _rate_limit = *matches.get_one::<f64>("rate_limit").unwrap();
    let timeout = *matches.get_one::<u64>("timeout").unwrap();
    let _max_retries = *matches.get_one::<i64>("max_retries").unwrap();
    let num_threads = *matches.get_one::<usize>("num_threads").unwrap_or(&1);
    let rate_limit = *matches.get_one::<f64>("rate_limit").unwrap_or(&1.0);
    let max_retries = *matches.get_one::<i64>("max_retries").unwrap_or(&0);
    let _groups = matches.get_one::<String>("groups").cloned();

    // Proxy configuration
    let proxy_type = matches.get_one::<String>("proxy_type").cloned();
    let proxy_address = matches.get_one::<String>("proxy_address").cloned();
    let proxy_auth = matches.get_one::<String>("proxy_auth").cloned();

    log::info!("Starting QKTHR with module: {}", module_name);
    log::debug!("Module arguments: {:?}", module_args);
    log::debug!(
        "Config: threads={}, rate_limit={}, timeout={}, max_retries={}",
        num_threads,
        rate_limit,
        timeout,
        max_retries
    );

    // Create module based on name
    let mut boxed_module: Box<dyn Module + Send + Sync> = match module_name.as_str() {
        "http" => {
            let mut module = HttpModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "url" => module = module.url(value),
                        "method" => module = module.method(value),
                        "header" => {
                            let parts: Vec<&str> = value.splitn(2, '=').collect();
                            if parts.len() == 2 {
                                module = module.header(parts[0], parts[1]);
                            }
                        }
                        "body" => module = module.body(value),
                        "follow_redirects" => {
                            module = module.follow_redirects(value.parse().unwrap_or(true))
                        }
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown HTTP argument: {}", key),
                    }
                }
            }
            // Apply proxy settings from global CLI args
            if let Some(ref pt) = proxy_type {
                module = module.proxy_type(pt);
            }
            if let Some(ref pa) = proxy_address {
                module = module.proxy_address(pa);
            }
            if let Some(ref pauth) = proxy_auth {
                module = module.proxy_auth(pauth);
            }
            Box::new(module)
        }
        "http_fuzz" => {
            let mut module = HttpFuzzModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "url" => module = module.url(value),
                        "method" => module = module.method(value),
                        "header" => {
                            let parts: Vec<&str> = value.splitn(2, '=').collect();
                            if parts.len() == 2 {
                                module = module.header(parts[0], parts[1]);
                            }
                        }
                        "body" => module = module.body(value),
                        "follow_redirects" => {
                            module = module.follow_redirects(value.parse().unwrap_or(true))
                        }
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown HTTP fuzz argument: {}", key),
                    }
                }
            }
            // Apply proxy settings from global CLI args
            if let Some(ref pt) = proxy_type {
                module = module.proxy_type(pt);
            }
            if let Some(ref pa) = proxy_address {
                module = module.proxy_address(pa);
            }
            if let Some(ref pauth) = proxy_auth {
                module = module.proxy_auth(pauth);
            }
            Box::new(module)
        }
        "ftp" => {
            let mut module = FtpModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(21)),
                        "username" => module = module.username(value),
                        "password" => module = module.password_template(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown FTP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "ssh" => {
            let mut module = SshModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(22)),
                        "username" => module = module.username(value),
                        "password" => module = module.password_template(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown SSH argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "smtp" => {
            let mut module = SmtpModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(25)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown SMTP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "imap" => {
            let mut module = ImapModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(143)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown IMAP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "pop3" => {
            let mut module = Pop3Module::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(110)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown POP3 argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "mysql" => {
            let mut module = MysqlModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(3306)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown MySQL argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "pgsql" => {
            let mut module = PgsqlModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(5432)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown PostgreSQL argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "ldap" => {
            let mut module = LdapModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "ldap_url" => module = module.ldap_url(value),
                        "user" => module = module.user(value),
                        "password" => module = module.password_template(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown LDAP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "snmp" => {
            let mut module = SnmpModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(161)),
                        "community" => module = module.community(value),
                        "version" => module = module.version(value.parse().unwrap_or(2)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(5)),
                        _ => eprintln!("Warning: Unknown SNMP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "rdp_login" => {
            let mut module = RdpLoginModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(3389)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(15)),
                        _ => eprintln!("Warning: Unknown RDP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "vmauthd_login" => {
            let mut module = VmauthdModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(902)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown VMware auth argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "telnet" => {
            let mut module = TelnetModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(23)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown Telnet argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "rlogin" => {
            let mut module = RloginModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(513)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown Rlogin argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "smb" => {
            let mut module = SmbModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(445)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown SMB argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "dns_forward" => {
            let mut module = DnsForwardModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(53)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(5)),
                        _ => eprintln!("Warning: Unknown DNS forward argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "dns_reverse" => {
            let mut module = DnsReverseModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(53)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(5)),
                        _ => eprintln!("Warning: Unknown DNS reverse argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "ike_enum" => {
            let mut module = IkeEnumModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(500)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown IKE argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "finger" => {
            let mut module = FingerModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(79)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown Finger argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "tcp_fuzz" => {
            let mut module = TcpFuzzModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(0)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(5)),
                        _ => eprintln!("Warning: Unknown TCP fuzz argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "ajp_fuzz" => {
            let mut module = AjpFuzzModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(8009)),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown AJP argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "umbraco_crack" => {
            let mut module = UmbracoModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "hash" => module = module.hash(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown Umbraco argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "keystore_pass" => {
            let mut module = KeystoreModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "keystore_path" => module = module.keystore_path(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown Keystore argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "sqlcipher_pass" => {
            let mut module = SqlcipherModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "db_path" => module = module.db_path(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown SQLCipher argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "unzip_pass" => {
            let mut module = UnzipModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "zip_path" => module = module.zip_path(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => eprintln!("Warning: Unknown Unzip argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        "dummy_test" => {
            let mut module = DummyTestModule::new();
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "mode" => module = module.mode(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(1)),
                        _ => eprintln!("Warning: Unknown dummy_test argument: {}", key),
                    }
                }
            }
            Box::new(module)
        }
        _ => {
            println!("Unknown module: {}", module_name);
            println!("\nAvailable modules:");
            println!("  http            - HTTP/HTTPS brute force");
            println!("  http_fuzz       - HTTP/HTTPS fuzzing");
            println!("  ftp             - FTP brute force");
            println!("  ssh             - SSH brute force");
            println!("  smtp            - SMTP AUTH brute force");
            println!("  imap            - IMAP brute force");
            println!("  pop3            - POP3 brute force");
            println!("  mysql           - MySQL brute force");
            println!("  pgsql           - PostgreSQL brute force");
            println!("  ldap            - LDAP brute force");
            println!("  snmp            - SNMP community string brute force");
            println!("  rdp_login       - RDP brute force");
            println!("  vmauthd_login   - VMware auth daemon brute force");
            println!("  telnet          - Telnet brute force");
            println!("  rlogin          - Rlogin brute force");
            println!("  smb             - SMB brute force");
            println!("  dns_forward     - DNS forward lookup (subdomain enum)");
            println!("  dns_reverse     - DNS reverse lookup (PTR enum)");
            println!("  ike_enum        - IKE VPN enumeration");
            println!("  finger          - Finger user enumeration");
            println!("  tcp_fuzz        - Generic TCP fuzzing");
            println!("  ajp_fuzz        - AJP (Apache JServ Protocol) fuzzing");
            println!("  umbraco_crack   - Umbraco CMS hash cracking");
            println!("  keystore_pass   - Java Keystore (JKS/PKCS12) password crack");
            println!("  sqlcipher_pass  - SQLCipher database password crack");
            println!("  unzip_pass      - ZIP archive password crack");
            println!("  dummy_test      - Test module for development");
            println!("\nUse 'qkthr --help <module>' for module-specific help and examples.");
            return;
        }
    };
    let config = FuzzConfig {
        num_threads: num_threads.try_into().unwrap_or(1),
        rate_limit: rate_limit as u64,
        timeout,
        max_retries: max_retries.try_into().unwrap_or(0),
        assume_yes,
        allow_ignore_failures,
        combo_delim: combo_delim.to_string(),
        condition_delim: condition_delim.to_string(),
    };

    // Initialize the module
    boxed_module.initialize();

    // Create and run the fuzzing engine
    let mut engine = FuzzEngine::new(boxed_module, config);
    if let Err(e) = engine.run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
