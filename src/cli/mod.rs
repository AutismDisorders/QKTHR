use clap::{value_parser, Arg, ArgAction, Command};

/// Module help text with examples
fn module_help(module: &str) -> &'static str {
    match module {
        "http" => {
            r#"
HTTP Module
===========
Perform HTTP/HTTPS requests with customizable headers, method, body, and payload injection.

Arguments (key=value):
  url                 Target URL (required)
  method              HTTP method: GET, POST, PUT, DELETE, etc. (default: GET)
  header              Add custom header (format: "Name=Value", can be used multiple times)
  body                Request body template with PAYLOAD placeholder
  follow_redirects    Follow HTTP redirects (default: true)
  timeout             Request timeout in seconds (default: 10)

Examples:
  # Basic GET request with payload in query string
  QKTHR http url="http://example.com/login?user=admin&pass=PAYLOAD" -x "grep,success"

  # POST request with JSON body
  QKTHR http url="http://example.com/api/login" method=POST header="Content-Type=application/json" body='{"username":"admin","password":"PAYLOAD"}' -x "eq,200"

  # Brute force with custom headers
  QKTHR http url="https://target.com/admin" header="Authorization=Bearer token" header="X-Custom=value" -x "grep,Welcome"
"#
        }
        "http_fuzz" => {
            r#"
HTTP Fuzz Module
================
Advanced HTTP fuzzing with full request customization and response analysis.

Arguments (key=value):
  url                 Target URL (required)
  method              HTTP method: GET, POST, PUT, DELETE, etc. (default: GET)
  header              Add custom header (format: "Name=Value", can be used multiple times)
  body                Request body template with PAYLOAD placeholder
  follow_redirects    Follow HTTP redirects (default: true)
  timeout             Request timeout in seconds (default: 10)

Examples:
  # Fuzz login form with multiple encodings
  QKTHR http_fuzz url="http://example.com/login" method=POST body="user=admin&pass=PAYLOAD" -e "hex,base64" -x "eq,200"

  # Fuzz API endpoint with JSON payload
  QKTHR http_fuzz url="http://api.example.com/v1/auth" method=POST header="Content-Type=application/json" body='{"user":"admin","pass":"PAYLOAD"}' -e "url" -x "grep,token"

  # Fuzz path traversal
  QKTHR http_fuzz url="http://example.com/view?file=PAYLOAD" -e "hex,double_url" -x "grep,root:"
"#
        }
        "ftp" => {
            r#"
FTP Module
==========
Brute-force FTP login credentials.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 21)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # Basic FTP brute force
  QKTHR ftp host=192.168.1.100 username=admin password=PAYLOAD

  # FTP with custom port and wordlist
  QKTHR ftp host=ftp.example.com port=2121 username=administrator password=FILE0 passwords.txt

  # FTP with rate limiting
  QKTHR ftp host=10.0.0.5 username=user password=PAYLOAD --rate-limit 2 --threads 5
"#
        }
        "ssh" => {
            r#"
SSH Module
==========
Brute-force SSH login credentials.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 22)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # Basic SSH brute force
  QKTHR ssh host=192.168.1.100 username=root password=PAYLOAD

  # SSH with custom port
  QKTHR ssh host=ssh.example.com port=2222 username=admin password=FILE0 passwords.txt

  # SSH with rate limiting and timeout
  QKTHR ssh host=10.0.0.5 username=user password=PAYLOAD --rate-limit 1 --timeout 10 --threads 3
"#
        }
        "smtp" => {
            r#"
SMTP Module
===========
Brute-force SMTP authentication (AUTH LOGIN/PLAIN).

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 25)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # SMTP brute force (credentials in payload as user:pass)
  QKTHR smtp host=mail.example.com password=FILE0 combos.txt

  # SMTP with custom port (submission)
  QKTHR smtp host=smtp.example.com port=587 password=FILE0 combos.txt

  # SMTP with TLS (STARTTLS)
  QKTHR smtp host=mail.example.com port=25 password=FILE0 combos.txt --rate-limit 2
"#
        }
        "imap" => {
            r#"
IMAP Module
===========
Brute-force IMAP authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 143)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # IMAP brute force (credentials in payload as user:pass)
  QKTHR imap host=mail.example.com password=FILE0 combos.txt

  # IMAP with SSL port
  QKTHR imap host=imap.example.com port=993 password=FILE0 combos.txt
"#
        }
        "pop3" => {
            r#"
POP3 Module
===========
Brute-force POP3 authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 110)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # POP3 brute force
  QKTHR pop3 host=mail.example.com password=FILE0 combos.txt

  # POP3 with SSL port
  QKTHR pop3 host=pop.example.com port=995 password=FILE0 combos.txt
"#
        }
        "mysql" => {
            r#"
MySQL Module
============
Brute-force MySQL database authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 3306)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # MySQL brute force
  QKTHR mysql host=192.168.1.100 username=root password=PAYLOAD

  # MySQL with custom port
  QKTHR mysql host=db.example.com port=3307 username=admin password=FILE0 passwords.txt
"#
        }
        "pgsql" => {
            r#"
PostgreSQL Module
=================
Brute-force PostgreSQL database authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 5432)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  database            Database name (default: postgres)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # PostgreSQL brute force
  QKTHR pgsql host=192.168.1.100 username=postgres password=PAYLOAD

  # PostgreSQL with specific database
  QKTHR pgsql host=db.example.com username=admin password=FILE0 passwords.txt database=myapp
"#
        }
        "ldap" => {
            r#"
LDAP Module
===========
Brute-force LDAP authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 389)
  username            Username/DN to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # LDAP brute force with simple bind
  QKTHR ldap host=ldap.example.com username="cn=admin,dc=example,dc=com" password=PAYLOAD

  # LDAP with SSL
  QKTHR ldap host=ldaps.example.com port=636 username="uid=user,ou=people,dc=example,dc=com" password=FILE0 passwords.txt
"#
        }
        "snmp" => {
            r#"
SNMP Module
===========
Brute-force SNMP community strings.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 161)
  community           Community string template with PAYLOAD placeholder (required)
  version             SNMP version: 1, 2c, 3 (default: 2c)
  timeout             Connection timeout in seconds (default: 5)

Examples:
  # SNMP community string brute force
  QKTHR snmp host=192.168.1.1 community=PAYLOAD

  # SNMP v3 with username
  QKTHR snmp host=10.0.0.1 version=3 username=admin password=PAYLOAD
"#
        }
        "rdp_login" => {
            r#"
RDP Login Module
================
Brute-force RDP (Remote Desktop Protocol) login.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 3389)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  domain              Domain name (optional)
  timeout             Connection timeout in seconds (default: 15)

Examples:
  # RDP brute force
  QKTHR rdp_login host=192.168.1.100 username=Administrator password=PAYLOAD

  # RDP with domain
  QKTHR rdp_login host=rdp.example.com username=user password=FILE0 passwords.txt domain=CORP
"#
        }
        "vmauthd_login" => {
            r#"
VMware Auth Daemon Module
=========================
Brute-force VMware authentication service (vmauthd).

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 902)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # VMware auth brute force
  QKTHR vmauthd_login host=esxi.example.com username=root password=PAYLOAD
"#
        }
        "telnet" => {
            r#"
Telnet Module
=============
Brute-force Telnet login.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 23)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # Telnet brute force
  QKTHR telnet host=192.168.1.100 username=admin password=PAYLOAD
"#
        }
        "rlogin" => {
            r#"
Rlogin Module
=============
Brute-force rlogin (remote login) authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 513)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # Rlogin brute force
  QKTHR rlogin host=unix.example.com username=root password=PAYLOAD
"#
        }
        "smb" => {
            r#"
SMB Module
==========
Brute-force SMB (Server Message Block) authentication.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 445)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  domain              Domain/workgroup (default: WORKGROUP)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # SMB brute force
  QKTHR smb host=192.168.1.100 username=Administrator password=PAYLOAD

  # SMB with domain
  QKTHR smb host=smb.example.com username=user password=FILE0 passwords.txt domain=CORP
"#
        }
        "dns_forward" => {
            r#"
DNS Forward Lookup Module
=========================
Perform DNS forward lookups (A/AAAA records) for subdomain enumeration.

Arguments (key=value):
  domain              Target domain (required)
  nameserver          DNS server to query (default: system default)
  record_type         Record type: A, AAAA, CNAME, etc. (default: A)
  timeout             Query timeout in seconds (default: 5)

Examples:
  # Subdomain enumeration
  QKTHR dns_forward domain=example.com nameserver=8.8.8.8 record_type=A

  # Subdomain enumeration with wordlist
  QKTHR dns_forward domain=example.com record_type=A -x "grep,NOERROR"
"#
        }
        "dns_reverse" => {
            r#"
DNS Reverse Lookup Module
=========================
Perform DNS reverse lookups (PTR records) for IP range enumeration.

Arguments (key=value):
  network             CIDR network range (required, e.g., 192.168.1.0/24)
  nameserver          DNS server to query (default: system default)
  timeout             Query timeout in seconds (default: 5)

Examples:
  # Reverse DNS enumeration
  QKTHR dns_reverse network=192.168.1.0/24

  # Reverse DNS with custom nameserver
  QKTHR dns_reverse network=10.0.0.0/8 nameserver=8.8.8.8
"#
        }
        "ike_enum" => {
            r#"
IKE Enum Module
===============
Enumerate IKE (Internet Key Exchange) VPN gateways and group names.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 500)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # IKE enumeration
  QKTHR ike_enum host=vpn.example.com

  # IKE with aggressive mode group enumeration
  QKTHR ike_enum host=192.168.1.1 port=500 -x "grep,SA="
"#
        }
        "finger" => {
            r#"
Finger Module
=============
Query Finger service for user enumeration.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 79)
  username            Username to query (optional, empty for all users)
  timeout             Connection timeout in seconds (default: 5)

Examples:
  # Finger user enumeration
  QKTHR finger host=unix.example.com

  # Finger specific user
  QKTHR finger host=192.168.1.100 username=root
"#
        }
        "tcp_fuzz" => {
            r#"
TCP Fuzz Module
===============
Generic TCP fuzzing - send raw payloads to TCP ports.

Arguments (key=value):
  host                Target host (required)
  port                Target port (required)
  payload             Payload template with PAYLOAD placeholder (required)
  timeout             Connection timeout in seconds (default: 5)

Examples:
  # Raw TCP fuzzing
  QKTHR tcp_fuzz host=192.168.1.100 port=9999 payload="USER PAYLOAD\r\n"

  # Protocol fuzzing with encodings
  QKTHR tcp_fuzz host=10.0.0.1 port=21 payload="USER PAYLOAD\r\n" -e "hex" -x "grep,230"
"#
        }
        "ajp_fuzz" => {
            r#"
AJP Fuzz Module
===============
Fuzz Apache JServ Protocol (AJP) endpoints.

Arguments (key=value):
  host                Target host (required)
  port                Target port (default: 8009)
  uri                 Request URI (default: /)
  timeout             Connection timeout in seconds (default: 10)

Examples:
  # AJP fuzzing
  QKTHR ajp_fuzz host=192.168.1.100 port=8009 uri=/admin
"#
        }
        "umbraco_crack" => {
            r#"
Umbraco Crack Module
====================
Brute-force Umbraco CMS login.

Arguments (key=value):
  url                 Target Umbraco login URL (required)
  username            Username to test (required)
  password            Password template with PAYLOAD placeholder (required)
  timeout             Request timeout in seconds (default: 10)

Examples:
  # Umbraco brute force
  QKTHR umbraco_crack url="http://cms.example.com/umbraco/login" username=admin password=PAYLOAD
"#
        }
        "keystore_pass" => {
            r#"
Keystore Password Module
========================
Brute-force Java Keystore (JKS/PKCS12) passwords.

Arguments (key=value):
  file                Keystore file path (required)
  password            Password template with PAYLOAD placeholder (required)
  type                Keystore type: jks, pkcs12 (default: jks)

Examples:
  # JKS keystore brute force
  QKTHR keystore_pass file=keystore.jks password=PAYLOAD

  # PKCS12 keystore brute force
  QKTHR keystore_pass file=keystore.p12 password=FILE0 passwords.txt type=pkcs12
"#
        }
        "sqlcipher_pass" => {
            r#"
SQLCipher Password Module
=========================
Brute-force SQLCipher encrypted database passwords.

Arguments (key=value):
  file                Database file path (required)
  password            Password template with PAYLOAD placeholder (required)

Examples:
  # SQLCipher brute force
  QKTHR sqlcipher_pass file=encrypted.db password=PAYLOAD
"#
        }
        "unzip_pass" => {
            r#"
Unzip Password Module
=====================
Brute-force ZIP archive passwords.

Arguments (key=value):
  file                ZIP file path (required)
  password            Password template with PAYLOAD placeholder (required)

Examples:
  # ZIP password brute force
  QKTHR unzip_pass file=archive.zip password=PAYLOAD
"#
        }
        "dummy_test" => {
            r#"
Dummy Test Module
=================
Simple test module for development and testing.

Arguments (key=value):
  mode                Mode of operation: success, failure, timeout, error (default: success)
  timeout             Timeout in seconds (default: 1)

Examples:
  # Test module with success mode
  QKTHR dummy_test mode=success timeout=1

  # Test module with failure mode
  QKTHR dummy_test mode=failure timeout=1

  # Test module with timeout mode
  QKTHR dummy_test mode=timeout timeout=2
"#
        }
        _ => "No help available for this module.",
    }
}

/// General usage examples
const USAGE_EXAMPLES: &str = r#"
EXAMPLES:
  # HTTP form brute force
  QKTHR http url="http://example.com/login" method=POST body="user=admin&pass=PAYLOAD" -x "grep,Welcome"

  # SSH brute force with wordlist
  QKTHR ssh host=192.168.1.100 username=root password=FILE0 passwords.txt --threads 20

  # FTP brute force with rate limiting
  QKTHR ftp host=ftp.example.com username=admin password=PAYLOAD --rate-limit 2

  # SMTP brute force (user:pass in payload)
  QKTHR smtp host=mail.example.com password=FILE0 combos.txt

  # MySQL brute force
  QKTHR mysql host=db.example.com username=root password=PAYLOAD

  # SMB brute force with domain
  QKTHR smb host=192.168.1.100 username=Administrator password=FILE0 passwords.txt domain=CORP

  # SNMP community string brute force
  QKTHR snmp host=192.168.1.1 community=PAYLOAD

  # DNS subdomain enumeration
  QKTHR dns_forward domain=example.com record_type=A -x "grep,NOERROR"

  # HTTP fuzzing with encodings
  QKTHR http_fuzz url="http://example.com/search?q=PAYLOAD" -e "hex,url,double_url" -x "grep,error"

  # RDP brute force
  QKTHR rdp_login host=rdp.example.com username=user password=FILE0 passwords.txt

  # Module-specific help
  QKTHR --help http
  QKTHR --help ssh
  QKTHR --help ftp

  # HTTP with proxy (e.g., Burp Suite)
  QKTHR http url="http://example.com/login" method=POST body="user=admin&pass=PAYLOAD" --proxy-type http --proxy-address 127.0.0.1:8080
"#;

/// Payload syntax help
const PAYLOAD_SYNTAX: &str = r#"
PAYLOAD SYNTAX:
  FILE0:file.txt     Read payloads from file (one per line)
  FILE1:file.txt     Read payloads from file, keep empty lines
  RANGE:1-100        Numeric range (inclusive)
  HEX:00-ff          Hexadecimal range
  NET:192.168.1.0/24 CIDR network range
  PROG:cmd           Execute command and use stdout as payloads
  MOD:base:div:rem   Modulo filter on base iterator

COMBINATIONS:
  Use comma to combine multiple payload sets (cartesian product):
  QKTHR http ... password=FILE0:users.txt,FILE0:passes.txt

  Use colon for pitchfork mode (simultaneous iteration):
  QKTHR http ... password=FILE0:users.txt:FILE0:passes.txt --groups 0,1

ENCODINGS (-e/--encodings):
  hex         Hex encode payload
  base64      Base64 encode payload
  url         URL encode payload
  double_url  Double URL encode payload
  md5         MD5 hash of payload
  sha1        SHA1 hash of payload
  sha256      SHA256 hash of payload
  rot13       ROT13 encode payload

CONDITIONS (-x/--actions):
  eq,CODE     Match exact status code (e.g., eq,200)
  ne,CODE     Match non-equal status code
  gt,CODE     Match status code greater than
  lt,CODE     Match status code less than
  grep,STR    Match string in response body
  egrep,REGEX Match regex in response body
  size,N      Match response size equal to N
  time,N      Match response time greater than N seconds
  retry       Retry on match (for rate limiting)
  reset       Reset retry counter on match
  ignore      Ignore failures on match
  free        Free payload on match (stop fuzzing)
"#;

pub fn getopts() -> clap::ArgMatches {
    // First, check if user wants module-specific help
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && (args[1] == "--help" || args[1] == "-h") {
        let module = &args[2];
        if module != "qkthr" && !module.starts_with('-') {
            print!("{}", module_help(module));
            std::process::exit(0);
        }
    }

    Command::new("qkthr")
        .version("0.1.0")
        .about("A multi-protocol brute-forcer written in Rust")
        .override_usage("qkthr <MODULE> [OPTIONS] [MODULE_ARGS...]")
        .after_help(format!("{}\n{}", USAGE_EXAMPLES, PAYLOAD_SYNTAX))
        .arg(
            Arg::new("module")
                .help("Module to run (use 'qkthr --help <module>' for module-specific help)")
                .required(true)
                .value_parser([
                    "http",
                    "http_fuzz",
                    "ftp",
                    "ssh",
                    "smtp",
                    "imap",
                    "pop3",
                    "mysql",
                    "pgsql",
                    "ldap",
                    "snmp",
                    "rdp_login",
                    "vmauthd_login",
                    "telnet",
                    "rlogin",
                    "smb",
                    "dns_forward",
                    "dns_reverse",
                    "ike_enum",
                    "finger",
                    "tcp_fuzz",
                    "ajp_fuzz",
                    "umbraco_crack",
                    "keystore_pass",
                    "sqlcipher_pass",
                    "unzip_pass",
                    "dummy_test",
                ]),
        )
        .arg(
            Arg::new("module_args")
                .help("Module-specific arguments (key=value format)")
                .last(true)
                .num_args(0..),
        )
        .arg(
            Arg::new("actions")
                .short('x')
                .long("actions")
                .help("Actions and conditions (see PAYLOAD SYNTAX below)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("start")
                .long("start")
                .help("Start from offset N in the product of all payload sets")
                .value_parser(value_parser!(usize))
                .default_value("0"),
        )
        .arg(
            Arg::new("stop")
                .long("stop")
                .help("Stop at offset N")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("resume")
                .long("resume")
                .help("Resume previous run from offset file"),
        )
        .arg(
            Arg::new("encodings")
                .short('e')
                .long("encodings")
                .help("Encode payloads (see PAYLOAD SYNTAX below)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("combo_delim")
                .short('C')
                .long("combo-delim")
                .help("Delimiter string in combo files (default is ':')")
                .default_value(":"),
        )
        .arg(
            Arg::new("condition_delim")
                .short('X')
                .long("condition-delim")
                .help("Delimiter string in conditions (default is ',')")
                .default_value(","),
        )
        .arg(
            Arg::new("allow_ignore_failures")
                .long("allow-ignore-failures")
                .help("Allow failures to be ignored with -x (safeguard override)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("assume_yes")
                .short('y')
                .long("assume-yes")
                .help("Automatically answer yes for all questions")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rate_limit")
                .long("rate-limit")
                .help("Wait N seconds between each attempt (default: 0)")
                .value_parser(value_parser!(f64))
                .default_value("0"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Wait N seconds for a response before retrying payload (default: 0)")
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("max_retries")
                .long("max-retries")
                .help("Skip payload after N retries (default: 4) (-1 for unlimited)")
                .value_parser(value_parser!(i64))
                .default_value("4"),
        )
        .arg(
            Arg::new("num_threads")
                .short('t')
                .long("threads")
                .help("Number of concurrent threads (default: 10)")
                .value_parser(value_parser!(usize))
                .default_value("10"),
        )
        .arg(
            Arg::new("groups")
                .long("groups")
                .help("Iterate over payload sets simultaneously (pitchfork mode)"),
        )
        .arg(
            Arg::new("proxy_type")
                .long("proxy-type")
                .help("Proxy type: http, https, socks4, socks5")
                .value_parser(["http", "https", "socks4", "socks5"]),
        )
        .arg(
            Arg::new("proxy_address")
                .long("proxy-address")
                .help("Proxy address (e.g., 127.0.0.1:8080)"),
        )
        .arg(
            Arg::new("proxy_auth")
                .long("proxy-auth")
                .help("Proxy authentication (user:pass)"),
        )
        .get_matches()
}
