use anyhow::{Result,Error};
use clap::Parser;
use regex::Regex;
use serde::Serialize;

#[derive(
    clap::ValueEnum, Clone, Debug, Serialize
)]
#[serde(rename_all = "snake_case")]
pub enum Actions {
    Test,
    Cmd,
    Shell,
    Dance,
}

impl ToString for Actions {
    fn to_string(&self) -> String {
        match self {
            Actions::Test => "test".to_owned(),
            Actions::Cmd => "cmd".to_owned(),
            Actions::Shell => "shell".to_owned(),
            Actions::Dance => "dance".to_owned()
        }
    }
}



fn validate_hostname(host: &str) -> Result<String> {
    let ip_address_format = Regex::new(r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:(\d{1,4}))?\b")?;
    let nonalpha = Regex::new(r"^[0-9.:]+$")?;
    let nonalpha_check = nonalpha.is_match(host);
    let ip_address_format_check = ip_address_format.is_match(host);
    let valid = nonalpha_check && ip_address_format_check;
    if valid {
        Ok(host.to_string())
    }
    else {
        Err(Error::msg("mst be in format 10.0.0.1 or 10.0.0.2:1337"))
    }
}

#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Target hostname or IP address (format 10.0.0.1 or 10.0.0.2:1337) 
    #[arg(short = 't', long = "host",value_parser = validate_hostname)]
    pub hostname: String,

    /// Username 
    #[arg(short, long, default_value_t = String::from("admin"))]
    pub username: String,
    
    /// Password 
    #[arg(short, long, default_value_t = String::from("cisco"))]
    pub password: String,

    /// Action to perform
    #[arg(short, long, default_value_t = Actions::Test)]
    pub action: Actions,

    /// OS command to run [default: None]
    #[arg(short, long)]
    pub cmd: Option<String>,

    /// Displays more information about cimc
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool

}



#[test]
fn validate_hostname_test() {
    let test_cases = [
        ("10.0.0.1",true),
        ("10.0.0.1:1337",true),
        ("10.0.0.1:aa",false),
        ("255.255.255.255:1337",true),
        ("256.255.255.255:1337",false),

    ];

    for case in test_cases {
        let result = validate_hostname(case.0);
        if case.1 {
            assert!(result.is_ok());
        }
        else {
            assert!(result.is_err());
        }
    }
}

