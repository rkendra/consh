use std::net::*;
use std::env;
use std::thread;
use std::process::{Command, Stdio, ChildStdin, ChildStdout};
use std::os::unix::process::CommandExt;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use log::{info, warn, error, debug};
use consh::ConMsg;

fn handle_message(msg: String, pipe: &mut ChildStdin) -> Result<(), Box<dyn std::error::Error>> {
    let msg = ConMsg::from_string(msg)?;
    match msg {
        ConMsg::Hello(_) => warn!("Operation not implemented yet"),
        ConMsg::Command(body) => pipe.write_all(body.as_bytes())?,
        ConMsg::End(_) => warn!("Operation not implemented yet"),
        ConMsg::Error(_) => warn!("Operation not implemented yet"),
        ConMsg::Timeout(_) => warn!("Operation not implemented yet"),
    }
    Ok(())
}


fn client_handler(sock: TcpStream) {
    warn!("Actual user handshake not implemented yet, using canned username");
    let uname = String::from("ryanj");
    let uid: u32;
    let start_sh: String;
    // get uid of uname from /etc/passwd
    let mut passwd = BufReader::new(File::open("/etc/passwd").expect("Unable to open /etc/passwd"));
    loop {
        // Read and parse line in passwd
        let mut buf = String::new();
        match passwd.read_line(&mut buf) {
            Ok(n) if n == 0 => {
                error!("Fatal: requested user not found");
                return;
            },
            Err(_) => {
                error!("Fatal: could not read /etc/passwd");
            },
            _ => {}
        }
        
        let user_info: Vec<&str> = buf.split(':').collect();
        if user_info[0] == uname {
            uid = user_info[2].parse().unwrap();
            // start_sh = user_info[user_info.len() - 1].to_string();
            // debug!("Uid: {uid}, Shell: {start_sh}");
            break;
        }
    }
    start_sh = String::from("bash");
    // Start bash subprocess
    let mut shell = {
        Command::new(start_sh)
            .uid(uid)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start shell")
    };

    let input = shell.stdin.take().expect("Failed to obtain stdin reference");
    let output = shell.stdout.take().expect("Failed to obtain stdout reference");
    let err_stream = shell.stderr.take().expect("Failed to obtain stderr reference");
}

fn server_loop(port: u16) -> std::io::Result<()>{
    let addr = format!("0.0.0.0:{}", port);
    let server = TcpListener::bind(addr)?;
    info!("Server listening on port {}", port);
    for stream in server.incoming() {
        let client_sock = stream?;
        thread::spawn(|| client_handler(client_sock));
    }
    Ok(())
}

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: ./conServer [port]");
        println!("Where port is a valid 16 bit integer");
        return Err(std::io::Error::other("Invalid command line arguments"));
    }
    let port: Result<u16, std::num::ParseIntError> = args[1].parse::<u16>();
    let port = match port {
        Ok(p) => p,
        Err(e) => panic!("Unable to parse port argument, Reason: {}, is port a valid 16 bit integer?", e),
    };
    let mut clog = colog::default_builder();
    clog.filter(None, log::LevelFilter::Debug);
    clog.init();
    server_loop(port)
}