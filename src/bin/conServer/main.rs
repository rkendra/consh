use std::net::*;
use std::env;
use std::thread;
use std::sync::mpsc;
use std::process::{Command, Stdio, ChildStdin, ChildStdout, ChildStderr};
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

fn send_loop(queue: mpsc::Receiver<ConMsg>, sock: &mut TcpStream) {
    info!("Sending output to {}", sock.peer_addr().unwrap());
    let msg = queue.recv().unwrap();
    let body: String = msg.to_string();
    let bytes: &[u8] = body.as_bytes();
    let bytes_len: usize = bytes.len();
    let mut bytes_sent: usize = 0;
    while bytes_sent < bytes_len {
        match sock.write(&bytes[bytes_sent..]) {
            Ok(n) => bytes_sent += n,
            Err(_) => error!("Writing to TCP stream failed, retrying..."),
        }
    }
}

fn shell_listener(sender: &mut mpsc::Sender<ConMsg>, pipe: &mut ChildStdout) {
    let mut shell_out = BufReader::new(pipe);
    loop {
        let mut buf: [u8; 1024] = [0; 1024];
        match shell_out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut vec = Vec::new();
                vec.extend_from_slice(&buf[0..n]);
                let body = String::from_utf8(vec).expect("Shell only uses UTF-8");
                sender.send(ConMsg::Command(body));
            },
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                debug!("Interrupt occured, retrying");
            },
            Err(err) => {
                error!("Fatal: {:?}", err);
                return;
            }
        }
    }
    info!("EOF reached, terminating thread");
}

fn shell_err_listener(sender: &mut mpsc::Sender<ConMsg>, pipe: &mut ChildStderr) {
    let mut shell_out = BufReader::new(pipe);
    loop {
        let mut buf: [u8; 1024] = [0; 1024];
        match shell_out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut vec = Vec::new();
                vec.extend_from_slice(&buf[0..n]);
                let body = String::from_utf8(vec).expect("Shell only uses UTF-8");
                sender.send(ConMsg::Error(body));
            },
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {},
            Err(err) => {
                error!("Fatal: {:?}", err);
                return;
            }
        }
    }
    info!("EOF reached, terminating thread");
}


fn client_handler(mut sock: TcpStream) {
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
            Ok(0) => {
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

    let mut input = shell.stdin.take().expect("Failed to obtain stdin reference");
    let mut output = shell.stdout.take().expect("Failed to obtain stdout reference");
    let mut err_stream = shell.stderr.take().expect("Failed to obtain stderr reference");

    let (mut tx, mut rx) = mpsc::channel();
    let mut txe = tx.clone();

    thread::scope( |s| {
        info!("Beginning listening for shell serving {}", sock.peer_addr().unwrap());
        s.spawn(|| shell_listener(&mut tx, &mut output));
        s.spawn(|| shell_err_listener(&mut txe, &mut err_stream));
        s.spawn(|| send_loop(rx, &mut sock));
    })
    
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