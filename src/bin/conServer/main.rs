use std::net::*;
use std::env;
use std::thread;
use std::sync::{Arc, Mutex, mpsc};
use subterminal::{Pty, PtyIn, PtyOut};
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use log::{info, warn, error, debug};
use consh::ConMsg;

fn handle_message(msg: String, pipe: &mut PtyIn, shutdown: &mut bool) -> std::io::Result<()> {
    let msg = ConMsg::from_bytes(msg)?;
    match msg {
        ConMsg::Hello(_) => warn!("Operation not implemented yet"),
        ConMsg::Command(body) => pipe.write_all(body.as_bytes())?,
        ConMsg::End(_) => *shutdown = true,
        ConMsg::Error(_) => warn!("Operation not implemented yet"),
        ConMsg::Timeout(_) => warn!("Operation not implemented yet"),
    }
    Ok(())
}

fn send_loop(queue: mpsc::Receiver<ConMsg>, mut sock: TcpStream) {
    info!("Sender thread started");
    loop {
        let msg: ConMsg;
        match queue.recv() {
            Ok(received) => msg = received,
            Err(_) => {
                info!("All references to sender closed, exiting...");
                return;
            }
        }
        let body: Vec<u8> = msg.to_bytes();
        let bytes_len: usize = body.len();
        let mut bytes_sent: usize = 0;
        while bytes_sent < bytes_len {
            match sock.write(&body[bytes_sent..]) {
                Ok(n) => bytes_sent += n,
                Err(_) => error!("Writing to TCP stream failed, retrying..."),
            }
        }
    }
}

fn shell_listener(sender: mpsc::Sender<ConMsg>, pipe: &mut PtyOut) {
    info!("Pty listener thread started");
    loop {
        let mut buf: [u8; 1024] = [0; 1024];
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut vec = Vec::new();
                vec.extend_from_slice(&buf[0..n]);
                let body = String::from_utf8(vec).expect("Shell only uses UTF-8");
                sender.send(ConMsg::Command(body)).expect("Receiving thread panicked/terminated early");
            },
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                debug!("Interrupt occured, retrying");
            },
            Err(_) => {
                error!("Fatal: {:?}", std::io::Error::last_os_error());
                return;
            }
        }
    }
    info!("EOF reached, terminating thread");
}


fn client_handler(mut sock: TcpStream) -> std::io::Result<()> {
    warn!("Actual user handshake not implemented yet, using canned username");
    let uname = String::from("ryanj");
    // Check /etc/passwd to ensure that desired user actually exists
    let mut passwd = BufReader::new(File::open("/etc/passwd").expect("Unable to open /etc/passwd"));
    loop {
        // Read and parse line in passwd
        let mut buf = String::new();
        match passwd.read_line(&mut buf) {
            Ok(0) => {
                error!("Fatal: requested user not found");
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "No such user found"));
            },
            Err(_) => {
                error!("Fatal: could not read /etc/passwd");
            },
            _ => {}
        }
        
        let user_info: Vec<&str> = buf.split(':').collect();
        if user_info[0] == uname {
            break;
        }
    }
    // Start bash subprocess
    let cmd = format!("su {uname}");
    debug!("command to be ran is {}", cmd);
    let mut shell = Pty::spawn_shell(String::from("/usr/bin/bash"))?;

    let (tx, rx) = mpsc::channel();
    let sender = sock.try_clone()?;
    thread::scope( |s| -> std::io::Result<()> {
        s.spawn(move || -> std::io::Result<()> {
            send_loop(rx, sender);
            Ok(())
        });
        s.spawn(|| shell_listener(tx.clone(), &mut shell.output));
        let mut shutdown = false;
        while !shutdown {
            let mut len_bytes: [u8; 4] = [0; 4];
            sock.read(&mut len_bytes)?;
            let msg_len = u32::from_be_bytes(len_bytes);
            let mut bytes_recd = 0;
            let mut msg = Vec::new();
            while bytes_recd < msg_len {
                let mut buf: Vec<u8> = vec![0; (msg_len - bytes_recd) as usize];
                match sock.read(&mut buf) {
                    Ok(n) => {
                        bytes_recd += n as u32;
                        msg.extend_from_slice(&buf[..n]);
                    },
                    Err(e) => return Err(e),
                }
            }
            handle_message(str::from_utf8(&msg).unwrap().to_string(), &mut shell.input, &mut shutdown)?;
        }
        Ok(())
    })
}

// Listen for new clients on the connection, creating
// a new client thread for each one
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
    //TODO; Add more sophisticated argument parsing (external crate?)
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

    // Log level is Debug for debug builds, info for release builds
    let mut clog = colog::default_builder();
    if cfg!(debug_assertions) {
        clog.filter(None, log::LevelFilter::Debug);
    }
    clog.init();
    server_loop(port)
}
