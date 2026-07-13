use std::net::*;
use std::thread;
use std::sync::mpsc;
use subterminal::{Pty, PtyIn, PtyOut};
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use log::{info, warn, error, debug};
use clap::{Parser, Subcommand};
use consh::ConMsg;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Argv {

    #[command(subcommand)]
    command: Commands
}
#[derive(Subcommand)]
enum Commands {
    Run {
        /// Port for the server to run on
        #[arg(short, long, value_name = "PORT", default_value_t = 1618)]
        port: u16,
    },

    Keygen {
        /// User to generate a key for, must be logged in user if
        /// command is not run with root priveliges
        #[arg(short, long, value_name = "USER")]
        uname: String
    }
}

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
        let msg: ConMsg = match queue.recv() {
            Ok(received) => received,
            Err(_) => {
                info!("All references to sender closed, exiting...");
                return;
            }
        };
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
            // Unix-systems will send EIO if a pty's child closes early
            Err(err) if err.raw_os_error() == Some(libc::EIO) => {
                info!("Inner PTY process closed, exiting...");
                break;
            },
            Err(_) => {
                error!("Fatal: {:?}", std::io::Error::last_os_error());
                return;
            }
        }
    }
    info!("EOF reached, terminating thread");
}

#[cfg(target_os = "linux")]
fn user_exists(uname: &str) -> bool {
    // Check /etc/passwd to ensure that desired user actually exists
    let mut passwd = BufReader::new(File::open("/etc/passwd").expect("Unable to open /etc/passwd"));
    loop {
        // Read and parse line in passwd
        let mut buf = String::new();
        match passwd.read_line(&mut buf) {
            Ok(0) => {
                error!("Fatal: requested user not found");
                return false;
            },
            Err(_) => {
                error!("Fatal: could not read /etc/passwd");
                return false;
            },
            _ => {}
        }
        
        let user_info: Vec<&str> = buf.split(':').collect();
        if user_info[0] == uname {
            return true;
        }
    }
}

#[cfg(target_os = "macos")]
fn user_exists(uname: &str) -> bool {
    let userlist = {
        std::process::Command::new("dscl")
            .args([".", "-ls", "/Users"])
            .output()
            .expect("Failed to fetch user list")
    };
    let users = BufReader::new(userlist.stdout);
    loop {
        let mut buf = String::new();
        match users.read_line(&mut buf) {
            Ok(0) => return false,
            Err(_) => {
                error!("Could not read user list");
                return false;
            },
            _ => {}
        }
        if buf == uname {
            return true;
        }
    }
}

fn client_handler(mut sock: TcpStream) -> std::io::Result<()> {
    warn!("Actual user handshake not implemented yet, using canned username");
    let uname = "ryanj";
    if !user_exists(uname) {
        return Err(std::io::Error::other("User not found"));
    }
    // Start bash subprocess
    let cmd = String::from("/usr/bin/bash");
    debug!("command to be ran is {}", cmd);
    let mut shell = Pty::spawn_as_user(&cmd, &uname)?;
    thread::sleep(std::time::Duration::from_millis(10));

    let (tx, rx) = mpsc::channel();
    let sender = sock.try_clone()?;
    thread::scope( |s| -> std::io::Result<()> {
        s.spawn(move || -> std::io::Result<()> {
            send_loop(rx, sender);
            Ok(())
        });
        s.spawn(|| shell_listener(tx, &mut shell.output));
        let mut shutdown = false;
        while !shutdown {
            let mut len_bytes: [u8; 4] = [0; 4];
            sock.read_exact(&mut len_bytes)?;
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
        let end = ConMsg::End(String::new());
        shell.input.write_all(b"\x04")?;
        sock.write_all(&end.to_bytes())?;
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
    let args = Argv::parse();
    //TODO; Add more sophisticated argument parsing (external crate?)
    match &args.command {
        Commands::Run { port } => {
            // Log level is Debug for debug builds, info for release builds
            let mut clog = colog::default_builder();
            if cfg!(debug_assertions) {
                clog.filter(None, log::LevelFilter::Debug);
            }
            clog.init();
            server_loop(*port)
        }
        Commands::Keygen { uname } => {
            println!("Pretending to generate key for {}", *uname);
            Ok(())
        }
    }
}
