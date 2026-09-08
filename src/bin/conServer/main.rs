use aws_lc_rs::signature::{ML_DSA_44, UnparsedPublicKey};
use clap::{Parser, Subcommand};
use consh::ConMsg;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, ErrorKind};
use std::net::*;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use subterminal::{Pty, PtyIn, PtyOut};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Argv {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Run an instance of the server. Must run as root to avoid permission errors
    Run {
        /// Port for the server to run on
        #[arg(short, long, value_name = "PORT", default_value_t = 1618)]
        port: u16,
    },

    /// Generate a new MLDSA_44 keypair for the server
    Keygen {},

    /// Register a MLDSA_44 key with a specific user
    /// A key will attempt to log in the user it is associated with
    /// Must have permission to access a user's /home
    AddUser {
        /// User to assign a key to
        uname: String,

        /// Key to associate with user
        keyfile: String,
    },
}

const CONFIG_DIR: &str = ".consh";

fn handle_message(msg: &[u8], pipe: &mut PtyIn, shutdown: &mut bool) -> std::io::Result<()> {
    let msg = ConMsg::from_bytes(msg)?;
    match msg {
        ConMsg::Hello(_) => warn!("Operation not implemented yet"),
        ConMsg::Command(body) => pipe.write_all(&body)?,
        ConMsg::End(_) => *shutdown = true,
        ConMsg::Error(_) => warn!("Operation not implemented yet"),
        ConMsg::Challenge { .. } => warn!("Operation not implemented yet"),
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
                Ok(0) => {
                    info!("Connection closed by client");
                    break;
                }
                Ok(n) => bytes_sent += n,
                Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                    warn!("Client disconnected unexpectedly, quitting...");
                    break;
                }
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
                sender
                    .send(ConMsg::Command(vec))
                    .expect("Receiving thread panicked/terminated early");
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                debug!("Interrupt occured, retrying");
            }
            // Unix-systems will send EIO if a pty's child closes early
            Err(err) if err.raw_os_error() == Some(libc::EIO) => {
                info!("Inner PTY process closed, exiting...");
                break;
            }
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
            }
            Err(_) => {
                error!("Fatal: could not read /etc/passwd");
                return false;
            }
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
            }
            _ => {}
        }
        if buf == uname {
            return true;
        }
    }
}

fn client_handler(mut sock: TcpStream) -> std::io::Result<()> {
    info!(
        "Performing handshake from user at address {}",
        sock.peer_addr()?
    );
    // Receive key from client, ensure key is known, then send challenge
    let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
    sock.read_exact(&mut len_bytes)?;
    let msg_len = usize::from_be_bytes(len_bytes);
    let mut msg = vec![0u8; msg_len];
    sock.read_exact(&mut msg)?;
    let client_key = match ConMsg::from_bytes(&msg) {
        Ok(con_msg) => match con_msg {
            ConMsg::Hello(key) => key,
            _ => {
                error!("Client sent invalid message, quitting...");
                let error_msg = ConMsg::Error(Vec::from(b"Bad handshake opener")).to_bytes();
                sock.write_all(&error_msg)?;
                return Err(std::io::Error::other("Handshake failed"));
            }
        },
        Err(e) => {
            error!("Client sent malformed message, terminating thread...");
            return Err(e);
        }
    };

    // Check that given key is authorized

    let client_key = UnparsedPublicKey::new(&ML_DSA_44, client_key);
    let mut nonce = [0u8; 12];
    match aws_lc_rs::rand::fill(&mut nonce) {
        Ok(_) => {}
        Err(_) => {
            error!("Could not properly generate challenge, terminating thread...");
            return Err(std::io::Error::other("RNG Failed"));
        }
    }

    let challenge = ConMsg::Challenge {
        nonce: Vec::from(nonce),
        timestamp: time::OffsetDateTime::now_utc(),
        signature: vec![0u8; 1],
    };

    sock.write_all(&challenge.to_bytes())?;

    // Verify signature from client
    sock.read_exact(&mut len_bytes)?;
    let msg_len = usize::from_be_bytes(len_bytes);
    let mut msg = vec![0u8; msg_len];
    sock.read_exact(&mut msg)?;
    let challenge = match ConMsg::from_bytes(&msg) {
        Ok(con_msg) => match con_msg {
            ConMsg::Challenge {
                nonce,
                timestamp,
                signature,
            } => (nonce, timestamp, signature),
            _ => {
                error!("Client sent invalid message, quitting...");
                let error_msg = ConMsg::Error(Vec::from(b"Malformed signature message")).to_bytes();
                sock.write_all(&error_msg)?;
                return Err(std::io::Error::other("Handshake failed"));
            }
        },
        Err(e) => {
            error!("Client sent malformed message, terminating thread...");
            return Err(e);
        }
    };
    // Verify that the nonce was the one generated, reject otherwise
    if challenge.0 != nonce {
        // Close the connection w/o notifying client
        return Err(std::io::Error::other("Malicious client"));
    }

    match client_key.verify(&challenge.0, &challenge.2) {
        Ok(_) => {}
        Err(_) => {
            error!("Client failed to produce valid signature, quitting...");
            return Err(std::io::Error::other("Malicious client"));
        }
    }

    warn!("Actual user handshake not implemented yet, using canned username");
    let uname = "ryanj";
    if !user_exists(uname) {
        return Err(std::io::Error::other("User not found"));
    }
    // Start bash subprocess
    let cmd = String::from("/usr/bin/bash");
    debug!("command to be ran is {}", cmd);
    let mut shell = Pty::spawn_as_user(&cmd, uname)?;
    thread::sleep(std::time::Duration::from_millis(10));

    let (tx, rx) = mpsc::channel();
    let sender = sock.try_clone()?;
    thread::scope(|s| -> std::io::Result<()> {
        s.spawn(move || -> std::io::Result<()> {
            send_loop(rx, sender);
            Ok(())
        });
        s.spawn(|| shell_listener(tx, &mut shell.output));
        let mut shutdown = false;
        while !shutdown {
            sock.read_exact(&mut len_bytes)?;
            let msg_len = usize::from_be_bytes(len_bytes);
            let mut bytes_recd = 0;
            let mut msg = Vec::new();
            while bytes_recd < msg_len {
                let mut buf: Vec<u8> = vec![0; msg_len - bytes_recd];
                let n = sock.read(&mut buf)?;
                bytes_recd += n;
                msg.extend_from_slice(&buf[..n]);
            }
            handle_message(&msg, &mut shell.input, &mut shutdown)?;
        }
        let end = ConMsg::End(Vec::new());
        shell.input.write_all(b"\x04")?;
        sock.write_all(&end.to_bytes())?;
        Ok(())
    })
}

// Listen for new clients on the connection, creating
// a new client thread for each one
fn server_loop(port: u16) -> std::io::Result<()> {
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
        Commands::Keygen {} => Ok(()),

        Commands::AddUser { uname, keyfile } => {
            if !std::fs::exists(keyfile)? {
                println!("Could not open {keyfile}: No such file or directory");
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "No such file or directory",
                ));
            }
            let userfile = format!(
                "{}/{CONFIG_DIR}/{uname}.pub",
                std::env::var("HOME").expect("Running user does not have a home directory")
            );
            std::fs::copy(keyfile, userfile)?;
            Ok(())
        }
    }
}
