use aws_lc_rs::signature::{ML_DSA_44, UnparsedPublicKey};
use base64::{prelude::BASE64_STANDARD, read::DecoderReader, write::EncoderWriter};
use clap::{Parser, Subcommand};
use consh::ConMsg;
use consh::auth;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Cursor, ErrorKind};
use std::net::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic, mpsc};
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

const GLOBAL_CONFIG_DIR: &str = "/etc/consh";
const USER_CONFIG_DIR: &str = ".consh";
const MLDSA44_PUBKEYLEN: usize = 1312;

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
    let client_key = auth::receive_key(&mut sock)?;
    // Check that given key is authorized
    let allowlist = File::open(String::from(GLOBAL_CONFIG_DIR) + "/allowed_keys")?;
    let mut key_buf = Vec::new();
    let mut uname = String::new();
    for line in BufReader::new(allowlist).lines() {
        let line = match line {
            Ok(data) => data,
            Err(e) => {
                return Err(e);
            }
        };
        let mut parts = line.split_ascii_whitespace();
        let b64_key = parts.next().unwrap();
        DecoderReader::new(b64_key.as_bytes(), &BASE64_STANDARD).read_to_end(&mut key_buf)?;
        if key_buf == client_key {
            uname = String::from(parts.next().unwrap());
            info!("located user {uname} associated with key");
            break;
        }
    }

    if uname == String::new() {
        error!("Client sent an unrecognized key, quitting...");
        return Err(std::io::Error::other("Unknown client"));
    }

    match auth::challenge(&mut sock, &client_key, &ML_DSA_44) {
        Ok(()) => info!("Client public key successfully verified, proceeding..."),
        Err(e) => {
            error!("Handshake with client failed: {e}");
            return Err(std::io::Error::other(format!("{e}")));
        }
    }

    if !user_exists(uname.as_str()) {
        return Err(std::io::Error::other("User not found"));
    }
    // Start bash subprocess
    let cmd = String::from("/usr/bin/bash");
    debug!("command to be ran is {}", cmd);
    let mut shell = Pty::spawn_as_user(&cmd, uname.as_str())?;
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
        let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
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
    let num_cons = Arc::new(atomic::AtomicU8::new(0));
    info!("Server listening on port {}", port);
    for stream in server.incoming() {
        let mut client_sock = stream?;
        if num_cons.load(atomic::Ordering::Acquire) >= 10 {
            warn!("Max connections reached, refusing new connection");
            let res = ConMsg::Error(Vec::from(b"Max connections reached")).to_bytes();
            client_sock.write_all(&res)?;
            continue;
        }
        num_cons.update(atomic::Ordering::AcqRel, atomic::Ordering::Acquire, |x| {
            x + 1
        });
        let monitor = thread::spawn(|| client_handler(client_sock));
        let con_update = num_cons.clone();
        thread::spawn(move || {
            match monitor.join() {
                Ok(status) => match status {
                    Ok(()) => {}
                    Err(e) => {
                        error!("Client socket disconnected unexpectedly: {}", e);
                    }
                },
                Err(_) => {
                    error!("Client thread panicked");
                }
            }
            con_update.update(atomic::Ordering::AcqRel, atomic::Ordering::Acquire, |n| {
                n - 1
            });
        });
    }
    Ok(())
}

fn main() -> Result<(), std::io::Error> {
    // Create root config directory if one doesn't exist
    if !Path::new(GLOBAL_CONFIG_DIR).exists() {
        std::fs::create_dir(GLOBAL_CONFIG_DIR)?;
    }
    let args = Argv::parse();
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
            let mut allowlist = File::options()
                .create(true)
                .append(true)
                .open(String::from(GLOBAL_CONFIG_DIR) + "/allowed_keys")?;
            std::io::copy(
                &mut File::open(keyfile)?,
                &mut EncoderWriter::new(&mut allowlist, &BASE64_STANDARD),
            )?;
            allowlist.write_all(b"\t")?;
            allowlist.write_all(uname.as_bytes())?;
            allowlist.write_all(b"\n")?;
            Ok(())
        }
    }
}
