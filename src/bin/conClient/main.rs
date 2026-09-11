use aws_lc_rs::error::{KeyRejected, Unspecified};
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::signature::{
    ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair, PqdsaSigningAlgorithm,
};
use clap::{Parser, Subcommand, ValueEnum};
use consh::ConMsg;
use log::{debug, error, warn};
use std::io::{Error, Read, Write};
use std::mem::MaybeUninit;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic;
use std::thread;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Argv {
    #[command(subcommand)]
    cmd: Ops,
}

#[derive(Subcommand)]
enum Ops {
    /// Open a remote shell at a valid server
    Run {
        /// The address of the host, leaving this blank will automatically
        /// select the default host (if one exists)
        #[arg(short = 'o', long)]
        hostname: Option<String>,

        /// The port the host is listening on (if not default)
        #[arg(short, long, default_value_t = 1618)]
        port: u16,

        /// Print debug information to the console
        #[arg(short, long)]
        debug: bool,

        /// Location of the key to use
        #[arg(short, long)]
        key_path: Option<String>,
    },

    /// Generate an authentication keypair for the current user/machine combination
    Keygen {
        /// The algorithm to use (default MLDSA-44)
        #[arg(value_enum, short, long, default_value_t = Algorithms::MLDSA44)]
        algorithm: Algorithms,

        /// The path to generate the keypair in
        #[arg(short, long, default_value_t = String::from("."))]
        path: String,
    },
}

#[derive(ValueEnum, Clone)]
enum Algorithms {
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

fn generate_key(algo: Algorithms, path: &Path) -> Result<(), Unspecified> {
    if path.join("mldsa").exists() && path.join("mldsa.pub").exists() {
        let stdin = std::io::stdin();
        print!("An associated key pair already exists at this path, overwrite? (y/N): ");
        std::io::stdout().flush().unwrap();
        loop {
            let mut buf = String::new();
            match stdin.read_line(&mut buf) {
                Ok(n) if n < 2 => return Ok(()),
                Ok(_) => {
                    buf = buf.to_lowercase();
                    let yeses = ["y", "yes"];
                    let nos = ["n", "no"];
                    if yeses.contains(&buf.as_str().trim_end()) {
                        println!("Continuing...");
                        break;
                    } else if nos.contains(&buf.as_str()) {
                        return Ok(());
                    } else {
                        print!("Please answer [y]es or [n]o: ");
                        std::io::stdout().flush().unwrap();
                    }
                }
                Err(_) => return Err(Unspecified),
            }
        }
    }

    let algo: &'static PqdsaSigningAlgorithm = match algo {
        Algorithms::MLDSA44 => &ML_DSA_44_SIGNING,
        Algorithms::MLDSA65 => &ML_DSA_65_SIGNING,
        Algorithms::MLDSA87 => &ML_DSA_87_SIGNING,
    };
    let keypair = PqdsaKeyPair::generate(algo)?;
    let priv_key = keypair.to_pkcs8v1()?;
    println!("{}", priv_key.as_ref().len());
    let pub_key = keypair.public_key().as_ref();
    let mut priv_file = std::fs::File::create(path.join("mldsa")).expect("Failed to create file");
    let mut pub_file =
        std::fs::File::create(path.join("mldsa.pub")).expect("Failed to create file");
    priv_file.write_all(priv_key.as_ref()).unwrap();
    pub_file.write_all(pub_key).unwrap();
    Ok(())
}

fn handle_message(msg: &[u8], shutdown: &atomic::AtomicBool) -> std::io::Result<()> {
    let msg = ConMsg::from_bytes(msg)?;
    match msg {
        ConMsg::Hello(_) => println!("Operation currently unsupported"),
        ConMsg::Command(string) => {
            let mut stdout = std::io::stdout();
            stdout.write_all(&string)?;
            stdout.flush()?;
        }
        ConMsg::End(_) => {
            debug!("End signal received from server, quitting...");
            shutdown.store(true, atomic::Ordering::Relaxed)
        }
        ConMsg::Error(_) => println!("Operation currently unsupported"),
        ConMsg::Challenge { .. } => println!("Operation currently unsupported"),
    }
    Ok(())
}

fn read_loop(mut sock: TcpStream, shutdown: &atomic::AtomicBool) -> std::io::Result<()> {
    while !shutdown.load(atomic::Ordering::Relaxed) {
        let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
        sock.read_exact(&mut len_bytes)?;
        let msg_len = usize::from_be_bytes(len_bytes);
        let mut bytes_recd = 0;
        let mut msg = Vec::new();
        while bytes_recd < msg_len {
            let mut buf: Vec<u8> = vec![0; msg_len - bytes_recd];
            let pack_size = sock.read(&mut buf)?;
            bytes_recd += pack_size;
            msg.extend_from_slice(&buf[..pack_size]);
        }
        handle_message(&msg, shutdown)?;
    }
    Ok(())
}

fn client(hostname: &str, port: u16, key_path: Option<&Path>) -> std::io::Result<()> {
    let mut sock = match TcpStream::connect((hostname, port)) {
        Ok(s) => s,
        Err(e) => {
            warn!("Connection to server failed! Is the server online?");
            return Err(e);
        }
    };
    // Perform security handshake with server
    let keyfile = match key_path {
        Some(path) => path.join("mldsa"),
        None => {
            let home = std::env::var("HOME").unwrap();
            PathBuf::from(format!("{home}/.consh/mldsa"))
        }
    };
    let mut keyfile = match std::fs::File::open(keyfile) {
        Ok(key) => key,
        Err(e) => {
            error!("Fatal, could not open keyfile: No such file or directory");
            return Err(e);
        }
    };
    let mut seed = Vec::new();
    keyfile.read_to_end(&mut seed)?;
    let key = match PqdsaKeyPair::from_pkcs8(&ML_DSA_44_SIGNING, &seed) {
        Ok(data) => data,
        Err(e) => return Err(Error::other(e)),
    };
    debug!("Successfully loaded MLDSA auth keypair");
    let hello_msg = ConMsg::Hello(key.public_key().as_ref().to_vec());

    sock.write_all(&hello_msg.to_bytes())?;
    debug!("Hello message sent to server");

    // Receive and respond to server Challenge
    let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
    sock.read_exact(&mut len_bytes)?;
    let msg_len = usize::from_be_bytes(len_bytes);
    let mut challenge = vec![0u8; msg_len];
    sock.read_exact(&mut challenge)?;
    let challenge = match ConMsg::from_bytes(&challenge)? {
        ConMsg::Challenge {
            nonce,
            timestamp,
            signature,
        } => (nonce, timestamp, signature),
        _ => {
            return Err(Error::other("Malformed challenge response from server"));
        }
    };

    let mut signature = vec![0u8; ML_DSA_44_SIGNING.signature_len()];
    match key.sign(&challenge.0, &mut signature) {
        Ok(_) => {}
        Err(_) => {
            return Err(Error::other("Failed to generate signature for challenge"));
        }
    }

    let response = ConMsg::Challenge {
        nonce: challenge.0,
        timestamp: challenge.1,
        signature,
    };

    sock.write_all(&response.to_bytes())?;

    let shutdown = atomic::AtomicBool::new(false);
    let mut stdin = std::io::stdin();
    thread::scope(|s| -> std::io::Result<()> {
        let listener = sock.try_clone()?;
        let reader = s.spawn(|| read_loop(listener, &shutdown));
        let mut keep_reading = true;
        while keep_reading && !shutdown.load(atomic::Ordering::Relaxed) {
            let mut buf: [u8; 1024] = [0; 1024];
            match stdin.read(&mut buf) {
                Ok(n) if n == 1 => {
                    if buf[0] == 4 {
                        let end_msg = ConMsg::End(Vec::new());
                        sock.write_all(&end_msg.to_bytes())?;
                        debug!("Ctrl+D received, preparing to end transmission");
                        keep_reading = false;
                    } else {
                        let msg = buf[..n].to_vec();
                        let msg = ConMsg::Command(msg);
                        match sock.write_all(&msg.to_bytes()) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("Failed to send packet to server");
                                return Err(e);
                            }
                        }
                    }
                }
                Ok(n) => {
                    let msg = buf[..n].to_vec();
                    let msg = ConMsg::Command(msg);
                    match sock.write_all(&msg.to_bytes()) {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Failed to send packet to server");
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Could not read from terminal!");
                    return Err(e);
                }
            }
        }
        let _ = reader.join();
        Ok(())
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create dotdir if it doesn't exist
    let home_dir = std::env::var("HOME").expect("User does not have a valid home directory");
    let config = Path::new(&home_dir).join(".consh");
    if !config.exists() {
        std::fs::create_dir(&config).unwrap();
    }
    // Parse args
    let argv = Argv::parse();
    let mut host: String;
    let port_arg: u16;
    let key_name: String;
    let keyfile: Option<&Path>;
    let print_debug: bool;
    match argv.cmd {
        Ops::Keygen { algorithm, path } => {
            generate_key(algorithm, Path::new(&path))?;
            return Ok(());
        }
        Ops::Run {
            hostname,
            port,
            debug,
            key_path,
        } => {
            match hostname {
                Some(name) => host = name,
                None => {
                    if !config.join("default_host").exists() {
                        return Err(Box::new(Error::other(
                            "No host provided, and a default host not set",
                        )));
                    }
                    host = String::new();
                    let mut hostfile = std::fs::File::open(config.join("default_host"))?;
                    hostfile.read_to_string(&mut host)?;
                }
            }
            port_arg = port;
            print_debug = debug;
            keyfile = match key_path {
                None => None,
                Some(path) => {
                    key_name = path;
                    Some(Path::new(&key_name))
                }
            };
        }
    }

    // Create debug logging setup, if debug is enabled in args
    let mut clog = colog::default_builder();
    if print_debug {
        clog.filter(None, log::LevelFilter::Debug);
    } else {
        clog.filter(None, log::LevelFilter::Error);
    }
    clog.init();
    debug!("Preparing to connect to {host}");

    // Set terminal into raw mode
    // SAFETY: termios struct guaranteed to be initialized by libc::tcgetattr
    let reset: MaybeUninit<libc::termios>;
    unsafe {
        let mut flags: MaybeUninit<libc::termios> = MaybeUninit::uninit();
        if libc::tcgetattr(libc::STDIN_FILENO, flags.as_mut_ptr()) == -1 {
            panic!("Failed to get terminal info, is stdin a terminal?");
        }
        reset = flags;
        let mut flags = flags.assume_init();
        libc::cfmakeraw(&mut flags);
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &flags) == -1 {
            panic!("Failed to set terminal to raw mode");
        }
    }

    // Define custom panic handler that resets terminal to default settings
    // then executes the default panic handler
    let panic_reset = reset;
    let panicker = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Reset terminal to previous state before quitting
        // SAFETY: reset guaranteed to have previous state assuming no panics
        unsafe {
            let reset = panic_reset.assume_init();
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &reset);
        }
        panicker(info);
    }));

    match client(&host, port_arg, keyfile) {
        Ok(_) => {}
        Err(e) => println!("consh: {e}"),
    }

    std::io::stdout().write_all(b"\x1b[?25h\x1b[0m\r\n")?;
    std::io::stdout().flush()?;
    // Reset terminal to previous state before quitting
    // SAFETY: reset guaranteed to have previous state assuming no panics
    unsafe {
        let reset = reset.assume_init();
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &reset);
    }
    Ok(())
}
