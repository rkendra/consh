use consh::ConMsg;
use std::io::{Error, Read, Write};
use std::mem::MaybeUninit;
use std::net::TcpStream;
use std::thread;
use std::sync::{atomic};
use std::path::Path;
use clap::{Parser, Subcommand, ValueEnum};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, PqdsaSigningAlgorithm, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};
use aws_lc_rs::error::{KeyRejected, Unspecified};
use aws_lc_rs::signature::KeyPair;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Argv {
   #[command(subcommand)]
    cmd: Ops,
}

#[derive(Subcommand)]
enum Ops {
    Run {
        /// The address of the host, leaving this blank will automatically
        /// select the default host (if one exists)
        #[arg(short = 'o', long)]
        hostname: Option<String>,

        /// The port the host is listening on (if not default)
        #[arg(short, long, default_value_t = 1618)]
        port: u16
    },

    /// Generate an authentication keypair for the current user/machine combination
    Keygen {
        /// The algorithm to use (default MLDSA-44)
        #[arg(value_enum, short, long, default_value_t = Algorithms::MLDSA44)]
        algorithm: Algorithms,
        
        #[arg(short, long, default_value_t = String::from("."))]
        path: String,
    }
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
        loop {
            let mut buf = String::new();
            match stdin.read_line(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    buf = buf.to_lowercase();
                    let yeses = vec!["y", "yes"];
                    let nos = vec!["n", "no"];
                    if yeses.contains(&buf.as_str()) {
                        println!("Continuing...");
                        break;
                    }
                    else if nos.contains(&buf.as_str()) {
                        return Ok(());
                    }
                    else {
                        print!("Please answer [y]es or [n]o: ");
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
    let keypair = PqdsaKeyPair::generate(&algo)?;
    let priv_key = keypair.to_pkcs8()?;
    let pub_key = keypair.public_key().as_ref();
    let mut priv_file = std::fs::File::create(path.join("mldsa")).expect("Failed to create file");
    let mut pub_file = std::fs::File::create(path.join("mldsa.pub")).expect("Failed to create file");
    priv_file.write_all(priv_key.as_ref()).unwrap();
    pub_file.write_all(pub_key).unwrap();
    Ok(())
}

fn handle_message(msg: String, shutdown: &atomic::AtomicBool) -> std::io::Result<()> {
    let msg = ConMsg::from_bytes(msg)?;
    match msg {
        ConMsg::Hello(_) => println!("Operation currently unsupported"),
        ConMsg::Command(string) => {
            let mut stdout = std::io::stdout();
            stdout.write_all(string.as_bytes())?;
            stdout.flush()?;
        },
        ConMsg::End(_) => shutdown.store(true, atomic::Ordering::Relaxed),
        ConMsg::Error(_) => println!("Operation currently unsupported"),
        ConMsg::Timeout(_) => println!("Operation currently unsupported"),
    }
    Ok(())
}

fn read_loop(mut sock: TcpStream, shutdown: &atomic::AtomicBool) -> std::io::Result<()> {
    while !shutdown.load(atomic::Ordering::Relaxed) {
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
        handle_message(String::from_utf8(msg).expect("Server only sends UTF-8"), shutdown)?;
    }
    Ok(())
}

fn client() -> std::io::Result<()> {
    // TODO: Add config, currently using canned example
    let port: u16 = 8080;
    let host = "localhost";
    let mut sock = TcpStream::connect((host, port))?;
    let shutdown = atomic::AtomicBool::new(false);
    let mut stdin = std::io::stdin();
    thread::scope( |s| -> std::io::Result<()> {
        let listener = sock.try_clone()?;
        let reader = s.spawn(|| read_loop(listener, &shutdown));
        let mut keep_reading = true;
        while keep_reading && !shutdown.load(atomic::Ordering::Relaxed) {
            let mut buf: [u8; 1024] = [0; 1024];
            match stdin.read(&mut buf) {
                Ok(n) if n == 1 => {
                    if buf[0] == 4 {
                        let end_msg = ConMsg::End(String::new());
                        sock.write_all(&end_msg.to_bytes())?;
                        keep_reading = false;
                    } else {
                        let msg = match String::from_utf8(buf[..n].to_vec()) {
                            Ok(data) => data,
                            Err(_) => { 
                                shutdown.store(true, atomic::Ordering::Relaxed);
                                return Err(Error::new(std::io::ErrorKind::InvalidInput, "Input is not valid UTF-8"));
                            }
                        };
                        let msg = ConMsg::Command(msg);
                        sock.write_all(&msg.to_bytes())?;
                    }
                },
                Ok(n) => {
                    let msg = match String::from_utf8(buf[..n].to_vec()) {
                        Ok(data) => data,
                        Err(_) => { 
                            shutdown.store(true, atomic::Ordering::Relaxed);
                            return Err(Error::new(std::io::ErrorKind::InvalidInput, "Input is not valid UTF-8"));
                        }
                    };
                    let msg = ConMsg::Command(msg);
                    sock.write_all(&msg.to_bytes())?;
                }
                Err(e) => return Err(e),
            }
        }
        let _ = reader.join();
        Ok(()) 
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>>{
    // Parse args
    let argv = Argv::parse();
    match argv.cmd {
        Ops::Keygen{ algorithm, path } => {
            generate_key(algorithm, &Path::new(&path))?;
            return Ok(());
        }
        Ops::Run{ hostname, port } => {}
    }


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

    let _ = client();

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
