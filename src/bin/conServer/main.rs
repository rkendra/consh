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

fn send_loop(queue: mpsc::Receiver<ConMsg>, sock: Arc<Mutex<TcpStream>>) {
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
        let mut sock = sock.lock().unwrap();
        match sock.write(&body[bytes_sent..]) {
            Ok(n) => bytes_sent += n,
            Err(_) => error!("Writing to TCP stream failed, retrying..."),
        }
    }
}

fn shell_listener(sender: &mut mpsc::Sender<ConMsg>, pipe: &mut PtyOut) {
    let mut shell_out = BufReader::new(pipe);
    loop {
        let mut buf: [u8; 1024] = [0; 1024];
        match shell_out.read(&mut buf) {
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
            Err(err) => {
                error!("Fatal: {:?}", err);
                return;
            }
        }
    }
    info!("EOF reached, terminating thread");
}


fn client_handler(sock: TcpStream) -> std::io::Result<()> {
    warn!("Actual user handshake not implemented yet, using canned username");
    let uname = String::from("ryanj");
    // get uid of uname from /etc/passwd
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
    let mut shell = Pty::spawn_shell(format!("su {uname}"))?;

    let (tx, rx) = mpsc::channel();
    let sock = Arc::new(Mutex::new(sock));

    thread::scope( |s| -> std::io::Result<()> {
        s.spawn(|| shell_listener(&mut tx.clone(), &mut shell.output));
        s.spawn(|| send_loop(rx, sock.clone()));
        let mut shutdown = false;
        while !shutdown {
            let mut buf: [u8; 4096] = [0; 4096];
            let mut sock = sock.lock().unwrap();
            let bytes_read = sock.read(&mut buf)?;
            handle_message(str::from_utf8(&buf[..bytes_read]).unwrap().to_string(), &mut shell.input, &mut shutdown)?;
        }
        Ok(())
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
    if cfg!(debug_assertions) {
        clog.filter(None, log::LevelFilter::Debug);
    }
    clog.init();
    server_loop(port)
}
