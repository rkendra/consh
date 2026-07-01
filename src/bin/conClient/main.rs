use consh::ConMsg;
use std::io::{Result, Error, Read, Write};
use std::mem::MaybeUninit;
use std::net::TcpStream;
use std::thread;
use std::sync::{atomic}; 

fn handle_message(msg: String, shutdown: &atomic::AtomicBool) -> Result<()> {
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

fn read_loop(mut sock: TcpStream, shutdown: &atomic::AtomicBool) -> Result<()> {
    while !shutdown.load(atomic::Ordering::Relaxed) {
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
        handle_message(String::from_utf8(msg).expect("Server only sends UTF-8"), shutdown)?;
    }
    Ok(())
}

fn client() -> Result<()> {
    // TODO: Add config, currently using canned example
    let port: u16 = 8080;
    let host = "localhost";
    let mut sock = TcpStream::connect((host, port))?;
    let shutdown = atomic::AtomicBool::new(false);
    let mut stdin = std::io::stdin();
    thread::scope( |s| -> Result<()> {
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
fn main() -> Result<()>{
    // Set terminal into raw mode
    // SAFETY: termios struct guaranteed to be initialized by libc::tcgetattr
    let reset: MaybeUninit<libc::termios>;
    unsafe {
        let mut flags: MaybeUninit<libc::termios> = MaybeUninit::uninit();
        match libc::tcgetattr(libc::STDIN_FILENO, flags.as_mut_ptr()) {
            -1 => panic!("Failed to get terminal info, is stdin a terminal?"),
            _ => {}
        }
        reset = flags.clone();
        let mut flags = flags.assume_init();
        libc::cfmakeraw(&mut flags);
        match libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &flags) {
            -1 => panic!("Failed to set terminal to raw mode"),
            _ => {}
        }
    }

    // Define custom panic handler that resets terminal to default settings
    // then executes the default panic handler
    let panic_reset = reset.clone();
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

    std::io::stdout().write(b"\x1b[?25h\x1b[0m\r\n")?;
    std::io::stdout().flush()?;
    // Reset terminal to previous state before quitting
    // SAFETY: reset guaranteed to have previous state assuming no panics
    unsafe {
        let reset = reset.assume_init();
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &reset);
    }
    Ok(())
}
