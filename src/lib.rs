pub enum ConMsg {
    Hello(String),
    End(String),
    Command(String),
    Error(String),
    Timeout(String),
}
use ConMsg::*;

impl ToString for ConMsg {
    fn to_string(&self) -> String {
        let mut out = String::new();
        match self {
            Hello(m) => {
                out.push('0');
                out.push_str(m);
            },
            End(m) => {
                out.push('1');
                out.push_str(m);
            },
            Command(m) => {
                out.push('2');
                out.push_str(m);
            },
            Error(m) => {
                out.push('3');
                out.push_str(m);
            },
            Timeout(m) => {
                out.push('4');
                out.push_str(m);
            },
        }
        out
    }
}

impl ConMsg {
    pub fn from_string(msg: String) -> Result<ConMsg, &'static str> {
        match msg.chars().nth(0) {
            Some('0') => Ok(Hello(msg[1..].to_string())),
            Some('1') => Ok(End(msg[1..].to_string())),
            Some('2') => Ok(Command(msg[1..].to_string())),
            Some('3') => Ok(Error(msg[1..].to_string())),
            Some('4') => Ok(Timeout(msg[1..].to_string())),
            _ => Err("Invalid message type")
        }
    }
}