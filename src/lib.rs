#[derive(PartialEq, Debug)]
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
                out.push_str((m.len() + 1).to_string().as_str());
                out.push(':');
                out.push('0');
                out.push_str(m);
            },
            End(m) => {
                out.push_str((m.len() + 1).to_string().as_str());
                out.push(':');
                out.push('1');
                out.push_str(m);
            },
            Command(m) => {
                out.push_str((m.len() + 1).to_string().as_str());
                out.push(':');
                out.push('2');
                out.push_str(m);
            },
            Error(m) => {
                out.push_str((m.len() + 1).to_string().as_str());
                out.push(':');
                out.push('3');
                out.push_str(m);
            },
            Timeout(m) => {
                out.push_str((m.len() + 1).to_string().as_str());
                out.push(':');
                out.push('4');
                out.push_str(m);
            },
        }
        out
    }
}

impl ConMsg {
    pub fn from_string(msg: String) -> Result<ConMsg, &'static str> {
        let msg = msg.split(":").collect::<Vec<&str>>()[1];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_to_str() {
        let one: ConMsg = ConMsg::Hello(String::from("a"));
        let two: ConMsg = ConMsg::End(String::from("ab"));
        let three: ConMsg = ConMsg::Command(String::from("abc"));
        let four: ConMsg = ConMsg::Error(String::from("abcd"));
        let five: ConMsg = ConMsg::Timeout(String::from("abcde"));
        assert_eq!(one.to_string(), "2:0a");
        assert_eq!(two.to_string(), "3:1ab");
        assert_eq!(three.to_string(), "4:2abc");
        assert_eq!(four.to_string(), "5:3abcd");
        assert_eq!(five.to_string(), "6:4abcde");
    }

    #[test]
    fn str_to_msg() {
        let one: ConMsg = ConMsg::Hello(String::from("a"));
        let two: ConMsg = ConMsg::End(String::from("ab"));
        let three: ConMsg = ConMsg::Command(String::from("abc"));
        let four: ConMsg = ConMsg::Error(String::from("abcd"));
        let five: ConMsg = ConMsg::Timeout(String::from("abcde"));
        assert_eq!(one, ConMsg::from_string(String::from("2:0a")).unwrap());
        assert_eq!(two, ConMsg::from_string(String::from("3:1ab")).unwrap());
        assert_eq!(three, ConMsg::from_string(String::from("4:2abc")).unwrap());
        assert_eq!(four, ConMsg::from_string(String::from("5:3abcd")).unwrap());
        assert_eq!(five, ConMsg::from_string(String::from("6:4abcde")).unwrap());
    }
}