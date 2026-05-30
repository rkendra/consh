
#[repr(i32)]
#[derive(Debug)]
pub enum Opcode {
    HELLO,
    END,
    CMD,
    ERR,
    TO,
}

struct ConMsg {
    
}