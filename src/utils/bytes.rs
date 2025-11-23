use byteorder::{BigEndian, ByteOrder};

pub trait UintType: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl UintType for u16 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 2];
        BigEndian::write_u16(&mut buf, *self);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 2 {
            panic!("insufficient bytes for u16");
        }
        BigEndian::read_u16(bytes)
    }
}

impl UintType for u32 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 4];
        BigEndian::write_u32(&mut buf, *self);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 4 {
            panic!("insufficient bytes for u32");
        }
        BigEndian::read_u32(bytes)
    }
}

impl UintType for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        BigEndian::write_u64(&mut buf, *self);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 8 {
            panic!("insufficient bytes for u64");
        }
        BigEndian::read_u64(bytes)
    }
}
