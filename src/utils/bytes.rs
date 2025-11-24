use byteorder::{BigEndian, ByteOrder};

/// Trait for converting unsigned integers to/from big-endian byte arrays.
///
/// This trait abstracts the byte conversion logic, ensuring consistent
/// big-endian representation across the application (important for file formats).
pub trait UintType: Sized {
    /// Converts the integer to a big-endian byte vector.
    fn to_bytes(&self) -> Vec<u8>;

    /// Creates an integer from a big-endian byte slice.
    ///
    /// # Panics
    ///
    /// Panics if the slice length is insufficient for the type.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u16_conversion() {
        let val: u16 = 0x1234;
        let bytes = val.to_bytes();
        assert_eq!(bytes, vec![0x12, 0x34]);
        assert_eq!(u16::from_bytes(&bytes), val);
    }

    #[test]
    fn test_u32_conversion() {
        let val: u32 = 0x12345678;
        let bytes = val.to_bytes();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(u32::from_bytes(&bytes), val);
    }

    #[test]
    fn test_u64_conversion() {
        let val: u64 = 0x1234567890ABCDEF;
        let bytes = val.to_bytes();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]);
        assert_eq!(u64::from_bytes(&bytes), val);
    }

    #[test]
    #[should_panic(expected = "insufficient bytes for u16")]
    fn test_u16_insufficient_bytes() {
        u16::from_bytes(&[0x12]);
    }

    #[test]
    #[should_panic(expected = "insufficient bytes for u32")]
    fn test_u32_insufficient_bytes() {
        u32::from_bytes(&[0x12, 0x34, 0x56]);
    }

    #[test]
    #[should_panic(expected = "insufficient bytes for u64")]
    fn test_u64_insufficient_bytes() {
        u64::from_bytes(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD]);
    }
}
