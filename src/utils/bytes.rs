use byteorder::{BigEndian, ByteOrder};

/// Trait for converting unsigned integers to/from big-endian byte arrays.
///
/// This trait provides methods to convert unsigned integers to their big-endian
/// byte representation and to create an integer from a big-endian byte slice.
/// It ensures consistent byte ordering across the application, which is crucial
/// for working with file formats, network protocols, or other binary data structures.
pub trait UintType: Sized {
    /// Converts the integer to a big-endian byte vector.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the big-endian representation of the integer.
    fn to_bytes(&self) -> Vec<u8>;

    /// Creates an integer from a big-endian byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the big-endian representation of the integer.
    ///
    /// # Panics
    ///
    /// This method will panic if the byte slice length is insufficient for the type.
    ///
    /// # Returns
    /// The converted integer.
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

/// Formats a byte size into a human-readable string.
///
/// This function converts a number of bytes into a more human-readable format,
/// using appropriate units such as B, KB, MB, GB, etc. The result includes up to
/// two decimal places for values greater than or equal to 1 KB.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB", "EB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let bytes_f64 = bytes as f64;
    let base = 1024.0_f64;

    let exponent = (bytes_f64.ln() / base.ln()).floor() as usize;
    let exponent = exponent.min(UNITS.len() - 1);

    let size = bytes_f64 / base.powi(exponent as i32);
    let unit = UNITS[exponent];

    if exponent == 0 {
        format!("{} {}", bytes, unit)
    } else {
        format!("{:.2} {}", size, unit)
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

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
}
