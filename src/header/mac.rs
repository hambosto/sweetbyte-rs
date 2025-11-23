use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn compute_mac(key: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow!("key cannot be empty"));
    }

    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow!("failed to create HMAC: {}", e))?;

    for part in parts {
        if !part.is_empty() {
            mac.update(part);
        }
    }

    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_mac(key: &[u8], expected_mac: &[u8], parts: &[&[u8]]) -> Result<()> {
    let computed_mac = compute_mac(key, parts)?;

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    if computed_mac.ct_eq(expected_mac).into() {
        Ok(())
    } else {
        Err(anyhow!("MAC verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_verify_mac() {
        let key = b"test_key";
        let parts = vec![b"part1".as_slice(), b"part2".as_slice()];

        let mac = compute_mac(key, &parts).unwrap();
        assert!(verify_mac(key, &mac, &parts).is_ok());

        // Wrong MAC should fail
        let wrong_mac = vec![0u8; 32];
        assert!(verify_mac(key, &wrong_mac, &parts).is_err());
    }
}
