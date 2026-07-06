mod decrypt;
mod encrypt;

pub(crate) use decrypt::decrypt;
pub(crate) use encrypt::encrypt;

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;
    use crate::files::Files;
    use crate::secret::Secret;

    #[tokio::test]
    async fn roundtrip_preserves_content() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("test.txt");
        let encrypted_path = dir.path().join("test.txt.swx");
        let decrypted_path = dir.path().join("test_dec.txt");

        fs::write(&source_path, b"test content").await.unwrap();

        let secret = Secret::new(b"password".to_vec());

        let source = Files::new(&source_path);
        let encrypted = Files::new(&encrypted_path);
        let decrypted = Files::new(&decrypted_path);

        encrypt(&source, &encrypted, &secret).await.unwrap();
        assert!(encrypted.exists());

        decrypt(&encrypted, &decrypted, &secret).await.unwrap();
        assert!(decrypted.exists());

        assert_eq!(fs::read(&decrypted_path).await.unwrap(), b"test content");
    }
}
