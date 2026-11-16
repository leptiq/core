//! Blob storage for attachment chunks (local filesystem).

use std::path::PathBuf;

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(root: &str) -> anyhow::Result<Self> {
        let root = PathBuf::from(root).join("blobs");
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self, key: &str) -> PathBuf {
        // Keys are server-generated IDs; still refuse anything path-like.
        let safe: String = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        let (a, b) = (
            safe.get(0..2).unwrap_or("00"),
            safe.get(2..4).unwrap_or("00"),
        );
        self.root.join(a).join(b).join(safe)
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> std::io::Result<()> {
        let p = self.path(key);
        if let Some(dir) = p.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let tmp = p.with_extension("tmp");
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(tmp, p).await
    }

    pub async fn get(&self, key: &str) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(self.path(key)).await
    }

    pub async fn delete(&self, key: &str) {
        let _ = tokio::fs::remove_file(self.path(key)).await;
    }
}
