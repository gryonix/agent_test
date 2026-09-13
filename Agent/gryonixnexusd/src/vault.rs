//! **The passwords of this deployment's own services, encrypted at rest by the
//! agent.**
//!
//! The rows live in `state.db` beside everything else; what lives HERE is the
//! key and the sealing, so that no other module can accidentally write a
//! credential to disk in the clear.
//!
//! **Why the agent holds the key at all.** The alternative — end-to-end, with a
//! passphrase only the phones know — sounds stronger and, on this product,
//! mostly is not: the install report sits in `/var/lib/gryonixnexus` in PLAIN
//! TEXT by design (the app reads it without sudo, it is the only copy of the
//! generated credentials), and the agent itself has to be able to write a
//! password it just generated into the vault without a person present. So the
//! honest claim is the narrow one: this protects COPIES — a backup archive, a
//! lifted disk, a snapshot handed to a provider — not the live machine's root.
//! Anything wider would be a promise the rest of the host does not keep.
//!
//! **XChaCha20-Poly1305, and a fresh random nonce per write.** The 24-byte
//! nonce is the whole reason for the X variant: a vault row can be rewritten
//! any number of times under the same key, and with a 12-byte nonce "random per
//! write" stops being safe long before that. AEAD rather than plain encryption
//! because a tampered row must FAIL rather than decrypt into something else.
//!
//! **The whole entry is sealed, not its secret fields.** Sealing only
//! `password` would leave the login, the site and the service name legible on
//! disk — which is most of what a credential dump is worth — and would need a
//! decision at every new field. One blob has one rule.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

/// 24 bytes, the XChaCha nonce width.
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

pub struct VaultCipher {
    cipher: XChaCha20Poly1305,
}

impl VaultCipher {
    /// Reads the key at `path`, creating it on first use.
    ///
    /// **Created with mode 0600 through `OpenOptions`, not chmod-after.** A key
    /// written 0644 and narrowed a moment later is world-readable for that
    /// moment, and this file is the only thing standing between a backup of
    /// `state.db` and every password in it. The directory it lives in is
    /// already root-only (0700, see `main`), so this is the second lock, not
    /// the first.
    ///
    /// A key file that exists but is the wrong length is an ERROR, not a reason
    /// to mint a new one: minting would silently orphan every row already
    /// sealed under the old key, and "all the passwords are gone" is not
    /// something to do on a guess.
    pub fn open(path: &Path) -> Result<Self> {
        match File::open(path) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .with_context(|| format!("reading vault key {}", path.display()))?;
                if bytes.len() != KEY_LEN {
                    return Err(anyhow!(
                        "vault key {} is {} bytes, expected {KEY_LEN} — refusing to replace it, \
                         because a new key would orphan every stored password",
                        path.display(),
                        bytes.len()
                    ));
                }
                Self::from_bytes(&bytes)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let bytes = random_bytes(KEY_LEN)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .with_context(|| format!("creating vault key {}", path.display()))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                // Belt and braces for a file that somehow predates this process
                // with a wider mode (an interrupted create, a restored backup).
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                Self::from_bytes(&bytes)
            }
            Err(err) => Err(err).with_context(|| format!("opening vault key {}", path.display())),
        }
    }

    /// A key that exists only for this process — the in-memory store, which is
    /// itself test-only. Compiled out of the shipped binary rather than left
    /// as dead code: a "vault key" that survives nothing is not something to
    /// have within reach of the real one.
    #[cfg(test)]
    pub fn ephemeral() -> Result<Self> {
        Self::from_bytes(&random_bytes(KEY_LEN)?)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = Key::from_slice(bytes);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(key),
        })
    }

    /// Returns (ciphertext, nonce). The nonce is stored beside the row: it is
    /// not a secret, it only has to be different every time.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let nonce_bytes = random_bytes(NONCE_LEN)?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("sealing a vault entry failed"))?;
        Ok((ciphertext, nonce_bytes))
    }

    pub fn unseal(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(anyhow!("vault nonce is {} bytes, expected {NONCE_LEN}", nonce.len()));
        }
        let nonce = XNonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("a vault entry did not decrypt — wrong key, or the row was altered"))
    }
}

/// **`/dev/urandom` rather than a random crate.** The agent's dependency list
/// is deliberately short, and this is the one thing the kernel does better than
/// any library: no seeding, no state, no question about which generator a
/// container inherited.
fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    File::open("/dev/urandom")
        .context("opening /dev/urandom")?
        .read_exact(&mut buf)
        .context("reading /dev/urandom")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_entry_comes_back_as_itself() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (sealed, nonce) = cipher.seal(b"hunter2").unwrap();
        assert_eq!(cipher.unseal(&sealed, &nonce).unwrap(), b"hunter2");
    }

    /// The point of the whole module, asked of the BYTES: what lands on disk
    /// must not contain the secret. A test that only round-trips is green on a
    /// cipher that returns its input.
    #[test]
    fn the_stored_bytes_do_not_contain_the_password() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (sealed, _nonce) = cipher.seal(b"correct-horse-battery-staple").unwrap();
        assert!(!contains(&sealed, b"correct-horse"), "the ciphertext carries the plaintext");
    }

    #[test]
    fn two_seals_of_the_same_text_differ() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (a, _) = cipher.seal(b"same").unwrap();
        let (b, _) = cipher.seal(b"same").unwrap();
        assert_ne!(a, b, "the nonce is not being varied per write");
    }

    #[test]
    fn a_tampered_row_fails_instead_of_decrypting() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (mut sealed, nonce) = cipher.seal(b"hunter2").unwrap();
        sealed[0] ^= 0xff;
        assert!(cipher.unseal(&sealed, &nonce).is_err());
    }

    #[test]
    fn another_key_cannot_read_it() {
        let mine = VaultCipher::ephemeral().unwrap();
        let theirs = VaultCipher::ephemeral().unwrap();
        let (sealed, nonce) = mine.seal(b"hunter2").unwrap();
        assert!(theirs.unseal(&sealed, &nonce).is_err());
    }

    #[test]
    fn the_key_file_is_created_0600_and_reused() {
        let dir = std::env::temp_dir().join(format!("gryonix-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.key");
        let _ = std::fs::remove_file(&path);

        let first = VaultCipher::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the vault key is readable by somebody else");

        let (sealed, nonce) = first.seal(b"hunter2").unwrap();
        // A second open must be the SAME key, or every restart would orphan
        // the rows written before it.
        let second = VaultCipher::open(&path).unwrap();
        assert_eq!(second.unseal(&sealed, &nonce).unwrap(), b"hunter2");

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_key_file_of_the_wrong_length_is_refused_rather_than_replaced() {
        let dir = std::env::temp_dir().join(format!("gryonix-vault-short-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.key");
        std::fs::write(&path, b"too short").unwrap();
        let err = match VaultCipher::open(&path) {
            Ok(_) => panic!("a short key file was accepted"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("refusing to replace"), "got: {err}");
        // And it is still on disk: the refusal must not be a delete.
        assert_eq!(std::fs::read(&path).unwrap(), b"too short");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
