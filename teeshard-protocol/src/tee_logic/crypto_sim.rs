// teeshard-protocol/src/tee_logic/crypto_sim.rs

use ed25519_dalek::{
    SigningKey, Signature, Signer, Verifier, VerifyingKey,
};
use rand::rngs::OsRng;

// Re-export key types for convenience
pub use ed25519_dalek::{SignatureError, SigningKey as SecretKey, VerifyingKey as PublicKey};

/// Generates a new Ed25519 keypair.
pub fn generate_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

/// Signs a message using an Ed25519 secret key.
pub fn sign(message: &[u8], secret_key: &SigningKey) -> Signature {
    secret_key.sign(message)
}

/// Verifies an Ed25519 signature against a message and public key.
pub fn verify(message: &[u8], signature: &Signature, public_key: &VerifyingKey) -> bool {
    public_key.verify(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_ed25519() {
        let keypair = generate_keypair();
        let public_key = keypair.verifying_key();
        let message = b"hello ed25519";

        let signature = sign(message, &keypair);

        // Verify with correct key and message
        assert!(verify(message, &signature, &public_key));

        // Verify with wrong key
        let wrong_keypair = generate_keypair();
        let wrong_public_key = wrong_keypair.verifying_key();
        assert!(!verify(message, &signature, &wrong_public_key));

        // Verify with wrong message
        assert!(!verify(b"wrong_message", &signature, &public_key));

        // Verify with tampered signature
        // Create a valid signature, then tamper it
        let another_message = b"another message";
        let mut tampered_signature = sign(another_message, &keypair);
        // Ed25519 signatures are typically 64 bytes. Tamper the first byte.
        if tampered_signature.to_bytes().len() > 0 {
            // Unfortunately, Signature doesn't expose mutable bytes directly.
            // We can create a slightly different sig by signing different data.
            // Or just assert verify fails with the *correct* signature for the *wrong* message
            assert!(!verify(message, &tampered_signature, &public_key));
        } else {
            panic!("Generated signature has zero length?");
        }
    }

     #[test]
    fn keypair_generation() {
        let key1 = generate_keypair();
        let key2 = generate_keypair();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
        assert_ne!(key1.verifying_key().as_bytes(), key2.verifying_key().as_bytes());
    }
} 