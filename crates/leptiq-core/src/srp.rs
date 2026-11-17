//! SRP modulus handling and server-side proof verification (via `proton-srp`).

use base64::{Engine, engine::general_purpose::STANDARD};
use proton_srp::{
    RawSRPModulus, ServerClientProof, ServerClientVerifier, ServerEphemeral, ServerInteraction,
    ServerInteractionState,
};
use zeroize::Zeroizing;

/// The publicly known 2048-bit SRP modulus, clearsigned by Proton's modulus key.
/// Official clients verify this signature, so serving it means clients need no
/// key patching. The modulus is public, so reusing it is not a security issue.
pub const DEFAULT_SIGNED_MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";

pub struct SrpModulus {
    pub id: String,
    pub signed: String,
    raw_b64: String,
}

pub struct Challenge {
    pub server_ephemeral: String,
    pub server_secret: String,
}

impl SrpModulus {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let signed = match path {
            Some(p) => std::fs::read_to_string(p)?.replace("\r\n", "\n"),
            None => DEFAULT_SIGNED_MODULUS.to_string(),
        };
        let raw = RawSRPModulus::new_with_pgp_modulus(&signed)
            .map_err(|e| anyhow::anyhow!("invalid SRP modulus: {e:?}"))?;
        let raw_b64 = raw.encode_b64();
        // Stable ID derived from the modulus itself.
        let id = crate::util::sha256_hex(&raw_b64)[..32].to_string();
        Ok(Self {
            id,
            signed,
            raw_b64,
        })
    }

    fn raw(&self) -> RawSRPModulus {
        RawSRPModulus::new(&self.raw_b64).expect("validated at load")
    }

    /// Starts a login: computes B for the stored verifier.
    pub fn challenge(&self, verifier_b64: &str) -> Result<Challenge, proton_srp::SRPError> {
        let verifier = ServerClientVerifier::new(verifier_b64)?;
        let mut server = ServerInteraction::new(&self.raw(), &verifier)?;
        let eph = server.generate_challenge();
        let state = server.state();
        Ok(Challenge {
            server_ephemeral: eph.encode_b64(),
            server_secret: STANDARD.encode(&*state.server_ephemeral_secret),
        })
    }

    /// Verifies the client proof; returns the base64 server proof on success.
    pub fn verify(
        &self,
        verifier_b64: &str,
        challenge: &Challenge,
        client_ephemeral: &str,
        client_proof: &str,
    ) -> Option<String> {
        let verifier = ServerClientVerifier::new(verifier_b64).ok()?;
        let eph_bytes: [u8; 256] = STANDARD
            .decode(&challenge.server_ephemeral)
            .ok()?
            .try_into()
            .ok()?;
        let state = ServerInteractionState {
            server_ephemeral: Some(ServerEphemeral(eph_bytes)),
            server_ephemeral_secret: Zeroizing::new(
                STANDARD.decode(&challenge.server_secret).ok()?,
            ),
        };
        let mut server = ServerInteraction::restore(&self.raw(), &verifier, &state).ok()?;
        let proof = ServerClientProof::new(client_ephemeral, client_proof).ok()?;
        server.verify_proof(&proof).ok().map(|p| p.encode_b64())
    }
}
