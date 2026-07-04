//! Service-key lifecycle and the fail-closed PRF boot policy.
//!
//! The nullifier keys are NEVER-ROTATE: anchors are discarded after
//! nullification, so there is no re-derivation path and a silent key fork
//! (e.g. generate-if-absent racing a replica restore) would be an
//! unrecoverable split of the dedup namespace. Every rule here exists to make
//! that structurally impossible:
//!
//! - **Explicit one-shot init.** The master seed is minted ONLY by
//!   `signet init-service-keys` (or `SIGNET_INIT_SERVICE_KEYS=1`), which
//!   seals it into `service_keys`, prints the derived public key `pkS` (and
//!   ONLY `pkS` — never seed bytes) for pinning, and exits.
//! - **Ordinary boot never generates.** PRF surface configured + seed absent
//!   → refuse to start, on every node (a replica that boots before its
//!   keystore restore completes must hard-fail, never mint a fresh seed).
//! - **Public-key pin.** Seed present → the derived `pkS` MUST equal
//!   `SIGNET_DEDUP_PUBKEY_PIN`, else refuse to start. Minister pins the same
//!   value, so a forked key can never serve `/prf/evaluate` from either side.
//! - **Fail-closed allow-list.** Keys initialized + empty
//!   `SIGNET_PRF_CLIENT_IDS` → refuse startup (the admin-list posture, not
//!   the open-client-list one). Keys absent + no PRF config → the PRF routes
//!   are simply not mounted and the existing /sign deployment is unchanged.
//! - **One-shot pairwise import.** `SIGNET_IMPORT_PAIRWISE_HMAC` is consumed
//!   at config load (zeroize + remove_var, the SIGNET_KEK pattern) and sealed
//!   here on first boot; a second import while a sealed copy exists refuses
//!   startup rather than silently overwriting.

use crate::db::Db;
use crate::keystore::Kek;
use crate::prf::{PrfKeys, MASTER_SEED_LEN, MASTER_SEED_PURPOSE, PAIRWISE_HMAC_PURPOSE};
use rand::TryRngCore;
use zeroize::Zeroizing;

/// AAD key-id used when sealing service keys. There is exactly one row per
/// purpose; the purpose string is the AAD group identity, so a sealed blob
/// cannot be replayed under a different purpose.
const SERVICE_KEY_ID: i64 = 0;

/// One-shot service-key initialization. Mints a fresh 32-byte master seed
/// from OS randomness, seals it into `service_keys`, and returns the derived
/// public key `pkS` in the pin encoding (base64url, no padding). Refuses if
/// service keys are already initialized. NEVER returns or logs seed bytes.
pub fn init_service_keys(db: &Db, kek: &Kek) -> Result<String, String> {
    if db.get_service_key(MASTER_SEED_PURPOSE)?.is_some() {
        return Err(
            "service keys are already initialized; refusing to overwrite (the nullifier \
             master seed is never-rotate)"
                .to_string(),
        );
    }
    let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
    rand::rngs::OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|e| format!("OS RNG failure: {e}"))?;
    seal_master_seed(db, kek, &seed)
}

/// Seal a PROVIDED master seed into `service_keys`, returning the derived
/// `pkS` in the pin encoding. Refuses if service keys already exist.
///
/// This is the deliberate-injection path for the integration test harness
/// (which needs a FIXED seed to assert frozen vectors over the real HTTP
/// surface). Production initialization always mints fresh OS randomness via
/// [`init_service_keys`]; nothing routes user input here.
pub fn seal_master_seed(
    db: &Db,
    kek: &Kek,
    seed: &[u8; MASTER_SEED_LEN],
) -> Result<String, String> {
    if db.get_service_key(MASTER_SEED_PURPOSE)?.is_some() {
        return Err("service keys are already initialized; refusing to overwrite".to_string());
    }
    let keys = PrfKeys::from_seed(*seed, None)?;
    let pk = keys.public_key_b64();
    let sealed = kek.seal(MASTER_SEED_PURPOSE, SERVICE_KEY_ID, seed)?;
    if !db.insert_service_key(MASTER_SEED_PURPOSE, &sealed)? {
        return Err("service keys were initialized concurrently; refusing".to_string());
    }
    Ok(pk)
}

/// Inputs to the boot policy, extracted from [`crate::config::Config`].
pub struct PrfBootArgs<'a> {
    /// Whether `SIGNET_PRF_CLIENT_IDS` is non-empty (the PRF surface is
    /// configured to be enabled).
    pub prf_clients_configured: bool,
    /// The pinned `pkS` (`SIGNET_DEDUP_PUBKEY_PIN`), required when enabled.
    pub dedup_pubkey_pin: Option<&'a str>,
    /// The consumed `SIGNET_IMPORT_PAIRWISE_HMAC` bytes, if set on this boot.
    pub import_pairwise: Option<Zeroizing<Vec<u8>>>,
}

/// Outcome of the boot policy.
pub enum PrfBoot {
    /// PRF surface not configured and no keys present: routes are not
    /// mounted; the existing /sign deployment behavior is unchanged.
    Disabled,
    /// PRF surface enabled: keys loaded, pin verified.
    Enabled(Box<PrfKeys>),
}

/// Evaluate the fail-closed boot matrix and load/import the service keys.
/// Any `Err` from this function must abort startup.
pub fn prepare_prf_boot(db: &Db, kek: &Kek, args: PrfBootArgs<'_>) -> Result<PrfBoot, String> {
    let sealed_seed = db.get_service_key(MASTER_SEED_PURPOSE)?;

    match (sealed_seed, args.prf_clients_configured) {
        (None, false) => {
            if args.import_pairwise.is_some() {
                return Err(
                    "SIGNET_IMPORT_PAIRWISE_HMAC is set but the PRF surface is not enabled \
                     (no service keys, no SIGNET_PRF_CLIENT_IDS); refusing to start rather \
                     than sealing a secret into a surface that is not configured"
                        .to_string(),
                );
            }
            Ok(PrfBoot::Disabled)
        }
        (Some(_), false) => Err(
            "service keys are initialized but SIGNET_PRF_CLIENT_IDS is empty; refusing to \
             start (fail-closed: an initialized PRF keystore with no allow-list would \
             otherwise be one config slip away from an open HMAC oracle)"
                .to_string(),
        ),
        (None, true) => Err(
            "SIGNET_PRF_CLIENT_IDS is configured but the service keys are not initialized; \
             refusing to start. Run `signet init-service-keys` exactly once on the primary. \
             A replica must wait for its keystore restore to complete — NEVER initialize a \
             fresh seed on a node that should be serving an existing one (key-fork guard)"
                .to_string(),
        ),
        (Some(sealed), true) => {
            let pin = args.dedup_pubkey_pin.map(str::trim).ok_or(
                "SIGNET_DEDUP_PUBKEY_PIN is required when the PRF surface is enabled; pin \
                 the public key printed by `signet init-service-keys`",
            )?;
            let seed_bytes =
                Zeroizing::new(kek.open(MASTER_SEED_PURPOSE, SERVICE_KEY_ID, &sealed)?);
            if seed_bytes.len() != MASTER_SEED_LEN {
                return Err(format!(
                    "sealed master seed has unexpected length {} (expected {MASTER_SEED_LEN})",
                    seed_bytes.len()
                ));
            }
            let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
            seed.copy_from_slice(&seed_bytes);

            // Pairwise secret: import once, or load the sealed copy.
            let pairwise = match args.import_pairwise {
                Some(secret) => {
                    if db.get_service_key(PAIRWISE_HMAC_PURPOSE)?.is_some() {
                        return Err(
                            "SIGNET_IMPORT_PAIRWISE_HMAC is set but a sealed pairwise secret \
                             already exists; refusing to start (unset the env var — the \
                             sealed copy is authoritative and is never silently overwritten)"
                                .to_string(),
                        );
                    }
                    let sealed_pw = kek.seal(PAIRWISE_HMAC_PURPOSE, SERVICE_KEY_ID, &secret)?;
                    if !db.insert_service_key(PAIRWISE_HMAC_PURPOSE, &sealed_pw)? {
                        return Err("pairwise secret import raced a concurrent insert; refusing"
                            .to_string());
                    }
                    tracing::info!(
                        "imported the pairwise HMAC secret into service_keys (env consumed)"
                    );
                    Some(secret)
                }
                None => match db.get_service_key(PAIRWISE_HMAC_PURPOSE)? {
                    Some(sealed_pw) => Some(Zeroizing::new(kek.open(
                        PAIRWISE_HMAC_PURPOSE,
                        SERVICE_KEY_ID,
                        &sealed_pw,
                    )?)),
                    None => None,
                },
            };

            let keys = PrfKeys::from_seed(*seed, pairwise)?;
            let derived = keys.public_key_b64();
            if derived != pin {
                // Both values are public keys — safe to surface for ops.
                return Err(format!(
                    "derived VOPRF public key {derived} does not match SIGNET_DEDUP_PUBKEY_PIN \
                     {pin}; refusing to start (key-fork guard: this node's sealed seed is not \
                     the pinned one)"
                ));
            }
            Ok(PrfBoot::Enabled(Box::new(keys)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Kek {
        Kek::from_encoded(&hex::encode([0x77u8; 32])).unwrap()
    }

    /// Extract the error from a boot attempt without requiring Debug on
    /// PrfBoot (which holds key material and deliberately has no Debug impl).
    fn boot_err(db: &Db, kek: &Kek, a: PrfBootArgs<'_>) -> String {
        match prepare_prf_boot(db, kek, a) {
            Err(e) => e,
            Ok(_) => panic!("expected the boot policy to refuse"),
        }
    }

    fn args<'a>(configured: bool, pin: Option<&'a str>, import: Option<&[u8]>) -> PrfBootArgs<'a> {
        PrfBootArgs {
            prf_clients_configured: configured,
            dedup_pubkey_pin: pin,
            import_pairwise: import.map(|b| Zeroizing::new(b.to_vec())),
        }
    }

    #[test]
    fn init_is_one_shot_and_prints_only_pk() {
        let db = Db::open_in_memory().unwrap();
        let kek = test_kek();
        let pk = init_service_keys(&db, &kek).unwrap();
        // The pin encoding: base64url no padding, 32-byte element -> 43 chars.
        assert_eq!(pk.len(), 43);
        assert!(pk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        // A second init must refuse (never-rotate, never overwrite).
        assert!(init_service_keys(&db, &kek).is_err());
        // The sealed row exists and opens back to a 32-byte seed under the KEK.
        let sealed = db.get_service_key(MASTER_SEED_PURPOSE).unwrap().unwrap();
        let seed = kek.open(MASTER_SEED_PURPOSE, 0, &sealed).unwrap();
        assert_eq!(seed.len(), MASTER_SEED_LEN);
        // And the returned pk is exactly the one derived from that seed.
        let mut arr = [0u8; MASTER_SEED_LEN];
        arr.copy_from_slice(&seed);
        assert_eq!(PrfKeys::from_seed(arr, None).unwrap().public_key_b64(), pk);
    }

    #[test]
    fn boot_disabled_when_nothing_configured() {
        let db = Db::open_in_memory().unwrap();
        assert!(matches!(
            prepare_prf_boot(&db, &test_kek(), args(false, None, None)).unwrap(),
            PrfBoot::Disabled
        ));
    }

    #[test]
    fn boot_refuses_seed_absent_with_prf_clients_configured() {
        let db = Db::open_in_memory().unwrap();
        let err = boot_err(&db, &test_kek(), args(true, Some("pin"), None));
        assert!(err.contains("not initialized"), "{err}");
    }

    #[test]
    fn boot_refuses_initialized_keys_with_empty_prf_list() {
        let db = Db::open_in_memory().unwrap();
        let kek = test_kek();
        init_service_keys(&db, &kek).unwrap();
        let err = boot_err(&db, &kek, args(false, None, None));
        assert!(err.contains("SIGNET_PRF_CLIENT_IDS is empty"), "{err}");
    }

    #[test]
    fn boot_refuses_missing_or_mismatched_pin() {
        let db = Db::open_in_memory().unwrap();
        let kek = test_kek();
        let pk = init_service_keys(&db, &kek).unwrap();
        // Missing pin.
        let err = boot_err(&db, &kek, args(true, None, None));
        assert!(err.contains("SIGNET_DEDUP_PUBKEY_PIN is required"), "{err}");
        // Mismatched pin (a forked/wrong seed scenario).
        let err = boot_err(
            &db,
            &kek,
            args(
                true,
                Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                None,
            ),
        );
        assert!(err.contains("does not match"), "{err}");
        // Correct pin boots (whitespace around the pin is tolerated).
        let padded = format!(" {pk}\n");
        assert!(matches!(
            prepare_prf_boot(&db, &kek, args(true, Some(&padded), None)).unwrap(),
            PrfBoot::Enabled(_)
        ));
    }

    #[test]
    fn pairwise_import_is_one_shot_and_persists() {
        let db = Db::open_in_memory().unwrap();
        let kek = test_kek();
        let pk = init_service_keys(&db, &kek).unwrap();
        let secret = b"live-pairwise-secret-bytes";

        // First boot with the import env: sealed + usable.
        let keys = match prepare_prf_boot(&db, &kek, args(true, Some(&pk), Some(secret))).unwrap() {
            PrfBoot::Enabled(keys) => keys,
            PrfBoot::Disabled => panic!("must be enabled"),
        };
        assert!(keys.has_pairwise());
        let out_first = keys.pairwise(b"probe").unwrap();

        // Second boot with the import STILL set: refuse (no silent overwrite).
        let err = boot_err(&db, &kek, args(true, Some(&pk), Some(secret)));
        assert!(err.contains("already exists"), "{err}");

        // Ordinary boot without the env: loads the sealed copy, byte-identical.
        let keys = match prepare_prf_boot(&db, &kek, args(true, Some(&pk), None)).unwrap() {
            PrfBoot::Enabled(keys) => keys,
            PrfBoot::Disabled => panic!("must be enabled"),
        };
        assert!(keys.has_pairwise());
        assert_eq!(keys.pairwise(b"probe").unwrap(), out_first);
    }

    #[test]
    fn boot_refuses_import_when_surface_disabled() {
        let db = Db::open_in_memory().unwrap();
        let err = boot_err(&db, &test_kek(), args(false, None, Some(b"secret")));
        assert!(err.contains("not enabled"), "{err}");
    }
}
