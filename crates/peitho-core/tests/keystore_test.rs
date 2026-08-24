use peitho_core::{generate_dsa_keypair, sign_message, verify_signature, EncryptedKeystore};

#[test]
fn test_encrypted_keystore_roundtrip() {
    let temp_dir = std::env::temp_dir();
    let keystore_path = temp_dir.join("test_peitho_keystore.json");

    // 1. Generate keypair
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let password = "SuperSecretEnterprisePassphrase123!";

    // 2. Encrypt with AES-256-GCM + Argon2id
    let keystore = EncryptedKeystore::encrypt(&pk, &sk, password).expect("encrypt");
    keystore.save_to_file(&keystore_path).expect("save");

    // 3. Load from disk
    let loaded_keystore = EncryptedKeystore::load_from_file(&keystore_path).expect("load");

    // 4. Decrypt with correct password
    let (dec_pk, dec_sk) = loaded_keystore.decrypt(password).expect("decrypt");
    assert_eq!(pk.as_bytes(), dec_pk.as_bytes());

    // 5. Test signing and verifying with decrypted key
    let message = b"Confidential financial trade instruction";
    let sig = sign_message(&dec_sk, message).expect("sign with decrypted key");
    verify_signature(&dec_pk, message, &sig).expect("verify with decrypted key");

    // 6. Test incorrect password failure
    assert!(loaded_keystore.decrypt("WrongPassword").is_err(), "Decryption with wrong password MUST fail!");

    let _ = std::fs::remove_file(keystore_path);
}
