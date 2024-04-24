/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use tempfile::NamedTempFile;

const STRONG_PASSWORD: &'static str = "^%master_p(ssword)";

fn setup_db() -> (PwdManager, NamedTempFile) {
  let temp_file = NamedTempFile::new().unwrap();
  let db_path = temp_file.path().to_str().unwrap();
  let manager = PwdManager::new(db_path, STRONG_PASSWORD).unwrap();
  (manager, temp_file)
}

#[test]
fn test_new_pwd_manager() {
  let (manager, _temp_file) = setup_db();
  assert!(manager.conn.is_autocommit());
}

#[test]
fn test_add_and_get_password() {
  let (manager, _temp_file) = setup_db();
  manager.add_password("test_id", "test_password").unwrap();
  let retrieved_password = manager.get_password("test_id").unwrap();
  assert_eq!(retrieved_password, Some("test_password".to_string()));
}

#[test]
fn test_update_password() {
  let (manager, _temp_file) = setup_db();
  manager.add_password("test_id", "test_password").unwrap();
  manager.update_password("test_id", "new_password").unwrap();
  let retrieved_password = manager.get_password("test_id").unwrap();
  assert_eq!(retrieved_password, Some("new_password".to_string()));
}

#[test]
fn test_delete_password() {
  let (manager, _temp_file) = setup_db();
  manager.add_password("test_id", "test_password").unwrap();
  manager.delete_password("test_id").unwrap();
  let retrieved_password = manager.get_password("test_id").unwrap();
  assert!(retrieved_password.is_none());
}

#[test]
fn test_get_nonexistent_password() {
  let (manager, _temp_file) = setup_db();
  assert_eq!(manager.get_password("nonexistent_id").unwrap(), None);
}

#[test]
fn test_update_nonexistent_password() {
  let (manager, _temp_file) = setup_db();
  assert!(manager
    .update_password("nonexistent_id", "new_password")
    .is_err());
}

#[test]
fn test_delete_nonexistent_password() {
  let (manager, _temp_file) = setup_db();
  assert!(manager.delete_password("nonexistent_id").is_err());
}

#[test]
fn test_long_password() {
  let (manager, _temp_file) = setup_db();
  let long_password = "p".repeat(1000);

  manager
    .add_password("long_pass_id", &long_password)
    .unwrap();
  assert_eq!(
    manager.get_password("long_pass_id").unwrap(),
    Some(long_password)
  );
}

#[test]
fn test_special_character_password() {
  let (manager, _temp_file) = setup_db();
  let special_password = "p@ssw0rd!$";

  manager
    .add_password("special_char_id", special_password)
    .unwrap();
  assert_eq!(
    manager.get_password("special_char_id").unwrap(),
    Some(special_password.to_string())
  );
}

#[test]
fn test_duplicate_password_addition() {
  let (manager, _temp_file) = setup_db();
  let duplicate_id = "duplicate_id";
  manager.add_password(duplicate_id, "password").unwrap();
  match manager.add_password(duplicate_id, "password") {
    Err(Error::DuplicateId(id)) => assert_eq!(duplicate_id, id),
    _ => panic!("Expected DuplicateId error"),
  }
}

#[test]
fn test_add_empty_password() {
  let (manager, _temp_file) = setup_db();
  let result = manager.add_password("empty_password_id", "");
  assert!(result.is_err());
}

#[test]
fn test_update_to_empty_password() {
  let (manager, _temp_file) = setup_db();
  manager.add_password("test_id", "test_password").unwrap();
  let result = manager.update_password("test_id", "");
  assert!(result.is_err());
}

#[test]
fn test_existing_database_with_master_salt() {
  let (manager_0, temp_file) = setup_db();
  let retrieved_salt_0: String = manager_0
    .conn
    .query_row(
      "SELECT value FROM metadata WHERE name = 'master_salt'",
      [],
      |row| row.get(0),
    )
    .expect("Failed to retrieve salt");

  let manager_1 =
    PwdManager::new(temp_file.path().to_str().unwrap(), STRONG_PASSWORD)
      .unwrap();
  let retrieved_salt_1: String = manager_1
    .conn
    .query_row(
      "SELECT value FROM metadata WHERE name = 'master_salt'",
      [],
      |row| row.get(0),
    )
    .expect("Failed to retrieve salt");

  assert_eq!(
    retrieved_salt_0, retrieved_salt_1,
    "The salts should be consistent across instances"
  );
}

#[test]
fn test_database_file_opening_failure() {
  let invalid_path = "\0/a:*?\"<>|/very/long/path/".repeat(100);
  let result = PwdManager::new(&invalid_path, "master_password");
  assert!(result.is_err());
}

#[test]
fn test_list_passwords() {
  let (manager, _temp_file) = setup_db();
  manager.add_password("test_id1", "test_password").unwrap();
  manager.add_password("test_id2", "test_password").unwrap();

  let ids = manager.list_passwords().unwrap();
  assert_eq!(ids, vec!["test_id1", "test_id2"]);
}

#[test]
fn test_add_update_long_password() {
  let (manager, _temp_file) = setup_db();
  let long_password = "p@ssw0Rd".repeat(100);

  manager.add_password("long_id", &long_password).unwrap();
  let retrieved_password = manager.get_password("long_id").unwrap();
  assert_eq!(retrieved_password, Some(long_password.clone()));

  let updated_long_password = "q".repeat(10_000);
  manager
    .update_password("long_id", &updated_long_password)
    .unwrap();
  let updated_retrieved_password = manager.get_password("long_id").unwrap();
  assert_eq!(updated_retrieved_password, Some(updated_long_password));
}

#[test]
fn test_wrong_master_password() {
  let (_manager, temp_file) = setup_db();
  assert!(PwdManager::new(
    temp_file.path().to_str().unwrap(),
    "wrong_password"
  )
  .is_err());
}

#[test]
fn test_cipher_encryption_and_decryption() {
  let cipher =
    Cipher::from_password(b"password", &SaltString::generate(&mut OsRng))
      .unwrap();

  let plaintext = "plaintext".to_string();
  let (ciphertext, nonce) = cipher.encrypt(&plaintext).unwrap();

  let decrypted = cipher.decrypt(&ciphertext[..], &nonce[..]).unwrap();
  let decrypted = String::from_utf8(decrypted).unwrap();

  assert_eq!(plaintext, decrypted);
}

#[test]
fn test_cipher_with_empty_input() {
  let cipher =
    Cipher::from_password(b"password", &SaltString::generate(&mut OsRng))
      .unwrap();

  let plaintext = "".to_string();
  let (ciphertext, nonce) = cipher.encrypt(&plaintext).unwrap();

  let decrypted = cipher.decrypt(&ciphertext[..], &nonce[..]).unwrap();
  let decrypted = String::from_utf8(decrypted).unwrap();

  assert_eq!(plaintext, decrypted);
}

#[test]
#[should_panic(expected = "AesGcm")]
fn test_cipher_decrypt_on_invalid_encryption() {
  let cipher =
    Cipher::from_password(b"password", &SaltString::generate(&mut OsRng))
      .unwrap();
  let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
  let ciphertext = vec![1, 2, 3, 4, 5];

  cipher.decrypt(&ciphertext[..], &nonce).unwrap();
}

#[test]
fn test_update_master_password() {
  let (mut manager, _temp_file) = setup_db();
  manager.add_password("test_id", "test_password").unwrap();

  let new_master_password = "new_master_password";
  manager.update_master_password(new_master_password).unwrap();

  // Verify that old master password is invalidated
  assert!(PwdManager::new(
    _temp_file.path().to_str().unwrap(),
    "master_password"
  )
  .is_err());

  // Verify that new master password is valid
  assert!(PwdManager::new(
    _temp_file.path().to_str().unwrap(),
    new_master_password
  )
  .is_ok());

  // Verify encryption/decryption
  assert_eq!(
    manager.get_password("test_id").unwrap(),
    Some("test_password".to_string())
  );

  manager.add_password("new_id", "new_password").unwrap();
  assert_eq!(
    manager.get_password("new_id").unwrap(),
    Some("new_password".to_string())
  );
}

const WEAK_PASSWORDS: &[&str] = &[
  "12345678",
  "password",
  "password123",
  "p@ssword",
  "p@ssword1",
];

#[test]
fn test_initial_weak_password() {
  let temp_file = NamedTempFile::new().unwrap();
  let db_path = temp_file.path().to_str().unwrap();

  for &password in WEAK_PASSWORDS.iter() {
    let result = PwdManager::new(db_path, password);
    match result {
      Err(Error::WeakPassword(_)) => {}
      _ => {
        panic!("Should return Error::WeakPassword.");
      }
    }
  }
}

#[test]
fn test_update_to_weak_password() {
  let (mut manager, _temp_file) = setup_db();

  for &password in WEAK_PASSWORDS.iter() {
    let result = manager.update_master_password(password);
    match result {
      Err(Error::WeakPassword(_)) => {}
      _ => {
        panic!("Should return Error::WeakPassword.");
      }
    }
  }
}

#[test]
fn test_atomicity_of_new() {
  let temp_file = NamedTempFile::new().unwrap();
  let db_path = temp_file.path().to_str().unwrap();
  let res = PwdManager::new(db_path, "weakpassword");

  assert!(res.is_err());

  let conn = Connection::open(db_path).unwrap();
  let metadata_exists: u8 = conn
    .query_row(
      "SELECT COUNT(*) FROM sqlite_master
       WHERE type = 'table' AND name = 'metadata'",
      [],
      |row| row.get(0),
    )
    .unwrap();

  // 'metadata' table should not exist because new() should have rolled back
  assert_eq!(metadata_exists, 0);
}
