/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
pub mod error;

use crate::db;
use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
  aes::cipher::typenum,
  Aes256Gcm, Nonce,
};
use argon2::{
  password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier,
    SaltString,
  },
  Argon2,
};
use error::{Error, Result};
use rusqlite::{params, Connection, OpenFlags, Transaction};
use zxcvbn::zxcvbn;

/// Password manager struct.
pub struct PwdManager {
  conn: Connection,
  cipher: Cipher,
}

impl PwdManager {
  // NOTE: This hardcoded signature is NOT used for security purposes.
  const SIGNATURE: &'static str = "pwdm__68DB418B-5E94-4640-BF7D-3340812ACE36";

  /// Creates a new `PwdManager`. It opens a new connection to the SQLite
  /// database (creating one if the database does not exist at the path),
  /// initializes it with the necessary tables if they do not already exist,
  /// authenticates the master password, retrieves or generates the master
  /// salt, and prepares the cipher.
  pub fn new(db_path: &str, master_password: &str) -> Result<Self> {
    let mut conn = Connection::open(db_path)?;
    let db_empty = db::is_empty(&conn)?;
    let found_signature = Self::query_signature(&conn);

    // Wrap all mutating db operations inside a transaction for atomicity
    let tx = conn.transaction()?;

    if db_empty {
      Self::init_db(&tx)?;
    } else if !found_signature {
      return Err(Error::SignatureNotFound);
    }

    Self::verify_master_password(&tx, master_password)?;
    let master_salt = Self::get_or_generate_salt(&tx, "master_salt")?;

    let cipher =
      Cipher::from_password(master_password.as_bytes(), &master_salt)?;

    tx.commit()?;

    Ok(Self { conn, cipher })
  }

  fn init_db(tx: &Transaction) -> Result<()> {
    tx.execute(
      "CREATE TABLE metadata (
        name TEXT PRIMARY KEY,
        value BLOB
      )",
      [],
    )?;

    tx.execute(
      "CREATE TABLE passwords (
        id TEXT PRIMARY KEY,
        ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0),
        nonce BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )",
      [],
    )?;

    tx.execute(
      "INSERT INTO metadata (name, value) VALUES (?1, ?2)",
      params!["signature", Self::SIGNATURE],
    )?;

    Ok(())
  }

  fn get_or_generate_salt(
    tx: &Transaction,
    salt_name: &str,
  ) -> Result<SaltString> {
    let out_salt: String = match tx.query_row(
      "SELECT value FROM metadata WHERE name = ?1",
      rusqlite::params![salt_name],
      |row| row.get(0),
    ) {
      Ok(salt) => salt,
      Err(rusqlite::Error::QueryReturnedNoRows) => {
        let salt = SaltString::generate(&mut OsRng);

        tx.execute(
          "INSERT INTO metadata (name, value) VALUES (?1, ?2)",
          params![salt_name, salt.as_ref()],
        )?;

        salt.as_ref().to_owned()
      }
      Err(other) => return Err(Error::from(other)),
    };

    Ok(SaltString::from_b64(&out_salt)?)
  }

  fn verify_master_password(
    tx: &Transaction,
    master_password: &str,
  ) -> Result<()> {
    let argon2 = Argon2::default();

    let master_hash: String = match tx.query_row(
      "SELECT value FROM metadata WHERE name = 'master_hash'",
      [],
      |row| row.get(0),
    ) {
      Ok(hash) => hash,
      Err(rusqlite::Error::QueryReturnedNoRows) => {
        Self::check_password_strength(master_password)?;

        let auth_salt = SaltString::generate(&mut OsRng);

        let master_hash = argon2
          .hash_password(master_password.as_ref(), &auth_salt)?
          .to_string();
        tx.execute(
          "INSERT INTO metadata (name, value) VALUES ('master_hash', ?1)",
          params![&master_hash],
        )?;
        master_hash
      }
      Err(other) => return Err(Error::from(other)),
    };

    let parsed_hash = PasswordHash::new(&master_hash)?;
    if argon2
      .verify_password(master_password.as_ref(), &parsed_hash)
      .is_err()
    {
      return Err(Error::IncorrectMasterPassword);
    }

    Ok(())
  }

  /// Adds a password to the database.
  pub fn add_password(&self, id: &str, password: &str) -> Result<()> {
    if password.is_empty() {
      return Err(Error::EmptyPassword);
    }

    let (ciphertext, nonce) = self.cipher.encrypt(password)?;

    match self.conn.execute(
      "INSERT INTO passwords (id, ciphertext, nonce) VALUES (?1, ?2, ?3)",
      params![id, &ciphertext[..], &nonce[..]],
    ) {
      Ok(_) => Ok(()),
      Err(err) => match err {
        rusqlite::Error::SqliteFailure(error, _)
          if error.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
          Err(Error::DuplicateId(id.to_string()))
        }
        _ => Err(Error::Sqlite(err)),
      },
    }
  }

  /// Removes a password by its ID from the database.
  pub fn delete_password(&self, id: &str) -> Result<()> {
    let changes = self
      .conn
      .execute("DELETE FROM passwords WHERE id = ?1", params![id])?;

    if changes == 0 {
      Err(Error::PasswordNotFound)
    } else {
      Ok(())
    }
  }

  /// Fetches all password IDs sorted in ascending order.
  pub fn list_passwords(&self) -> Result<Vec<String>> {
    let mut stmt = self
      .conn
      .prepare("SELECT id FROM passwords ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| row.get(0))?;

    let mut ids = Vec::new();
    for id_result in rows {
      let id: String = id_result?;
      ids.push(id);
    }

    Ok(ids)
  }

  /// Updates a password by its ID.
  pub fn update_password(&self, id: &str, new_password: &str) -> Result<()> {
    if new_password.is_empty() {
      return Err(Error::EmptyPassword);
    }
    if self.get_password(id)?.is_none() {
      return Err(Error::PasswordNotFound);
    }

    let (ciphertext, nonce) = self.cipher.encrypt(new_password)?;

    self.conn.execute(
      "UPDATE passwords SET ciphertext = ?1, nonce = ?2 WHERE id = ?3",
      params![&ciphertext[..], &nonce[..], id],
    )?;

    Ok(())
  }

  /// Retrieves a password by its ID.
  pub fn get_password(&self, id: &str) -> Result<Option<String>> {
    let mut stmt = self
      .conn
      .prepare("SELECT ciphertext, nonce FROM passwords WHERE id = ?")?;

    let mut rows = stmt.query(params![id])?;

    if let Some(row) = rows.next()? {
      let ciphertext: Vec<u8> = row.get(0)?;
      let nonce: Vec<u8> = row.get(1)?;

      let decrypted_plaintext = self.cipher.decrypt(&ciphertext, &nonce)?;

      Ok(Some(String::from_utf8(decrypted_plaintext)?))
    } else {
      Ok(None)
    }
  }

  /// Update the master password associated with the database.
  pub fn update_master_password(
    &mut self,
    new_master_password: &str,
  ) -> Result<()> {
    Self::check_password_strength(new_master_password)?;

    let argon2 = Argon2::default();

    let auth_salt = SaltString::generate(&mut OsRng);
    let master_hash = argon2
      .hash_password(new_master_password.as_ref(), &auth_salt)?
      .to_string();

    let master_salt = SaltString::generate(&mut OsRng);
    let cipher =
      Cipher::from_password(new_master_password.as_bytes(), &master_salt)?;

    let tx = self.conn.transaction()?;

    tx.execute(
      "UPDATE metadata SET value = ?1 WHERE name = 'master_salt'",
      params![master_salt.as_ref()],
    )?;

    tx.execute(
      "UPDATE metadata SET value = ?1 WHERE name = 'master_hash'",
      params![&master_hash],
    )?;

    {
      let mut stmt =
        tx.prepare("SELECT id, ciphertext, nonce FROM passwords")?;

      let rows = stmt.query_map([], |row| {
        let id: String = row.get(0)?;
        let ciphertext: Vec<u8> = row.get(1)?;
        let nonce: Vec<u8> = row.get(2)?;
        Ok((id, ciphertext, nonce))
      })?;

      for row in rows {
        let (id, ciphertext, nonce) = row?;

        let decrypted_plaintext = self.cipher.decrypt(&ciphertext, &nonce)?;
        let (new_ciphertext, new_nonce) =
          cipher.encrypt(std::str::from_utf8(&decrypted_plaintext)?)?;

        tx.execute(
          "UPDATE passwords SET ciphertext = ?1, nonce = ?2 WHERE id = ?3",
          params![&new_ciphertext[..], &new_nonce[..], id],
        )?;
      }
    }

    tx.commit()?;

    self.cipher = cipher;

    Ok(())
  }

  fn check_password_strength(password: &str) -> Result<()> {
    let entropy = zxcvbn(password, &[])?;
    if entropy.score() < 4 {
      return Err(Error::WeakPassword(entropy.feedback().clone()));
    }
    Ok(())
  }

  fn query_signature(conn: &Connection) -> bool {
    let sig: String = match conn.query_row(
      "SELECT value FROM metadata WHERE name = 'signature'",
      [],
      |row| row.get(0),
    ) {
      Ok(signature) => signature,
      Err(_) => return false,
    };

    sig == Self::SIGNATURE
  }

  /// Return `true` if a database at path `db_path` exists and the `pwdm` 'file
  /// signature' is stored within it. If any error occurs during the process,
  /// including if the database does not exist, if the signature is not found,
  /// or if the database file cannot be read, this function will return `false`.
  pub fn found_signature(db_path: &str) -> bool {
    let conn = match Connection::open_with_flags(
      db_path,
      // Open the database in read-only mode. If the database does not already
      // exist, an error is returned.
      OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
      Ok(connection) => connection,
      Err(_) => return false,
    };

    Self::query_signature(&conn)
  }
}

struct Cipher(Aes256Gcm);

impl Cipher {
  fn from_password(password: &[u8], salt: &SaltString) -> Result<Self> {
    const KEY_SIZE: usize = 32;
    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; KEY_SIZE];
    argon2.hash_password_into(
      password,
      salt.as_ref().as_bytes(),
      &mut key_bytes,
    )?;
    Ok(Self(Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(
      &key_bytes,
    ))))
  }

  fn encrypt(
    &self,
    plaintext: &str,
  ) -> Result<(Vec<u8>, GenericArray<u8, typenum::U12>)> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = self.0.encrypt(&nonce, plaintext.as_ref())?;
    Ok((ciphertext, nonce))
  }

  fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    let decrypted_plaintext = self.0.decrypt(nonce, ciphertext)?;
    Ok(decrypted_plaintext)
  }
}

#[cfg(test)]
mod tests;
