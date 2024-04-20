/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
//! Error type

/// Result with `pwdm`'s [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("AesGcm error: {0}")]
  AesGcm(aes_gcm::aead::Error),

  #[error("Argon2 error: {0}")]
  Argon2(argon2::Error),

  #[error("Argon2PasswordHash error: {0}")]
  Argon2PasswordHash(argon2::password_hash::Error),

  #[error("The password provided is empty")]
  EmptyPassword,

  #[error("Incorrect master password")]
  IncorrectMasterPassword,

  #[error("No password found for the provided id")]
  PasswordNotFound,

  #[error("SQLite error: {0}")]
  Sqlite(#[from] rusqlite::Error),

  #[error("UTF-8 Decoding error: {0}")]
  Utf8Decoding(#[from] std::string::FromUtf8Error),
}

impl From<aes_gcm::aead::Error> for Error {
  fn from(err: aes_gcm::aead::Error) -> Self {
    Self::AesGcm(err)
  }
}

impl From<argon2::Error> for Error {
  fn from(err: argon2::Error) -> Self {
    Self::Argon2(err)
  }
}

impl From<argon2::password_hash::Error> for Error {
  fn from(err: argon2::password_hash::Error) -> Self {
    Self::Argon2PasswordHash(err)
  }
}
