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

  #[error("Duplicate id '{0}': A password with this id already exists")]
  DuplicateId(String),

  #[error("The password provided is empty")]
  EmptyPassword,

  #[error("Incorrect master password")]
  IncorrectMasterPassword,

  #[error("No password found for the provided id")]
  PasswordNotFound,

  #[error("pwdm signature not found")]
  SignatureNotFound,

  #[error("SQLite error: {0}")]
  Sqlite(#[from] rusqlite::Error),

  #[error("{0}")]
  Utf8Decoding(#[from] Utf8DecodingError),

  #[error("Weak password")]
  WeakPassword(Option<zxcvbn::feedback::Feedback>),

  #[error("zxcvbn error: {0}")]
  Zxcvbn(#[from] zxcvbn::ZxcvbnError),
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

impl From<core::str::Utf8Error> for Error {
  fn from(err: core::str::Utf8Error) -> Self {
    Self::Utf8Decoding(Utf8DecodingError::StrUtf8(err))
  }
}

impl From<std::string::FromUtf8Error> for Error {
  fn from(err: std::string::FromUtf8Error) -> Self {
    Self::Utf8Decoding(Utf8DecodingError::Utf8(err))
  }
}

#[derive(Debug, thiserror::Error)]
pub enum Utf8DecodingError {
  #[error("UTF-8 Decoding error (String): {0}")]
  Utf8(#[from] std::string::FromUtf8Error),

  #[error("UTF-8 Decoding error (str): {0}")]
  StrUtf8(#[from] core::str::Utf8Error),
}
