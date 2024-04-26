/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("Dialoguer error: {0}")]
  Dialoguer(#[from] dialoguer::Error),

  #[error("I/O error: {0}")]
  IO(#[from] std::io::Error),

  #[error("Manager error: {0}")]
  Manager(#[from] pwdm::Error),

  #[error("Path error: {0}")]
  Path(&'static str),

  #[error("Password generator error: {0}")]
  PwdGen(#[from] pwdg::Error),

  #[error("clearscreen error: {0}")]
  ClearScreen(#[from] clearscreen::Error),
}
