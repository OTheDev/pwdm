/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
#![doc = include_str!("../README.md")]
mod db;
mod manager;

pub use manager::error::{Error, Result};
pub use manager::PwdManager;
