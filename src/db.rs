/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
use rusqlite::{Connection, Result};

pub fn is_empty(conn: &Connection) -> Result<bool> {
  conn
    .query_row(
      "SELECT exists (SELECT name FROM sqlite_master WHERE type = 'table')",
      [],
      |row| row.get(0),
    )
    .map(|x: u8| x == 0)
}
