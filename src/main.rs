/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
mod cli;

use clap::Parser;
use cli::{Error, Result};
use crossterm::{
  execute,
  terminal::{Clear, ClearType},
};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use pwdg::{PwdGen, PwdGenOptions};
use pwdm::PwdManager;
use std::io::stdout;
use std::path::{Path, PathBuf};

/// Password Manager CLI
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
  /// Path to the database file.
  #[clap(short, long, value_parser = clap::value_parser!(std::path::PathBuf))]
  path: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
  let args = Args::parse();

  let db_path = determine_path(args)?;
  ensure_path_dir_exists(&db_path)?;

  let path = &db_path.to_string_lossy();
  println!("Database: {}", path);
  let master_password: String = Password::new()
    .with_prompt("Enter master password")
    .interact()?;

  let pwdgen = PwdGen::new(
    16,
    Some(PwdGenOptions {
      min_upper: 2,
      min_lower: 2,
      min_digit: 2,
      min_special: 2,
      exclude: None,
    }),
  )?;

  match PwdManager::new(path, &master_password) {
    Ok(mut pwd_manager) => loop {
      clear_screen()?;

      let selection = select_action()?;
      match match_action(selection, &pwdgen, &mut pwd_manager)? {
        UserAction::Back => continue,
        UserAction::Continue => {}
        UserAction::ContinueWithMessage(msg) => println!("{}", msg),
        UserAction::Exit => break,
      }

      println!("\nPress Enter to continue...");
      let _ = std::io::stdin().read_line(&mut String::new());
    },
    Err(e) => return Err(Error::Manager(e)),
  }

  Ok(())
}

enum UserAction<T> {
  Back,
  Continue,
  ContinueWithMessage(T),
  Exit,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum Action {
  Add,
  Get,
  Delete,
  Update,
  List,
  UpdateMaster,
  Exit,
}

impl core::fmt::Display for Action {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    write!(
      f,
      "{}",
      match self {
        Action::Add => "Add",
        Action::Get => "Get",
        Action::Delete => "Delete",
        Action::Update => "Update",
        Action::List => "List",
        Action::UpdateMaster => "Update Master Password",
        Action::Exit => "Exit",
      }
    )
  }
}

fn select_action() -> Result<Action> {
  let selections = &[
    Action::Add,
    Action::Get,
    Action::Delete,
    Action::Update,
    Action::List,
    Action::UpdateMaster,
    Action::Exit,
  ];
  let selection = Select::with_theme(&ColorfulTheme::default())
    .with_prompt("Choose action")
    .default(0)
    .items(&selections[..])
    .interact()?;
  Ok(selections[selection])
}

fn match_action(
  selection: Action,
  pwdgen: &PwdGen,
  pwd_manager: &mut PwdManager,
) -> Result<UserAction<String>> {
  match selection {
    Action::Add => add_password(pwd_manager, pwdgen),
    Action::Get => get_password(pwd_manager),
    Action::Delete => delete_password(pwd_manager),
    Action::Update => update_password(pwd_manager, pwdgen),
    Action::List => {
      list_passwords(pwd_manager)?;
      Ok(UserAction::Continue)
    }
    Action::UpdateMaster => update_master_password(pwd_manager),
    Action::Exit => Ok(UserAction::Exit),
  }
}

fn do_action<F>(
  prompt: &str,
  mut action: F,
  is_password: bool,
) -> Result<UserAction<String>>
where
  F: FnMut(&str) -> Result<()>,
{
  let result = if is_password {
    password_with_back_option(prompt, "b")?
  } else {
    input_with_back_option(prompt, "b")?
  };

  match result {
    UserAction::Back => Ok(UserAction::Back),
    UserAction::ContinueWithMessage(msg) => {
      action(&msg)?;
      Ok(UserAction::Continue)
    }
    _ => panic!("Unexpected UserAction"),
  }
}

fn add_password(
  pwd_manager: &PwdManager,
  pwdgen: &PwdGen,
) -> Result<UserAction<String>> {
  do_action(
    "Enter ID",
    |id| {
      if pwd_manager.get_password(id)?.is_none() {
        let password: String = generate_password(pwdgen, "Enter password")?;
        pwd_manager.add_password(id, &password)?;
        println!("Password added.");
      } else {
        println!("Password exists.");
      }
      Ok(())
    },
    false,
  )
}

fn get_password(pwd_manager: &PwdManager) -> Result<UserAction<String>> {
  do_action(
    "Enter ID",
    |id| {
      match pwd_manager.get_password(id)? {
        Some(password) => println!("Password: {}", password),
        None => println!("No password found for ID: {}", id),
      }
      Ok(())
    },
    false,
  )
}

fn delete_password(pwd_manager: &PwdManager) -> Result<UserAction<String>> {
  do_action(
    "Enter ID",
    |id| {
      if pwd_manager.get_password(id)?.is_none() {
        println!("No password found for ID: {}", id);
      } else if Confirm::new()
        .with_prompt(format!(
          "Are you sure you want to delete password for ID {}",
          id
        ))
        .interact()?
      {
        pwd_manager.delete_password(id)?;
        println!("Password deleted.");
      }
      Ok(())
    },
    false,
  )
}

fn update_password(
  pwd_manager: &PwdManager,
  pwdgen: &PwdGen,
) -> Result<UserAction<String>> {
  do_action(
    "Enter ID",
    |id| {
      if pwd_manager.get_password(id)?.is_none() {
        println!("No password found for ID: {}", id);
      } else {
        let new_password: String =
          generate_password(pwdgen, "Enter new password")?;
        pwd_manager.update_password(id, &new_password)?;
        println!("Password updated.");
      }
      Ok(())
    },
    false,
  )
}

fn list_passwords(pwd_manager: &PwdManager) -> Result<()> {
  let ids = pwd_manager.list_passwords()?;
  if ids.is_empty() {
    println!("No passwords stored.");
  } else {
    println!("Stored passwords:");
    for id in ids {
      println!("- {}", id);
    }
  }
  Ok(())
}

fn update_master_password(
  pwd_manager: &mut PwdManager,
) -> Result<UserAction<String>> {
  do_action(
    "Enter new master password",
    |new_master_password| {
      pwd_manager.update_master_password(new_master_password)?;
      println!("Master password updated.");
      Ok(())
    },
    true,
  )
}

fn generate_password(pwdgen: &PwdGen, prompt: &str) -> Result<String> {
  let use_autogenerated_password = Confirm::new()
    .with_prompt("Do you want to generate a password automatically?")
    .interact()?;
  Ok(if use_autogenerated_password {
    pwdgen.gen()
  } else {
    Password::new().with_prompt(prompt).interact()?
  })
}

fn clear_screen() -> std::io::Result<()> {
  execute!(stdout(), Clear(ClearType::All))
}

fn input_with_back_option(
  prompt: &str,
  back_keyword: &str,
) -> Result<UserAction<String>> {
  let input: String = Input::new()
    .with_prompt(format!(
      "{} (or type '{}' to go back)",
      prompt, back_keyword
    ))
    .interact_text()?;

  if input == back_keyword {
    Ok(UserAction::Back)
  } else {
    Ok(UserAction::ContinueWithMessage(input))
  }
}

fn password_with_back_option(
  prompt: &str,
  back_keyword: &str,
) -> Result<UserAction<String>> {
  let mut input: String;
  let mut confirm: String;

  loop {
    input = Password::new()
      .with_prompt(format!("{} ('{}' to go back)", prompt, back_keyword))
      .interact()?;
    if input == back_keyword {
      return Ok(UserAction::Back);
    }

    confirm = Password::new()
      .with_prompt(format!("Repeat password ('{}' to go back)", back_keyword))
      .interact()?;
    if confirm == back_keyword {
      return Ok(UserAction::Back);
    }

    if input != confirm {
      println!("Error: the passwords don't match. Please try again.\n");
    } else {
      if Confirm::new()
        .with_prompt("Are you sure you want to change the master password?")
        .interact()?
      {
        break;
      }
      return Ok(UserAction::Back);
    }
  }

  Ok(UserAction::ContinueWithMessage(input))
}

fn determine_path(args: Args) -> Result<PathBuf> {
  args
    .path
    .or_else(|| {
      std::env::var("PWDM_PATH")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
          dirs::home_dir().map(|mut path| {
            path.push(".pwdm/passwords.db");
            path
          })
        })
    })
    .ok_or_else(|| Error::Path("Failed to determine database path"))
}

fn ensure_path_dir_exists(path: &Path) -> Result<()> {
  if let Some(parent_dir) = path.parent() {
    if !parent_dir.exists() {
      std::fs::create_dir_all(parent_dir)?;
    }
  }
  Ok(())
}
