/*
Copyright 2024 Owain Davies
SPDX-License-Identifier: Apache-2.0
*/
mod cli;

use clap::Parser;
use cli::{Error, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use pwdg::{PwdGen, PwdGenOptions};
use pwdm::{
  Error::{IncorrectMasterPassword, WeakPassword},
  PwdManager, UserIdentity,
};
use std::path::{Path, PathBuf};

const PWDGEN_OPTIONS: Option<PwdGenOptions> = Some(PwdGenOptions {
  min_upper: 2,
  min_lower: 2,
  min_digit: 2,
  min_special: 2,
  exclude: None,
});
const PWDGEN_LEN: usize = 16;

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

  let found_signature = PwdManager::found_signature(path);

  let mut pwd_manager: PwdManager;
  loop {
    clear_screen()?;

    print_header(path);
    let master_password: String = Password::new()
      .with_prompt("Enter master password")
      .interact()?;

    if !found_signature {
      let confirm: String =
        Password::new().with_prompt("Repeat password").interact()?;
      if master_password != confirm {
        print_if_password_confirmation_fails();
        press_enter_to_continue();
        continue;
      }
    }
    match PwdManager::new(path, &master_password) {
      Ok(manager) => {
        pwd_manager = manager;
        break;
      }
      Err(WeakPassword(feedback)) => {
        print_if_weak_password(feedback);
      }
      Err(IncorrectMasterPassword) => {
        eprintln!("{}", format!("Error: {}", IncorrectMasterPassword).red());
        std::process::exit(1);
      }
      Err(e) => return Err(Error::Manager(e)),
    }

    press_enter_to_continue();
  }

  let pwdgen = PwdGen::new(PWDGEN_LEN, PWDGEN_OPTIONS)?;

  let mut last_action: Option<Action> = None;
  loop {
    clear_screen()?;

    print_header(path);
    let selection = match last_action.take() {
      Some(action) => {
        print_selected_action(action);
        action
      }
      _ => select_action()?,
    };

    match match_action(selection, &pwdgen, &mut pwd_manager)? {
      UserAction::Back => continue,
      UserAction::Continue => {}
      UserAction::ContinueWithMessage(msg) => println!("{}", msg),
      UserAction::Exit => break,
      UserAction::TryAgain(action) => last_action = Some(action),
    }

    press_enter_to_continue();
  }

  Ok(())
}

enum UserAction<T> {
  Back,
  Continue,
  ContinueWithMessage(T),
  Exit,
  TryAgain(Action),
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

const SELECTIONS: &[Action] = &[
  Action::Add,
  Action::Get,
  Action::Delete,
  Action::Update,
  Action::List,
  Action::UpdateMaster,
  Action::Exit,
];

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
  let selection = Select::with_theme(&ColorfulTheme::default())
    .with_prompt("Choose action")
    .default(0)
    .items(SELECTIONS)
    .interact()?;
  Ok(SELECTIONS[selection])
}

fn get_identity() -> Result<UserAction<UserIdentity>> {
  let service: String = Input::new()
    .with_prompt(format!("Enter {} ('b' to go back)", "Service".cyan()))
    .interact_text()?;
  if service == "b" {
    return Ok(UserAction::Back);
  }

  let username: String = Input::new()
    .with_prompt(format!(
      "Enter {} (or press Enter for None, 'b' to go back)",
      "Username".cyan()
    ))
    .allow_empty(true)
    .interact_text()?;
  if username == "b" {
    return Ok(UserAction::Back);
  }

  let uid = UserIdentity {
    service,
    username: if username.is_empty() {
      None
    } else {
      Some(username)
    },
  };
  Ok(UserAction::ContinueWithMessage(uid))
}

fn match_action(
  selection: Action,
  pwdgen: &PwdGen,
  pwd_manager: &mut PwdManager,
) -> Result<UserAction<String>> {
  match selection {
    Action::Add | Action::Get | Action::Delete | Action::Update => {
      match get_identity()? {
        UserAction::Back => Ok(UserAction::Back),
        UserAction::ContinueWithMessage(uid) => match selection {
          Action::Add => add_password(pwd_manager, pwdgen, &uid),
          Action::Get => get_password(pwd_manager, &uid),
          Action::Delete => delete_password(pwd_manager, &uid),
          Action::Update => update_password(pwd_manager, pwdgen, &uid),
          _ => unreachable!(),
        },
        _ => unreachable!(),
      }
    }
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
    UserAction::TryAgain(f) => Ok(UserAction::TryAgain(f)),
    _ => panic!("Unexpected UserAction"),
  }
}

fn add_password(
  pwd_manager: &PwdManager,
  pwdgen: &PwdGen,
  uid: &UserIdentity,
) -> Result<UserAction<String>> {
  if pwd_manager.get_password(uid)?.is_none() {
    let password: String = generate_password(pwdgen, "Enter password")?;
    pwd_manager.add_password(uid, &password)?;
    Ok(UserAction::ContinueWithMessage("Password added.".into()))
  } else {
    println!("{}", "Password exists.".red());
    Ok(UserAction::Continue)
  }
}

fn get_password(
  pwd_manager: &PwdManager,
  uid: &UserIdentity,
) -> Result<UserAction<String>> {
  match pwd_manager.get_password(uid)? {
    Some(entry) => Ok(UserAction::ContinueWithMessage(format!(
      "{}: {}",
      "Password".cyan(),
      entry.password
    ))),
    None => {
      print_no_password_found_for_id(uid);
      Ok(UserAction::Continue)
    }
  }
}

fn delete_password(
  pwd_manager: &PwdManager,
  uid: &UserIdentity,
) -> Result<UserAction<String>> {
  if pwd_manager.get_password(uid)?.is_none() {
    print_no_password_found_for_id(uid);
    return Ok(UserAction::Continue);
  } else if Confirm::new()
    .with_prompt(format!(
      "Are you sure you want to delete the password for {}",
      uid
    ))
    .interact()?
  {
    pwd_manager.delete_password(uid)?;
    return Ok(UserAction::ContinueWithMessage("Password deleted.".into()));
  }
  Ok(UserAction::Continue)
}

fn update_password(
  pwd_manager: &PwdManager,
  pwdgen: &PwdGen,
  uid: &UserIdentity,
) -> Result<UserAction<String>> {
  if pwd_manager.get_password(uid)?.is_none() {
    print_no_password_found_for_id(uid);
    return Ok(UserAction::Continue);
  }
  let new_password: String = generate_password(pwdgen, "Enter new password")?;
  pwd_manager.update_password(uid, &new_password)?;
  Ok(UserAction::ContinueWithMessage("Password updated.".into()))
}

fn list_passwords(pwd_manager: &PwdManager) -> Result<()> {
  let uids = pwd_manager.list_passwords()?;
  if uids.is_empty() {
    println!("No passwords stored.");
  } else {
    let max_service_len = uids
      .iter()
      .map(|uid| uid.service.len())
      .max()
      .unwrap_or(0)
      .max("Service".len());
    let max_username_len = uids
      .iter()
      .filter_map(|uid| uid.username.as_ref().map(String::len))
      .max()
      .unwrap_or(0);
    let separator_len = " | ".len();
    let header_len = max_service_len + separator_len + "Username".len();

    println!(
      "\n{0:<pad$} | {1}",
      "Service".cyan(),
      "Username".cyan(),
      pad = max_service_len
    );
    println!(
      "{:=<pad$}",
      "",
      pad = std::cmp::max(
        max_service_len + max_username_len + separator_len,
        header_len
      )
    );
    for uid in uids {
      println!(
        "{0:<pad$} | {1:}",
        uid.service,
        uid.username.as_deref().unwrap_or(""),
        pad = max_service_len
      );
    }
  }
  Ok(())
}

fn update_master_password(
  pwd_manager: &mut PwdManager,
) -> Result<UserAction<String>> {
  let action = |new_master_password: &str| {
    pwd_manager.update_master_password(new_master_password)?;
    println!("Master password updated.");
    Ok::<_, Error>(())
  };

  match do_action("Enter new master password", action, true) {
    Err(Error::Manager(WeakPassword(feedback))) => {
      print_if_weak_password(feedback);
      Ok(UserAction::TryAgain(Action::UpdateMaster))
    }
    other => other,
  }
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

fn clear_screen() -> Result<()> {
  clearscreen::ClearScreen::Terminfo.clear()?;
  Ok(())
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
  let input = Password::new()
    .with_prompt(format!("{} ('{}' to go back)", prompt, back_keyword))
    .interact()?;
  if input == back_keyword {
    return Ok(UserAction::Back);
  }

  let confirm = Password::new()
    .with_prompt(format!("Repeat password ('{}' to go back)", back_keyword))
    .interact()?;
  if confirm == back_keyword {
    return Ok(UserAction::Back);
  }

  if input != confirm {
    print_if_password_confirmation_fails();
    Ok(UserAction::TryAgain(Action::UpdateMaster))
  } else {
    if Confirm::new()
      .with_prompt("Are you sure you want to change the master password?")
      .interact()?
    {
      return Ok(UserAction::ContinueWithMessage(input));
    }
    Ok(UserAction::Back)
  }
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

fn message_if_weak_password(opt: Option<zxcvbn::feedback::Feedback>) -> String {
  let mut details: String = String::new();

  if let Some(feedback) = opt {
    if let Some(warning) = feedback.warning() {
      details = format!("Warning: {}", warning);
    }

    let suggestions: Vec<String> = feedback
      .suggestions()
      .iter()
      .map(|s| s.to_string())
      .collect();

    if !suggestions.is_empty() {
      let sugg_str = suggestions.join(" ");
      details.push_str(&format!("\nSuggestions: {}", sugg_str));
    }
  }

  details
}

fn press_enter_to_continue() {
  println!("\nPress Enter to continue...");
  let _ = std::io::stdin().read_line(&mut String::new());
}

fn print_if_weak_password(feedback: Option<zxcvbn::feedback::Feedback>) {
  println!("{}", "\nThe password entered is weak.".red());
  let msg = message_if_weak_password(feedback).red();
  if !msg.is_empty() {
    println!("{}", msg);
  }
  println!("{}", "Please try again.".red());
}

fn print_header(path: &str) {
  println!(
    "\
██████╗ ██╗    ██╗██████╗ ███╗   ███╗
██╔══██╗██║    ██║██╔══██╗████╗ ████║
██████╔╝██║ █╗ ██║██║  ██║██╔████╔██║
██╔═══╝ ██║███╗██║██║  ██║██║╚██╔╝██║
██║     ╚███╔███╔╝██████╔╝██║ ╚═╝ ██║
╚═╝      ╚══╝╚══╝ ╚═════╝ ╚═╝     ╚═╝

{}
{}: {}
",
    "pwdm - Password Manager".bright_magenta().bold(),
    "Database".green(),
    path
  );
}

fn print_no_password_found_for_id(uid: &UserIdentity) {
  println!("No password found for {}", uid)
}

fn print_if_password_confirmation_fails() {
  println!(
    "\n{}",
    "Error: the passwords don't match. Please try again.".red()
  );
}

// TODO: this should be temporary. It's currently used to emulate the
// dialoguer output after choosing an option from `Select` so that if a try
// again path is used, everything looks the same. This approach is not ideal and
// needs to be investigated.
fn print_selected_action(action: Action) {
  println!(
    "{} Choose action · {}",
    "✔".green(),
    action.to_string().green()
  );
}
