[<img alt="github" src="https://img.shields.io/badge/github-othedev/pwdm-e0a484?style=for-the-badge&labelColor=3e454e&logo=github" height="20">](https://github.com/OTheDev/pwdm)
[![](https://github.com/OTheDev/pwdm/actions/workflows/test.yml/badge.svg)](https://github.com/OTheDev/pwdm/actions/workflows/test.yml)
[![](https://github.com/OTheDev/pwdm/actions/workflows/static.yml/badge.svg)](https://github.com/OTheDev/pwdm/actions/workflows/static.yml)

# pwdm - Password Manager

Rudimentary command-line tool and Rust library for managing passwords.

## Password Database

Passwords are encrypted and stored in a SQLite database where each password is
identified by a unique ID string.

## Security

Each password is encrypted using AES-256-GCM before it is stored in the database.
`pwdm` uses the user-provided **master password** (with a randomly-generated
salt) as an input to the [Argon2](https://en.wikipedia.org/wiki/Argon2) key
derivation function (Argon2id) to derive the encryption key. There exists one
master password associated with a database file. When the master password is
first provided, Argon2 is also used (with another randomly-generated salt) to
hash the password to a PHC string appropriate for password-based authentication.
The hash is stored in the database to authenticate the master password in
subsequent invocations.

## Command-line

```console
$ pwdm --help
Command-line password manager.

Usage: pwdm [OPTIONS]

Options:
  -p, --path <PATH>  Path to the database file
  -h, --help         Print help
  -V, --version      Print version
```

By default, the `pwdm` CLI stores the password database file at
`~/.pwdm/passwords.db`. To specify a custom path, use the `-p` or `--path`
option or set the `PWDM_PATH` environment variable.

On the command-line, after entering the master password, the following
interactive commands can be used:

 - `Add`: Add a new password.
 - `Get`: Retrieve a password.
 - `Delete`: Remove a password entry.
 - `Update`: Update an existing password.
 - `List`: List all password IDs.
 - `Exit`: Exit the program.

In `Add` or `Update`, either input a password manually or choose to
automatically generate a secure one.

### Installation

```shell
cargo install pwdm
```

#### From Source
```shell
git clone git@github.com:OTheDev/pwdm.git
cd pwdm
# Optionally, run `cargo test` to run tests
cargo install --path .
```

## License

`pwdm` is licensed under Apache-2.0.
