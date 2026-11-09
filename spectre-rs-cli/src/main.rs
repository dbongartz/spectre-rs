use std::error::Error;
use std::io::{self, BufRead};
use std::process::ExitCode;

use clap::{
    Parser,
    builder::{Styles, styling::AnsiColor},
};
use colored::Colorize;
use rustyline::{DefaultEditor, error::ReadlineError};
use secstr::{SecStr, SecUtf8};
use spectre_rs_core::{
    get_site_password,
    identicon::{Identicon, IdenticonColor},
};

#[derive(Debug, Parser)]
#[clap(version, about, author, long_about = None, styles = CLAP_STYLE)]
struct Args {
    /// The user name to use.
    #[clap(short = 'u', long, env = "SPECTRE_USERNAME")]
    user_name: Option<String>,

    /// Supply the secret as a command-line argument. INSECURE: visible in process listings/history.
    #[clap(
        short = 'S',
        long,
        long_help = "Supply the secret as a command-line argument. This is insecure because arguments may be visible in process listings or shell history. Prefer the hidden prompt for interactive use or --secret-stdin for scripts."
    )]
    secret: Option<SecStr>,

    /// Read one secret line from stdin (for scripts; avoids exposing it in argv).
    #[clap(long, conflicts_with = "secret")]
    secret_stdin: bool,

    /// Specify the type of password to generate.
    #[clap(short = 't', long, value_enum, default_value_t=PwType::Long)]
    pw_type: PwType,

    /// The value of the counter
    #[clap(short = 'c', long, default_value_t = 1)]
    counter: u32,

    #[clap(short = 'p', long, value_enum, default_value_t = Scope::Authentication)]
    purpose: Scope,

    /// The site name to use.
    site_name: Option<String>,
}

/// Exit status after Ctrl-C at a prompt, as if the shell had seen the interrupt itself.
const EXIT_INTERRUPTED: u8 = 130;

/// The user cancelled a prompt: Ctrl-C, or Ctrl-D before any input.
#[derive(Debug)]
enum Cancelled {
    Interrupted,
    EndOfInput,
}

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupted => f.write_str("interrupted"),
            Self::EndOfInput => f.write_str("no input"),
        }
    }
}

impl Error for Cancelled {}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => match error.downcast_ref::<Cancelled>() {
            // The prompt already ended its line; there is nothing more to say.
            Some(Cancelled::Interrupted) => ExitCode::from(EXIT_INTERRUPTED),
            Some(Cancelled::EndOfInput) | None => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Args {
        user_name: provided_user_name,
        site_name: provided_site_name,
        secret,
        secret_stdin,
        pw_type,
        counter,
        purpose,
    } = Args::parse();

    // Prompting would read the names from the same stdin the secret is piped through.
    if secret_stdin && (provided_user_name.is_none() || provided_site_name.is_none()) {
        return Err("--secret-stdin needs the user name and site name as arguments".into());
    }

    let mut editor = DefaultEditor::new()?;
    let user_name = read_name(&mut editor, provided_user_name, "Enter user name: ", "User")?;
    let site_name = read_name(&mut editor, provided_site_name, "Enter site name: ", "Site")?;
    let user_secret = read_user_secret(secret, secret_stdin)?;
    if user_secret.unsecure().is_empty() {
        return Err("secret cannot be empty".into());
    }

    generate_and_print(
        &user_name,
        &user_secret,
        &site_name,
        counter,
        pw_type,
        purpose,
    )
}

/// Returns the name as given, without trimming: whitespace is part of the name, as in every
/// other Spectre client, so trimming it would derive different passwords.
fn read_name(
    editor: &mut DefaultEditor,
    provided_name: Option<String>,
    prompt: &str,
    name_kind: &str,
) -> Result<String, Box<dyn Error>> {
    let name = match provided_name {
        Some(name) => name,
        None => read_prompt(editor, prompt)?,
    };
    if name.trim().is_empty() {
        return Err(format!("{name_kind} name cannot be empty").into());
    }
    Ok(name)
}

fn read_user_secret(secret: Option<SecStr>, secret_stdin: bool) -> Result<SecStr, Box<dyn Error>> {
    match (secret, secret_stdin) {
        (Some(secret), _) => Ok(secret),
        (None, true) => Ok(read_secret_stdin()?),
        (None, false) => read_secret(),
    }
}

fn generate_and_print(
    user_name: &str,
    user_secret: &SecStr,
    site_name: &str,
    counter: u32,
    pw_type: PwType,
    purpose: Scope,
) -> Result<(), Box<dyn Error>> {
    let site_password = get_site_password(
        user_name,
        user_secret,
        site_name,
        counter,
        pw_type.into(),
        purpose.into(),
    )?;

    print_password(&site_password, user_secret, user_name)?;
    Ok(())
}

fn print_password(
    site_password: &SecUtf8,
    user_secret: &SecStr,
    user_name: &str,
) -> Result<(), Box<dyn Error>> {
    let pw_str = site_password.unsecure();
    let identicon = Identicon::new(user_name, user_secret);

    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        println!("{pw_str}");
    } else {
        let identicon = identicon.to_string().color(terminal_color(identicon.color));
        println!("[ {identicon} ]: {pw_str}");
    }

    Ok(())
}

const fn terminal_color(color: IdenticonColor) -> colored::Color {
    match color {
        IdenticonColor::Red => colored::Color::Red,
        IdenticonColor::Green => colored::Color::Green,
        IdenticonColor::Yellow => colored::Color::Yellow,
        IdenticonColor::Blue => colored::Color::Blue,
        IdenticonColor::Magenta => colored::Color::Magenta,
        IdenticonColor::Cyan => colored::Color::Cyan,
        IdenticonColor::White => colored::Color::White,
    }
}

fn read_prompt(editor: &mut DefaultEditor, prompt: &str) -> Result<String, Box<dyn Error>> {
    match editor.readline(prompt) {
        Ok(input) => Ok(input),
        Err(ReadlineError::Interrupted) => Err(Cancelled::Interrupted.into()),
        Err(ReadlineError::Eof) => Err(Cancelled::EndOfInput.into()),
        Err(error) => Err(error.into()),
    }
}

fn read_secret() -> Result<SecStr, Box<dyn Error>> {
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();

    match rpassword::prompt_password_with_config("Enter secret: ", config) {
        Ok(secret) => Ok(SecStr::from(secret)),
        Err(error) => match error.kind() {
            io::ErrorKind::Interrupted => Err(Cancelled::Interrupted.into()),
            io::ErrorKind::UnexpectedEof => Err(Cancelled::EndOfInput.into()),
            _ => Err(error.into()),
        },
    }
}

fn read_secret_stdin() -> io::Result<SecStr> {
    let mut secret = String::new();
    let bytes_read = io::stdin().lock().read_line(&mut secret)?;
    if bytes_read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no secret line was provided on stdin",
        ));
    }
    secret.truncate(secret.trim_end_matches(['\r', '\n']).len());
    Ok(SecStr::from(secret))
}

const CLAP_STYLE: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());

#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum PwType {
    /// 20 characters, symbols
    #[clap(alias = "x")]
    Maximum,
    /// 14 characters, symbols
    #[clap(alias = "l")]
    Long,
    /// 8 characters, symbols
    #[clap(alias = "m")]
    Medium,
    /// 8 characters, no symbols
    #[clap(alias = "b")]
    Basic,
    /// 4 characters, no symbols
    #[clap(alias = "s")]
    Short,
    /// 4 numbers
    #[clap(alias = "i")]
    Pin,
}

impl From<PwType> for spectre_rs_core::PwType {
    fn from(pw_type: PwType) -> Self {
        match pw_type {
            PwType::Maximum => spectre_rs_core::PwType::Maximum,
            PwType::Long => spectre_rs_core::PwType::Long,
            PwType::Medium => spectre_rs_core::PwType::Medium,
            PwType::Basic => spectre_rs_core::PwType::Basic,
            PwType::Short => spectre_rs_core::PwType::Short,
            PwType::Pin => spectre_rs_core::PwType::Pin,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum Scope {
    /// An authentication token such as a password.
    #[clap(name = "auth", alias = "a")]
    Authentication,
    /// An identification token such as a username.
    #[clap(name = "ident", alias = "i")]
    Identification,
    /// A recovery token such as a security answer.
    #[clap(name = "rec", alias = "r")]
    Recovery,
}

impl From<Scope> for spectre_rs_core::Scope {
    fn from(scope: Scope) -> Self {
        match scope {
            Scope::Authentication => spectre_rs_core::Scope::Authentication,
            Scope::Identification => spectre_rs_core::Scope::Identification,
            Scope::Recovery => spectre_rs_core::Scope::Recovery,
        }
    }
}
