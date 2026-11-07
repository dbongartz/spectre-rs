use std::error::Error;
use std::io::{self, BufRead};

use clap::{
    Parser,
    builder::{Styles, styling::AnsiColor},
};
use rustyline::{DefaultEditor, error::ReadlineError};
use secstr::SecStr;
use spectre_rs_core::{get_site_password, identicon::Identicon};

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

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
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
    let mut editor = DefaultEditor::new()?;

    let Some(user_name) = read_name(&mut editor, provided_user_name, "Enter user name: ", "User")?
    else {
        return Ok(());
    };
    let Some(site_name) = read_name(&mut editor, provided_site_name, "Enter site name: ", "Site")?
    else {
        return Ok(());
    };
    let Some(user_secret) = read_user_secret(secret, secret_stdin)? else {
        return Ok(());
    };

    generate_and_print(
        &user_name,
        &user_secret,
        &site_name,
        counter,
        pw_type,
        purpose,
    )
}

fn read_name(
    editor: &mut DefaultEditor,
    provided_name: Option<String>,
    prompt: &str,
    name_kind: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    let name = match provided_name {
        Some(name) => name,
        None => match read_prompt(editor, prompt)? {
            Some(name) => name,
            None => return Ok(None),
        },
    }
    .trim()
    .to_owned();

    if name.is_empty() {
        return Err(format!("{name_kind} name cannot be empty").into());
    }

    u32::try_from(name.len()).map_err(|_| format!("{name_kind} name too long"))?;
    Ok(Some(name))
}

fn read_user_secret(secret: Option<SecStr>, secret_stdin: bool) -> io::Result<Option<SecStr>> {
    match (secret, secret_stdin) {
        (Some(secret), _) => Ok(Some(secret)),
        (None, true) => read_secret_stdin().map(Some),
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
    site_password: &SecStr,
    user_secret: &SecStr,
    user_name: &str,
) -> Result<(), Box<dyn Error>> {
    let pw_str = std::str::from_utf8(site_password.unsecure())?;
    let identicon = Identicon::from(user_secret, user_name);

    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        println!("{pw_str}");
    } else {
        println!("[ {identicon} ]: {pw_str}");
    }

    Ok(())
}

fn read_prompt(editor: &mut DefaultEditor, prompt: &str) -> Result<Option<String>, ReadlineError> {
    match editor.readline(prompt) {
        Ok(input) => Ok(Some(input.trim().to_string())),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_secret() -> io::Result<Option<SecStr>> {
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();

    match rpassword::prompt_password_with_config("Enter secret: ", config) {
        Ok(secret) => Ok(Some(SecStr::from(secret))),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
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

// Use with "help_template = HELP_TEMPLATE"
// const HELP_TEMPLATE: &str = "\
// {before-help}{name} {version}

// {author-with-newline}
// {about-with-newline}
// {usage-heading} {usage}

// {all-args}{after-help}
// ";

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
