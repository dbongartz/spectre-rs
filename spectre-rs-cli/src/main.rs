use std::error::Error;
use std::io;

use clap::{
    Parser,
    builder::{Styles, styling::AnsiColor},
};
use rustyline::{DefaultEditor, error::ReadlineError};
use secstr::SecStr;
use spectre_rs::{get_site_password, identicon::Identicon};

#[derive(Debug, Parser)]
#[clap(version, about, author, long_about = None, styles = CLAP_STYLE)]
struct Args {
    /// The user name to use.
    #[clap(short = 'u', long, env = "SPECTRE_USERNAME")]
    user_name: Option<String>,

    /// Specify the secret to use. INSECURE!
    #[clap(short = 'S', long)]
    secret: Option<SecStr>,

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
    // -------- Argument Parsing & TUI --------

    let args = Args::parse();
    let mut editor = DefaultEditor::new()?;

    let user_name = match args.user_name {
        Some(user_name) => user_name,
        None => match read_prompt(&mut editor, "Enter user name: ")? {
            Some(user_name) => user_name,
            None => return Ok(()),
        },
    };

    u32::try_from(user_name.len()).map_err(|_| "User name too long")?;

    let site_name = match args.site_name {
        Some(site_name) => site_name,
        None => match read_prompt(&mut editor, "Enter site name: ")? {
            Some(site_name) => site_name,
            None => return Ok(()),
        },
    };

    u32::try_from(site_name.len()).map_err(|_| "Site name too long")?;

    let user_secret = match args.secret {
        Some(secret) => secret,
        None => match read_secret()? {
            Some(secret) => secret,
            None => return Ok(()),
        },
    };

    let counter = args.counter;

    // -------- Key Derivation --------

    let site_password = get_site_password(
        &user_name,
        &user_secret,
        &site_name,
        counter,
        args.pw_type.into(),
        args.purpose.into(),
    );

    let identicon = Identicon::from(&user_secret, &user_name);

    // ------- Print Identicon and Password --------

    let pw_str = std::str::from_utf8(site_password.unsecure())?;

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
    /// 9 letter name
    #[clap(alias = "n")]
    Name,
    /// 20 letter sentence
    #[clap(alias = "p")]
    Phrase,
    /// 512 bit key
    #[clap(alias = "K")]
    Key,
    /// saved personal password
    #[clap(alias = "P")]
    Personal,
}

impl From<PwType> for spectre_rs::PwType {
    fn from(pw_type: PwType) -> Self {
        match pw_type {
            PwType::Maximum => spectre_rs::PwType::Maximum,
            PwType::Long => spectre_rs::PwType::Long,
            PwType::Medium => spectre_rs::PwType::Medium,
            PwType::Basic => spectre_rs::PwType::Basic,
            PwType::Short => spectre_rs::PwType::Short,
            PwType::Pin => spectre_rs::PwType::Pin,
            PwType::Name => spectre_rs::PwType::Name,
            PwType::Phrase => spectre_rs::PwType::Phrase,
            PwType::Key => spectre_rs::PwType::Key,
            PwType::Personal => spectre_rs::PwType::Personal,
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

impl From<Scope> for spectre_rs::Scope {
    fn from(scope: Scope) -> Self {
        match scope {
            Scope::Authentication => spectre_rs::Scope::Authentication,
            Scope::Identification => spectre_rs::Scope::Identification,
            Scope::Recovery => spectre_rs::Scope::Recovery,
        }
    }
}
