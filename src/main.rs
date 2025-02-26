use std::io::Write;

use clap::{
    builder::{styling::AnsiColor, Styles},
    Parser,
};
use colored::{Color, Colorize};
use secstr::SecStr;
use spectre_rs::{gen_site_password, gen_site_seed, gen_user_key, identicon::Identicon};

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
    #[clap(short = 't', long, value_enum, default_value_t=spectre_rs::PwType::Long)]
    pw_type: spectre_rs::PwType,

    /// The value of the counter
    #[clap(short = 'c', long, default_value_t = 1)]
    counter: u32,

    #[clap(short = 'p', long, value_enum, default_value_t = spectre_rs::Scope::Authentication)]
    purpose: spectre_rs::Scope,

    /// The site name to use.
    site_name: Option<String>,
}

fn main() {
    // -------- Argument Parsing & TUI --------

    let args = Args::parse();

    let user_name = args.user_name.unwrap_or_else(|| {
        print!("Enter user name: ");
        std::io::stdout().flush().unwrap();
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        buf.trim().to_string()
    });

    match u32::try_from(user_name.len()) {
        Ok(len) => len,
        Err(_) => {
            eprintln!("User name too long");
            std::process::exit(1);
        }
    };

    let site_name = args.site_name.unwrap_or_else(|| {
        print!("Enter site name: ");
        std::io::stdout().flush().unwrap();
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        buf.trim().to_string()
    });

    match u32::try_from(site_name.len()) {
        Ok(len) => len,
        Err(_) => {
            eprintln!("User name too long");
            std::process::exit(1);
        }
    };

    let user_secret = args
        .secret
        .unwrap_or_else(|| SecStr::from(rpassword::prompt_password("Enter secret: ").unwrap()));

    let counter = args.counter;

    // -------- Key Derivation --------

    let user_key = gen_user_key(&user_name, &user_secret, args.purpose);
    let site_key = gen_site_seed(&site_name, &user_key, args.purpose, counter);
    let password = gen_site_password(&site_key, args.pw_type);
    let identicon = Identicon::new(&user_secret, &user_name);

    // ------- Print Identicon and Password --------

    println!(
        "[ {}{}{}{} ]: {}",
        identicon
            .left_arm
            .color(get_ansi_color_from_number(identicon.color)),
        identicon
            .body
            .color(get_ansi_color_from_number(identicon.color)),
        identicon
            .right_arm
            .color(get_ansi_color_from_number(identicon.color)),
        identicon
            .accessory
            .color(get_ansi_color_from_number(identicon.color)),
        std::str::from_utf8(password.unsecure()).unwrap()
    );
}

const fn get_ansi_color_from_number(number: u8) -> Color {
    match number {
        0 => Color::Black,
        1 => Color::Red,
        2 => Color::Green,
        3 => Color::Yellow,
        4 => Color::Blue,
        5 => Color::Magenta,
        6 => Color::Cyan,
        7 => Color::White,
        _ => Color::White,
    }
}
