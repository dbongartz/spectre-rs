use byteorder::{BigEndian, WriteBytesExt};
use hmac::Mac;
use scrypt::scrypt;
use secstr::SecStr;

pub type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub fn gen_user_key(user_name: &str, user_secret: &SecStr, scope: Scope) -> SecStr {
    let seed = {
        let mut seed = Vec::new();
        seed.extend(Scope::get_template(scope));
        seed.write_u32::<BigEndian>(user_name.len() as u32).unwrap();
        seed.extend(user_name.bytes());
        SecStr::new(seed)
    };

    let mut user_key = SecStr::new(vec![0u8; 64]);

    const N: u32 = 32768;
    const LOG2_N: u8 = u32::ilog2(N) as u8;
    const R: u32 = 8;
    const P: u32 = 2;
    const KEY_LEN: usize = 64;

    scrypt(
        user_secret.unsecure(),
        seed.unsecure(),
        &scrypt::Params::new(LOG2_N, R, P, KEY_LEN).unwrap(),
        user_key.unsecure_mut(),
    )
    .unwrap();

    user_key
}

pub fn gen_site_seed(site_name: &str, user_key: &SecStr, scope: Scope, counter: u32) -> SecStr {
    let mut seed = Vec::new();
    seed.extend(Scope::get_template(scope));
    seed.write_u32::<BigEndian>(site_name.len() as u32).unwrap();
    seed.extend(site_name.bytes());
    seed.write_u32::<BigEndian>(counter).unwrap();

    SecStr::from(
        HmacSha256::new_from_slice(user_key.unsecure())
            .unwrap()
            .chain_update(seed)
            .finalize()
            .into_bytes()
            .as_slice(),
    )
}

pub fn gen_site_password(site_seed: &SecStr, pw_type: PwType) -> SecStr {
    let pw_type = PwType::get_template(pw_type);

    let mut site_seed_iter = site_seed.unsecure().iter().map(|&b| usize::from(b));

    let template = pw_type[site_seed_iter.next().unwrap() % pw_type.len()];

    SecStr::from(
        template
            .chars()
            .zip(site_seed_iter)
            .map(|(tchar, site_key)| {
                let char_class = get_char_class(tchar);
                char_class.chars().nth(site_key % char_class.len()).unwrap() as u8
            })
            .collect::<Vec<_>>(),
    )
}

/// Convenience function to generate a site password.
pub fn get_site_password(
    user_name: &str,
    user_secret: &SecStr,
    site_name: &str,
    counter: u32,
    pw_type: PwType,
    purpose: Scope,
) -> SecStr {
    let user_key = gen_user_key(user_name, user_secret, purpose);
    let site_seed = gen_site_seed(site_name, &user_key, purpose, counter);
    gen_site_password(&site_seed, pw_type)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PwType {
    /// 20 characters, symbols
    Maximum,
    /// 14 characters, symbols
    Long,
    /// 8 characters, symbols
    Medium,
    /// 8 characters, no symbols
    Basic,
    /// 4 characters, no symbols
    Short,
    /// 4 numbers
    Pin,
    /// 9 letter name
    Name,
    /// 20 letter sentence
    Phrase,
    /// 512 bit key
    Key,
    /// saved personal password
    Personal,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scope {
    /// An authentication token such as a password.
    Authentication,
    /// An identification token such as a username.
    Identification,
    /// A recovery token such as a security answer.
    Recovery,
}

impl Scope {
    const fn get_template(scope: Self) -> &'static [u8] {
        match scope {
            Self::Authentication => templates::SCOPE_AUTHENTICATION,
            Self::Identification => templates::SCOPE_IDENTIFICATION,
            Self::Recovery => templates::SCOPE_RECOVERY,
        }
    }
}

const fn get_char_class(template: char) -> &'static str {
    match template {
        'V' => templates::V,
        'C' => templates::C,
        'v' => templates::v,
        'c' => templates::c,
        'A' => templates::A,
        'a' => templates::a,
        'n' => templates::n,
        'o' => templates::o,
        _ => templates::ALL,
    }
}

impl PwType {
    const fn get_template(pw_type: Self) -> &'static [&'static str] {
        match pw_type {
            Self::Maximum => templates::RESULT_TYPE_MAXIMUM,
            Self::Long => templates::RESULT_TYPE_LONG,
            Self::Medium => templates::RESULT_TYPE_MEDIUM,
            Self::Basic => templates::RESULT_TYPE_BASIC,
            Self::Short => templates::RESULT_TYPE_SHORT,
            Self::Pin => templates::RESULT_TYPE_PIN,
            Self::Name | Self::Phrase | Self::Key | Self::Personal => todo!(),
        }
    }
}

#[allow(non_upper_case_globals)]
mod templates {
    pub const V: &str = "AEIOU";
    pub const C: &str = "BCDFGHJKLMNPQRSTVWXYZ";
    pub const v: &str = "aeiou";
    pub const c: &str = "bcdfghjklmnpqrstvwxyz";
    pub const A: &str = "AEIOUBCDFGHJKLMNPQRSTVWXYZ";
    pub const a: &str = "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
    pub const n: &str = "0123456789";
    pub const o: &str = "@&%?,=[]_:-+*$#!'^~;()/.";
    pub const ALL: &str =
        "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";

    pub const RESULT_TYPE_MAXIMUM: &[&str] = &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"];
    pub const RESULT_TYPE_LONG: &[&str] = &[
        "CvcvnoCvcvCvcv",
        "CvcvCvcvnoCvcv",
        "CvcvCvcvCvcvno",
        "CvccnoCvcvCvcv",
        "CvccCvcvnoCvcv",
        "CvccCvcvCvcvno",
        "CvcvnoCvccCvcv",
        "CvcvCvccnoCvcv",
        "CvcvCvccCvcvno",
        "CvcvnoCvcvCvcc",
        "CvcvCvcvnoCvcc",
        "CvcvCvcvCvccno",
        "CvccnoCvccCvcv",
        "CvccCvccnoCvcv",
        "CvccCvccCvcvno",
        "CvcvnoCvccCvcc",
        "CvcvCvccnoCvcc",
        "CvcvCvccCvccno",
        "CvccnoCvcvCvcc",
        "CvccCvcvnoCvcc",
        "CvccCvcvCvccno",
    ];
    pub const RESULT_TYPE_MEDIUM: &[&str] = &["CvcnoCvc", "CvcCvcno"];
    pub const RESULT_TYPE_SHORT: &[&str] = &["Cvcn"];
    pub const RESULT_TYPE_BASIC: &[&str] = &["aaanaaan", "aannaaan", "aaannaaa"];
    pub const RESULT_TYPE_PIN: &[&str] = &["nnnn"];

    pub const SCOPE_AUTHENTICATION: &[u8] = b"com.lyndir.masterpassword";
    pub const SCOPE_IDENTIFICATION: &[u8] = b"com.lyndir.masterpassword.login";
    pub const SCOPE_RECOVERY: &[u8] = b"com.lyndir.masterpassword.answer";
}

pub mod identicon {
    use std::fmt::Display;

    use crate::HmacSha256;
    use colored::{Color, Colorize};
    use hmac::Mac;
    use secstr::SecStr;

    const IDENTICON_LEFT_ARMS: &[&str] = &["╔", "╚", "╰", "═"];
    const IDENTICON_RIGHT_ARMS: &[&str] = &["╗", "╝", "╯", "═"];
    const IDENTICON_BODIES: &[&str] = &["█", "░", "▒", "▓", "☺", "☻"];
    const IDENTICON_ACCESSORIES: &[&str] = &[
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘",
        "☢", "☣", "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙",
        "♚", "♛", "♜", "♝", "♞", "♟", "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎",
        "✄", "✆", "✈", "✉", "✌",
    ];

    #[derive(Debug)]
    pub struct Identicon {
        pub left_arm: &'static str,
        pub right_arm: &'static str,
        pub body: &'static str,
        pub accessory: &'static str,
        // Must be <= 7
        color: u8,
    }

    impl Identicon {
        pub fn from(user_secret: &SecStr, name: &str) -> Self {
            let seed = HmacSha256::new_from_slice(user_secret.unsecure())
                .unwrap()
                .chain_update(name.as_bytes())
                .finalize()
                .into_bytes();

            Self {
                left_arm: IDENTICON_LEFT_ARMS[seed[0] as usize % IDENTICON_LEFT_ARMS.len()],
                body: IDENTICON_BODIES[seed[1] as usize % IDENTICON_BODIES.len()],
                right_arm: IDENTICON_RIGHT_ARMS[seed[2] as usize % IDENTICON_RIGHT_ARMS.len()],
                accessory: IDENTICON_ACCESSORIES[seed[3] as usize % IDENTICON_ACCESSORIES.len()],
                color: seed[4] % 7 + 1,
            }
        }

        pub fn get_ansi_color(&self) -> Color {
            match self.color {
                0 => Color::Black,
                1 => Color::Red,
                2 => Color::Green,
                3 => Color::Yellow,
                4 => Color::Blue,
                5 => Color::Magenta,
                6 => Color::Cyan,
                7 => Color::White,
                // <= 7 guaranteed by constructor
                _ => unreachable!(),
            }
        }
    }

    impl Display for Identicon {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let color = self.get_ansi_color();
            write!(
                f,
                "{}{}{}{}",
                self.left_arm.color(color),
                self.body.color(color),
                self.right_arm.color(color),
                self.accessory.color(color)
            )
        }
    }
}
