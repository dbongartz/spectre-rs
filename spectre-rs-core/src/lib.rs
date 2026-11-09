use hmac::{KeyInit, Mac};
use scrypt::scrypt;
use secstr::{SecStr, SecUtf8};

pub type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Debug)]
pub enum SpectreError {
    InputTooLong(&'static str),
    InvalidScryptParameters,
    InvalidScryptOutputLength,
    InvalidHmacKeyLength,
    InvalidSiteSeedLength,
    UnsupportedPasswordType(PwType),
}

impl std::fmt::Display for SpectreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputTooLong(name) => write!(f, "{name} is too long"),
            Self::InvalidScryptParameters => f.write_str("invalid scrypt parameters"),
            Self::InvalidScryptOutputLength => f.write_str("invalid scrypt output length"),
            Self::InvalidHmacKeyLength => f.write_str("invalid HMAC key length"),
            Self::InvalidSiteSeedLength => f.write_str("invalid site seed length"),
            Self::UnsupportedPasswordType(pw_type) => {
                write!(f, "password type {pw_type:?} is not supported yet")
            }
        }
    }
}

impl std::error::Error for SpectreError {}

pub fn gen_user_key(
    user_name: &str,
    user_secret: &SecStr,
    scope: Scope,
) -> Result<SecStr, SpectreError> {
    let seed = SecStr::new(name_seed(
        user_name,
        Scope::get_template(scope),
        "user name",
    )?);

    const N: u32 = 32768;
    const LOG2_N: u8 = u32::ilog2(N) as u8;
    const R: u32 = 8;
    const P: u32 = 2;
    const KEY_LEN: usize = 64;
    let mut user_key = SecStr::new(vec![0u8; KEY_LEN]);

    scrypt(
        user_secret.unsecure(),
        seed.unsecure(),
        &scrypt::Params::new(LOG2_N, R, P).map_err(|_| SpectreError::InvalidScryptParameters)?,
        user_key.unsecure_mut(),
    )
    .map_err(|_| SpectreError::InvalidScryptOutputLength)?;

    Ok(user_key)
}

pub fn gen_site_seed(
    site_name: &str,
    user_key: &SecStr,
    scope: Scope,
    counter: u32,
) -> Result<SecStr, SpectreError> {
    let mut seed = name_seed(site_name, Scope::get_template(scope), "site name")?;
    seed.extend(counter.to_be_bytes());

    Ok(SecStr::from(
        HmacSha256::new_from_slice(user_key.unsecure())
            .map_err(|_| SpectreError::InvalidHmacKeyLength)?
            .chain_update(seed)
            .finalize()
            .into_bytes()
            .as_slice(),
    ))
}

pub fn gen_site_password(site_seed: &SecStr, pw_type: PwType) -> Result<SecUtf8, SpectreError> {
    let pw_type = PwType::get_template(pw_type)?;

    let site_seed = site_seed.unsecure();
    let template_index = usize::from(
        *site_seed
            .first()
            .ok_or(SpectreError::InvalidSiteSeedLength)?,
    );
    let template = pw_type[template_index % pw_type.len()];
    if site_seed.len() < template.len() + 1 {
        return Err(SpectreError::InvalidSiteSeedLength);
    }

    // Collected straight into its final allocation, so no unprotected copy is left behind.
    let mut password = String::with_capacity(template.len());
    password.extend(
        template
            .chars()
            .zip(site_seed.iter().skip(1))
            .map(|(tchar, &site_key)| {
                let char_class = get_char_class(tchar);
                let character_index = usize::from(site_key) % char_class.len();
                // Character classes are ASCII, so a byte is a whole character.
                char::from(char_class.as_bytes()[character_index])
            }),
    );
    Ok(SecUtf8::from(password))
}

fn name_seed(
    name: &str,
    scope_template: &[u8],
    name_kind: &'static str,
) -> Result<Vec<u8>, SpectreError> {
    let name_length =
        u32::try_from(name.len()).map_err(|_| SpectreError::InputTooLong(name_kind))?;
    let mut seed = Vec::with_capacity(scope_template.len() + 4 + name.len());
    seed.extend(scope_template);
    seed.extend(name_length.to_be_bytes());
    seed.extend(name.bytes());
    Ok(seed)
}

/// Convenience function to generate a site password.
pub fn get_site_password(
    user_name: &str,
    user_secret: &SecStr,
    site_name: &str,
    counter: u32,
    pw_type: PwType,
    purpose: Scope,
) -> Result<SecUtf8, SpectreError> {
    let user_key = gen_user_key(user_name, user_secret, purpose)?;
    let site_seed = gen_site_seed(site_name, &user_key, purpose, counter)?;
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
    /// 9 letter name (not supported yet)
    Name,
    /// 20 letter sentence (not supported yet)
    Phrase,
    /// 512 bit key (not supported yet)
    Key,
    /// saved personal password (not supported yet)
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
    const fn get_template(pw_type: Self) -> Result<&'static [&'static str], SpectreError> {
        match pw_type {
            Self::Maximum => Ok(templates::RESULT_TYPE_MAXIMUM),
            Self::Long => Ok(templates::RESULT_TYPE_LONG),
            Self::Medium => Ok(templates::RESULT_TYPE_MEDIUM),
            Self::Basic => Ok(templates::RESULT_TYPE_BASIC),
            Self::Short => Ok(templates::RESULT_TYPE_SHORT),
            Self::Pin => Ok(templates::RESULT_TYPE_PIN),
            unsupported => Err(SpectreError::UnsupportedPasswordType(unsupported)),
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
    use hmac::{KeyInit, Mac};
    use secstr::SecStr;

    pub const IDENTICON_LEFT_ARMS: &[&str] = &["╔", "╚", "╰", "═"];
    pub const IDENTICON_RIGHT_ARMS: &[&str] = &["╗", "╝", "╯", "═"];
    pub const IDENTICON_BODIES: &[&str] = &["█", "░", "▒", "▓", "☺", "☻"];
    pub const IDENTICON_ACCESSORIES: &[&str] = &[
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    const USER: &str = "Robert Lee Mitchell";
    const SECRET: &str = "banana colored duckling";
    const SITE: &str = "masterpasswordapp.com";

    /// scrypt is deliberately slow, so derive the shared test key once per scope.
    fn user_key(scope: Scope) -> &'static SecStr {
        static AUTH: LazyLock<SecStr> = LazyLock::new(|| derive(Scope::Authentication));
        static IDENT: LazyLock<SecStr> = LazyLock::new(|| derive(Scope::Identification));
        static RECOVERY: LazyLock<SecStr> = LazyLock::new(|| derive(Scope::Recovery));
        fn derive(scope: Scope) -> SecStr {
            gen_user_key(USER, &SecStr::from(SECRET), scope).unwrap()
        }
        match scope {
            Scope::Authentication => &AUTH,
            Scope::Identification => &IDENT,
            Scope::Recovery => &RECOVERY,
        }
    }

    fn password(scope: Scope, counter: u32, pw_type: PwType) -> String {
        let seed = gen_site_seed(SITE, user_key(scope), scope, counter).unwrap();
        gen_site_password(&seed, pw_type)
            .unwrap()
            .unsecure()
            .to_owned()
    }

    /// The reference vectors of the Spectre / Master Password algorithm (v3). These must never
    /// change: a mismatch means every user's passwords would change.
    #[test]
    fn matches_reference_vectors() {
        for (pw_type, expected) in [
            (PwType::Maximum, "W6@692^B1#&@gVdSdLZ@"),
            (PwType::Long, "Jejr5[RepuSosp"),
            (PwType::Medium, "Jej2$Quv"),
            (PwType::Basic, "WAo2xIg6"),
            (PwType::Short, "Jej2"),
            (PwType::Pin, "7662"),
        ] {
            assert_eq!(
                password(Scope::Authentication, 1, pw_type),
                expected,
                "{pw_type:?}"
            );
        }
    }

    #[test]
    fn convenience_function_matches_step_by_step_derivation() {
        let password = get_site_password(
            USER,
            &SecStr::from(SECRET),
            SITE,
            1,
            PwType::Long,
            Scope::Authentication,
        )
        .unwrap();
        assert_eq!(password.unsecure(), "Jejr5[RepuSosp");
    }

    /// Values pinned from this implementation, to catch accidental changes to the counter and
    /// scope handling that the reference vectors above don't exercise.
    #[test]
    fn counters_and_scopes_are_stable() {
        for (scope, counter, expected) in [
            (Scope::Authentication, 0, "Nuqk6*MumeJemv"),
            (Scope::Authentication, 2, "GornJuci5/Zafs"),
            (Scope::Authentication, u32::MAX, "XambHoqo6[Peni"),
            (Scope::Identification, 1, "CoszViroLekz5-"),
            (Scope::Recovery, 1, "Mimb8#RulaRejd"),
        ] {
            assert_eq!(
                password(scope, counter, PwType::Long),
                expected,
                "{scope:?} counter {counter}"
            );
        }
    }

    /// Names are length-prefixed by their UTF-8 byte length, not their character count.
    #[test]
    fn non_ascii_input_is_stable() {
        let password = get_site_password(
            "Ünïcödé 名前",
            &SecStr::from("pässwörd 秘密"),
            "例え.jp",
            1,
            PwType::Maximum,
            Scope::Authentication,
        )
        .unwrap();
        assert_eq!(password.unsecure(), "B^eMe7cjAIHrrYcqyZ8[");
    }

    #[test]
    fn identicon_matches_reference() {
        let identicon = identicon::Identicon::from(&SecStr::from(SECRET), USER);
        assert_eq!(
            [
                identicon.left_arm,
                identicon.body,
                identicon.right_arm,
                identicon.accessory
            ]
            .concat(),
            "╚☻╯⛄"
        );
        assert_eq!(identicon.get_ansi_color(), colored::Color::Green);
    }

    #[test]
    fn unsupported_password_types_are_rejected() {
        let seed = gen_site_seed(
            SITE,
            user_key(Scope::Authentication),
            Scope::Authentication,
            1,
        )
        .unwrap();
        for pw_type in [PwType::Name, PwType::Phrase, PwType::Key, PwType::Personal] {
            assert!(matches!(
                gen_site_password(&seed, pw_type),
                Err(SpectreError::UnsupportedPasswordType(t)) if t == pw_type
            ));
        }
    }

    #[test]
    fn too_short_site_seed_is_rejected() {
        for seed in [&[][..], &[0u8; 4][..]] {
            assert!(matches!(
                gen_site_password(&SecStr::from(seed), PwType::Long),
                Err(SpectreError::InvalidSiteSeedLength)
            ));
        }
    }

    #[test]
    fn every_template_uses_known_character_classes() {
        let known = ['V', 'C', 'v', 'c', 'A', 'a', 'n', 'o', 'x'];
        for templates in [
            templates::RESULT_TYPE_MAXIMUM,
            templates::RESULT_TYPE_LONG,
            templates::RESULT_TYPE_MEDIUM,
            templates::RESULT_TYPE_BASIC,
            templates::RESULT_TYPE_SHORT,
            templates::RESULT_TYPE_PIN,
        ] {
            for template in templates {
                assert!(
                    template.chars().all(|c| known.contains(&c)),
                    "unknown class in {template:?}"
                );
                // The site seed is 32 bytes: one picks the template, the rest the characters.
                assert!(template.len() < 32, "{template:?} is too long for the seed");
            }
        }
    }
}
