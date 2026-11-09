//! The Spectre (formerly Master Password) algorithm: site passwords derived from a user name, a
//! secret and a site name, so nothing ever has to be stored.

use hmac::{KeyInit, Mac};
use secstr::{SecStr, SecUtf8};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectreError {
    /// A name is longer than the 4 GiB its length prefix can describe; holds which name.
    InputTooLong(&'static str),
    /// The site seed is too short for the password template it selects.
    InvalidSiteSeedLength,
}

impl std::fmt::Display for SpectreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputTooLong(name) => write!(f, "{name} is too long"),
            Self::InvalidSiteSeedLength => f.write_str("invalid site seed length"),
        }
    }
}

impl std::error::Error for SpectreError {}

/// Derives the user key from the user name and secret. This is the slow step (scrypt), so
/// derive it once and reuse it for every site.
///
/// # Errors
///
/// [`SpectreError::InputTooLong`] if the user name is 4 GiB or longer.
///
/// # Panics
///
/// Never: the scrypt parameters and key length are fixed, valid constants.
pub fn gen_user_key(
    user_name: &str,
    user_secret: &SecStr,
    scope: Scope,
) -> Result<SecStr, SpectreError> {
    const LOG2_N: u8 = 15;
    const R: u32 = 8;
    const P: u32 = 2;
    const KEY_LEN: usize = 64;

    let salt = name_seed(user_name, scope.template(), "user name")?;
    let params = scrypt::Params::new(LOG2_N, R, P).expect("the scrypt parameters are valid");
    let mut user_key = SecStr::new(vec![0u8; KEY_LEN]);
    scrypt::scrypt(
        user_secret.unsecure(),
        &salt,
        &params,
        user_key.unsecure_mut(),
    )
    .expect("the key length is valid for scrypt");

    Ok(user_key)
}

/// Derives the seed for one site from the user key.
///
/// # Errors
///
/// [`SpectreError::InputTooLong`] if the site name is 4 GiB or longer.
pub fn gen_site_seed(
    site_name: &str,
    user_key: &SecStr,
    scope: Scope,
    counter: u32,
) -> Result<SecStr, SpectreError> {
    let mut message = name_seed(site_name, scope.template(), "site name")?;
    message.extend(counter.to_be_bytes());

    let seed = hmac_sha256(user_key.unsecure(), &message);
    Ok(SecStr::from(seed.as_slice()))
}

/// Turns a site seed into a password of the given type.
///
/// # Errors
///
/// [`SpectreError::InvalidSiteSeedLength`] if `site_seed` is shorter than the template it selects.
/// Seeds from [`gen_site_seed`] are always long enough.
pub fn gen_site_password(site_seed: &SecStr, pw_type: PwType) -> Result<SecUtf8, SpectreError> {
    let templates = pw_type.templates();

    let site_seed = site_seed.unsecure();
    let (&template_byte, character_bytes) = site_seed
        .split_first()
        .ok_or(SpectreError::InvalidSiteSeedLength)?;
    let template = templates[usize::from(template_byte) % templates.len()];
    if character_bytes.len() < template.len() {
        return Err(SpectreError::InvalidSiteSeedLength);
    }

    // Collected straight into its final allocation, so no unprotected copy is left behind.
    let mut password = String::with_capacity(template.len());
    password.extend(template.chars().zip(character_bytes).map(|(class, &byte)| {
        let characters = char_class(class).as_bytes();
        // Character classes are ASCII, so a byte is a whole character.
        char::from(characters[usize::from(byte) % characters.len()])
    }));
    Ok(SecUtf8::from(password))
}

/// Derives a site password in one go. To derive several, call [`gen_user_key`] once and
/// [`gen_site_seed`] and [`gen_site_password`] for each, since the user key is slow to derive.
///
/// # Errors
///
/// [`SpectreError::InputTooLong`] if the user or site name is 4 GiB or longer.
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

/// The scope's identifier, followed by the name, prefixed by its length in bytes.
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

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    HmacSha256::new_from_slice(key)
        .expect("HMAC accepts keys of any length")
        .chain_update(message)
        .finalize()
        .into_bytes()
        .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl PwType {
    /// The templates this type picks from; each character names a character class.
    const fn templates(self) -> &'static [&'static str] {
        match self {
            Self::Maximum => templates::RESULT_TYPE_MAXIMUM,
            Self::Long => templates::RESULT_TYPE_LONG,
            Self::Medium => templates::RESULT_TYPE_MEDIUM,
            Self::Basic => templates::RESULT_TYPE_BASIC,
            Self::Short => templates::RESULT_TYPE_SHORT,
            Self::Pin => templates::RESULT_TYPE_PIN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// An authentication token such as a password.
    Authentication,
    /// An identification token such as a username.
    Identification,
    /// A recovery token such as a security answer.
    Recovery,
}

impl Scope {
    const fn template(self) -> &'static [u8] {
        match self {
            Self::Authentication => templates::SCOPE_AUTHENTICATION,
            Self::Identification => templates::SCOPE_IDENTIFICATION,
            Self::Recovery => templates::SCOPE_RECOVERY,
        }
    }
}

/// The characters a template character stands for.
///
/// # Panics
///
/// On a character no template uses; a test checks every template.
const fn char_class(template: char) -> &'static str {
    match template {
        'V' => templates::V,
        'C' => templates::C,
        'v' => templates::v,
        'c' => templates::c,
        'A' => templates::A,
        'a' => templates::a,
        'n' => templates::n,
        'o' => templates::o,
        'x' => templates::x,
        _ => panic!("unknown character class in a password template"),
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
    pub const x: &str = "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";

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
    //! A small picture derived from the user name and secret, so a typo in the secret is noticed
    //! before it produces wrong passwords.

    use std::fmt;

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

    /// The identicon's color: one of the seven non-black terminal colors.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IdenticonColor {
        Red,
        Green,
        Yellow,
        Blue,
        Magenta,
        Cyan,
        White,
    }

    impl IdenticonColor {
        const ALL: [Self; 7] = [
            Self::Red,
            Self::Green,
            Self::Yellow,
            Self::Blue,
            Self::Magenta,
            Self::Cyan,
            Self::White,
        ];
    }

    /// Displays as its four glyphs, without color.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Identicon {
        pub left_arm: &'static str,
        pub body: &'static str,
        pub right_arm: &'static str,
        pub accessory: &'static str,
        pub color: IdenticonColor,
    }

    impl Identicon {
        #[must_use]
        pub fn new(user_name: &str, user_secret: &SecStr) -> Self {
            let seed = super::hmac_sha256(user_secret.unsecure(), user_name.as_bytes());
            let pick =
                |options: &[&'static str], byte: u8| options[usize::from(byte) % options.len()];

            Self {
                left_arm: pick(IDENTICON_LEFT_ARMS, seed[0]),
                body: pick(IDENTICON_BODIES, seed[1]),
                right_arm: pick(IDENTICON_RIGHT_ARMS, seed[2]),
                accessory: pick(IDENTICON_ACCESSORIES, seed[3]),
                color: IdenticonColor::ALL[usize::from(seed[4]) % IdenticonColor::ALL.len()],
            }
        }
    }

    impl fmt::Display for Identicon {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}{}{}{}",
                self.left_arm, self.body, self.right_arm, self.accessory
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
    const ALL_PW_TYPES: [PwType; 6] = [
        PwType::Maximum,
        PwType::Long,
        PwType::Medium,
        PwType::Basic,
        PwType::Short,
        PwType::Pin,
    ];

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
        let expected_passwords = [
            (PwType::Maximum, "W6@692^B1#&@gVdSdLZ@"),
            (PwType::Long, "Jejr5[RepuSosp"),
            (PwType::Medium, "Jej2$Quv"),
            (PwType::Basic, "WAo2xIg6"),
            (PwType::Short, "Jej2"),
            (PwType::Pin, "7662"),
        ];
        // Every type is covered.
        assert_eq!(expected_passwords.map(|(pw_type, _)| pw_type), ALL_PW_TYPES);
        for (pw_type, expected) in expected_passwords {
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
        let identicon = identicon::Identicon::new(USER, &SecStr::from(SECRET));
        assert_eq!(identicon.to_string(), "╚☻╯⛄");
        assert_eq!(identicon.color, identicon::IdenticonColor::Green);
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
        for pw_type in ALL_PW_TYPES {
            for template in pw_type.templates() {
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
