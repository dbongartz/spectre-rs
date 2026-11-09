//! What the app knows and how it reacts to input, kept free of egui so it can be tested.
//!
//! The user key is derived on a worker thread (see [`crate::derive`]), so the model hands out
//! [`DeriveRequest`]s and takes the results back through [`Model::key_derived`]. Each request
//! carries a revision, and results for anything but the latest one are dropped.

use std::time::Instant;

use secstr::{SecStr, SecUtf8};
use spectre_rs_core::{PwType, Scope, SpectreError, identicon::Identicon};
use zeroize::Zeroize;

use crate::derive::{DeriveRequest, DerivedKey};

/// Room for the secret before the field has to reallocate, leaving an unwiped copy behind.
const SECRET_CAPACITY: usize = 256;

/// What the user typed or picked.
pub struct Input {
    pub user_name: String,
    pub user_secret: String,
    pub site_name: String,
    pub pw_type: PwType,
    pub counter: u32,
}

impl Default for Input {
    fn default() -> Self {
        Self {
            user_name: String::new(),
            user_secret: String::with_capacity(SECRET_CAPACITY),
            site_name: String::new(),
            pw_type: PwType::Medium,
            counter: 1,
        }
    }
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("user_name", &self.user_name)
            .field("user_secret", &"***SECRET***")
            .field("site_name", &self.site_name)
            .field("pw_type", &self.pw_type)
            .field("counter", &self.counter)
            .finish()
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.user_secret.zeroize();
    }
}

/// Where the user key stands.
enum KeyState {
    /// The user name or secret is empty, so there is no key.
    Missing,
    /// A key for the current credentials is being derived.
    Deriving {
        /// When the user started changing the credentials; see [`Model::deriving_since`].
        since: Instant,
        /// A copy was asked for meanwhile; [`Model::key_derived`] makes it once the key is in.
        copy_pending: bool,
    },
    Ready(SecStr),
    Failed,
}

pub struct Model {
    pub input: Input,
    key: KeyState,
    /// Revision of the latest derive request; results for older ones are dropped.
    revision: u64,
    /// The password for the current input. While deriving, this is still the previous one,
    /// which is shown (dimmed after a moment) but never copied.
    site_password: Option<SecUtf8>,
    identicon: Option<Identicon>,
}

impl Model {
    pub fn new(input: Input) -> Self {
        Self {
            input,
            key: KeyState::Missing,
            revision: 0,
            site_password: None,
            identicon: None,
        }
    }

    pub fn site_password(&self) -> Option<&SecUtf8> {
        self.site_password.as_ref()
    }

    pub fn identicon(&self) -> Option<&Identicon> {
        self.identicon.as_ref()
    }

    /// When the current derivation started, if one is running. Consecutive edits keep the
    /// original time, so a stale password dims once the user has been typing for a moment.
    pub fn deriving_since(&self) -> Option<Instant> {
        match self.key {
            KeyState::Deriving { since, .. } => Some(since),
            _ => None,
        }
    }

    /// The user name or secret changed. Returns the request for the worker, unless one of them
    /// is empty, in which case there is nothing to derive.
    pub fn credentials_changed(&mut self, now: Instant) -> Option<DeriveRequest> {
        // Invalidates any result still in flight, including when nothing new is requested.
        self.revision = self.revision.wrapping_add(1);

        let input = &self.input;
        if input.user_name.is_empty() || input.user_secret.is_empty() {
            self.key = KeyState::Missing;
            self.site_password = None;
            self.identicon = None;
            return None;
        }

        let user_secret = SecStr::from(input.user_secret.as_str());
        self.identicon = Some(Identicon::new(&input.user_name, &user_secret));
        // The previous password stays up until the new key is in, so typing doesn't flicker.
        let since = self.deriving_since().unwrap_or(now);
        self.key = KeyState::Deriving {
            since,
            copy_pending: false,
        };
        Some(DeriveRequest {
            revision: self.revision,
            user_name: input.user_name.clone(),
            user_secret,
        })
    }

    /// The site name, password type or counter changed.
    pub fn site_changed(&mut self) {
        match &mut self.key {
            // A copy asked for before the change would copy the wrong password.
            KeyState::Deriving { copy_pending, .. } => *copy_pending = false,
            // A pending key recomputes the password once it is in.
            _ => self.update_site_password(),
        }
    }

    /// Takes a result from the worker. Returns whether a copy is now due, because one was asked
    /// for while the key was being derived.
    pub fn key_derived(&mut self, derived: DerivedKey) -> bool {
        if derived.revision != self.revision {
            return false;
        }
        let copy_pending = matches!(
            self.key,
            KeyState::Deriving {
                copy_pending: true,
                ..
            }
        );
        self.key = match derived.user_key {
            Ok(user_key) => KeyState::Ready(user_key),
            Err(error) => {
                log::error!("Failed to derive user key: {error}");
                KeyState::Failed
            }
        };
        self.update_site_password();
        copy_pending
    }

    /// The user asked to copy the password. Returns it if it is current; while deriving, the
    /// copy is deferred to [`Model::key_derived`] instead.
    pub fn request_copy(&mut self) -> Option<&SecUtf8> {
        if let KeyState::Deriving { copy_pending, .. } = &mut self.key {
            *copy_pending = true;
            return None;
        }
        self.site_password.as_ref()
    }

    fn update_site_password(&mut self) {
        self.site_password = match &self.key {
            KeyState::Ready(user_key) if !self.input.site_name.is_empty() => {
                site_password(user_key, &self.input)
                    .inspect_err(|error| log::error!("Failed to generate site password: {error}"))
                    .ok()
            }
            _ => None,
        };
    }
}

fn site_password(user_key: &SecStr, input: &Input) -> Result<SecUtf8, SpectreError> {
    let seed = spectre_rs_core::gen_site_seed(
        &input.site_name,
        user_key,
        Scope::Authentication,
        input.counter,
    )?;
    spectre_rs_core::gen_site_password(&seed, input.pw_type)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const USER: &str = "Robert Lee Mitchell";
    const SECRET: &str = "banana colored duckling";
    const SITE: &str = "masterpasswordapp.com";

    /// Stands in for a derived key: the model only passes it on, so any 64 bytes will do.
    fn fake_key(byte: u8) -> SecStr {
        SecStr::new(vec![byte; 64])
    }

    fn expected_password(key: &SecStr, input: &Input) -> String {
        site_password(key, input).unwrap().unsecure().to_owned()
    }

    fn password(model: &Model) -> Option<&str> {
        model.site_password().map(SecUtf8::unsecure)
    }

    /// `Input` implements `Drop`, so struct update syntax can't build one.
    fn input(user_name: &str, user_secret: &str, site_name: &str) -> Input {
        let mut input = Input::default();
        input.user_name = user_name.to_owned();
        input.user_secret = user_secret.to_owned();
        input.site_name = site_name.to_owned();
        input
    }

    fn filled_model() -> Model {
        Model::new(input(USER, SECRET, SITE))
    }

    /// Changes the credentials and completes the derivation with `key`.
    fn derive(model: &mut Model, key: &SecStr) {
        let request = model.credentials_changed(Instant::now()).unwrap();
        model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Ok(key.clone()),
        });
    }

    #[test]
    fn empty_credentials_request_nothing() {
        let mut model = Model::new(input(USER, "", SITE));
        assert!(model.credentials_changed(Instant::now()).is_none());
        assert!(model.site_password().is_none());
        assert!(model.identicon().is_none());
        assert!(model.deriving_since().is_none());
    }

    #[test]
    fn derived_key_produces_the_password() {
        let mut model = filled_model();
        let request = model.credentials_changed(Instant::now()).unwrap();
        assert_eq!(request.user_name, USER);
        assert_eq!(request.user_secret.unsecure(), SECRET.as_bytes());
        assert!(model.deriving_since().is_some());
        assert!(model.site_password().is_none());
        assert_eq!(model.identicon().unwrap().to_string(), "╚☻╯⛄");

        let key = fake_key(1);
        model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Ok(key.clone()),
        });
        assert!(model.deriving_since().is_none());
        assert_eq!(
            password(&model),
            Some(expected_password(&key, &model.input).as_str())
        );
    }

    #[test]
    fn real_key_matches_the_reference_vector() {
        let mut model = filled_model();
        let request = model.credentials_changed(Instant::now()).unwrap();
        let user_key =
            spectre_rs_core::gen_user_key(USER, &request.user_secret, Scope::Authentication);
        model.key_derived(DerivedKey {
            revision: request.revision,
            user_key,
        });
        // Medium is the GUI's default type.
        assert_eq!(password(&model), Some("Jej2$Quv"));
    }

    #[test]
    fn outdated_results_are_dropped() {
        let mut model = filled_model();
        let old = model.credentials_changed(Instant::now()).unwrap();
        model.input.user_secret.push('!');
        let new = model.credentials_changed(Instant::now()).unwrap();

        model.key_derived(DerivedKey {
            revision: old.revision,
            user_key: Ok(fake_key(1)),
        });
        assert!(
            model.deriving_since().is_some(),
            "still waiting for the new key"
        );
        assert!(model.site_password().is_none());

        let key = fake_key(2);
        model.key_derived(DerivedKey {
            revision: new.revision,
            user_key: Ok(key.clone()),
        });
        assert_eq!(
            password(&model),
            Some(expected_password(&key, &model.input).as_str())
        );
    }

    #[test]
    fn consecutive_edits_keep_the_start_time() {
        let mut model = filled_model();
        let start = Instant::now();
        model.credentials_changed(start);
        model.credentials_changed(start + Duration::from_secs(1));
        assert_eq!(model.deriving_since(), Some(start));
    }

    #[test]
    fn previous_password_stays_while_deriving() {
        let mut model = filled_model();
        derive(&mut model, &fake_key(1));
        let previous = password(&model).unwrap().to_owned();

        model.input.user_secret.push('!');
        model.credentials_changed(Instant::now());
        assert_eq!(password(&model), Some(previous.as_str()));
    }

    #[test]
    fn site_changes_apply_at_once_when_the_key_is_ready() {
        let mut model = filled_model();
        let key = fake_key(1);
        derive(&mut model, &key);

        for change in [
            |input: &mut Input| input.site_name.push_str(".org"),
            |input: &mut Input| input.pw_type = PwType::Maximum,
            |input: &mut Input| input.counter = 7,
        ] {
            let before = password(&model).unwrap().to_owned();
            change(&mut model.input);
            model.site_changed();
            let after = password(&model).unwrap();
            assert_ne!(after, before);
            assert_eq!(after, expected_password(&key, &model.input));
        }
    }

    #[test]
    fn site_changes_while_deriving_apply_with_the_new_key() {
        let mut model = filled_model();
        let request = model.credentials_changed(Instant::now()).unwrap();
        model.input.site_name = "example.com".to_owned();
        model.site_changed();
        assert!(model.site_password().is_none());

        let key = fake_key(1);
        model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Ok(key.clone()),
        });
        assert_eq!(
            password(&model),
            Some(expected_password(&key, &model.input).as_str())
        );
    }

    #[test]
    fn empty_site_has_no_password() {
        let mut model = filled_model();
        model.input.site_name.clear();
        derive(&mut model, &fake_key(1));
        assert!(model.site_password().is_none());
    }

    #[test]
    fn clearing_the_secret_drops_the_password_at_once() {
        let mut model = filled_model();
        derive(&mut model, &fake_key(1));
        let in_flight = {
            model.input.user_secret.push('!');
            model.credentials_changed(Instant::now()).unwrap()
        };

        model.input.user_secret.clear();
        assert!(model.credentials_changed(Instant::now()).is_none());
        assert!(model.site_password().is_none());
        assert!(model.identicon().is_none());

        // The key for the secret as it was before clearing must not bring the password back.
        model.key_derived(DerivedKey {
            revision: in_flight.revision,
            user_key: Ok(fake_key(2)),
        });
        assert!(model.site_password().is_none());
    }

    #[test]
    fn copy_waits_for_the_key() {
        let mut model = filled_model();
        let request = model.credentials_changed(Instant::now()).unwrap();
        assert!(model.request_copy().is_none());

        let copy_due = model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Ok(fake_key(1)),
        });
        assert!(copy_due);
        assert!(model.request_copy().is_some());
    }

    #[test]
    fn copy_is_cancelled_by_site_changes() {
        let mut model = filled_model();
        let request = model.credentials_changed(Instant::now()).unwrap();
        model.request_copy();
        model.input.site_name.push('x');
        model.site_changed();
        let copy_due = model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Ok(fake_key(1)),
        });
        assert!(!copy_due);
    }

    #[test]
    fn copy_is_cancelled_by_credential_changes() {
        let mut model = filled_model();
        model.credentials_changed(Instant::now()).unwrap();
        model.request_copy();
        model.input.user_secret.push('!');
        let request = model.credentials_changed(Instant::now()).unwrap();
        let copy_due = model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Ok(fake_key(1)),
        });
        assert!(!copy_due);
    }

    #[test]
    fn copy_without_a_password_copies_nothing() {
        let mut model = Model::new(Input::default());
        assert!(model.request_copy().is_none());
    }

    #[test]
    fn failed_derivation_leaves_no_password() {
        let mut model = filled_model();
        derive(&mut model, &fake_key(1));
        model.input.user_secret.push('!');
        let request = model.credentials_changed(Instant::now()).unwrap();
        model.key_derived(DerivedKey {
            revision: request.revision,
            user_key: Err(SpectreError::InputTooLong("user name")),
        });
        assert!(model.site_password().is_none());
        assert!(model.deriving_since().is_none());
    }

    #[test]
    fn debug_output_hides_the_secret() {
        let input = input(USER, SECRET, SITE);
        assert!(!format!("{input:?}").contains(SECRET));
    }
}
