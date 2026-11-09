//! Derives user keys on a background thread, since scrypt takes a noticeable moment.

use std::sync::mpsc;

use secstr::SecStr;
use spectre_rs_core::SpectreError;

pub struct DeriveRequest {
    /// Echoed in the result, so results for outdated input can be told apart.
    pub revision: u64,
    pub user_name: String,
    pub user_secret: SecStr,
}

pub struct DerivedKey {
    pub revision: u64,
    /// `None` if the user name or secret is empty.
    pub user_key: Result<Option<SecStr>, SpectreError>,
}

/// Starts the worker thread. It runs until the returned sender is dropped, and repaints `ctx`
/// whenever a key is ready.
pub fn start(ctx: egui::Context) -> (mpsc::Sender<DeriveRequest>, mpsc::Receiver<DerivedKey>) {
    let (derive_tx, derive_rx) = mpsc::channel::<DeriveRequest>();
    let (derived_tx, derived_rx) = mpsc::channel::<DerivedKey>();

    std::thread::spawn(move || {
        while let Ok(request) = derive_rx.recv() {
            // Skip queued intermediate password edits and derive only the latest input.
            let mut latest = request;
            while let Ok(newer) = derive_rx.try_recv() {
                latest = newer;
            }

            let user_key = derive_user_key(&latest);
            let _ = derived_tx.send(DerivedKey {
                revision: latest.revision,
                user_key,
            });
            ctx.request_repaint();
        }
    });

    (derive_tx, derived_rx)
}

fn derive_user_key(request: &DeriveRequest) -> Result<Option<SecStr>, SpectreError> {
    if request.user_name.is_empty() || request.user_secret.unsecure().is_empty() {
        Ok(None)
    } else {
        spectre_rs_core::gen_user_key(
            &request.user_name,
            &request.user_secret,
            spectre_rs_core::Scope::Authentication,
        )
        .map(Some)
    }
}
