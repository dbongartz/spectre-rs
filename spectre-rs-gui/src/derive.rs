//! Derives user keys on a background thread, since scrypt takes a noticeable moment.

use std::sync::mpsc;

use secstr::SecStr;
use spectre_rs_core::{Scope, SpectreError};

pub struct DeriveRequest {
    /// Echoed in the result, so results for outdated input can be told apart.
    pub revision: u64,
    pub user_name: String,
    pub user_secret: SecStr,
}

pub struct DerivedKey {
    pub revision: u64,
    pub user_key: Result<SecStr, SpectreError>,
}

/// The worker thread, which runs until this is dropped.
pub struct KeyDeriver {
    requests: mpsc::Sender<DeriveRequest>,
    results: mpsc::Receiver<DerivedKey>,
}

impl KeyDeriver {
    /// Starts the worker; it repaints `ctx` whenever a key is ready.
    pub fn start(ctx: egui::Context) -> Self {
        let (requests, request_rx) = mpsc::channel::<DeriveRequest>();
        let (result_tx, results) = mpsc::channel::<DerivedKey>();

        std::thread::spawn(move || {
            while let Ok(request) = request_rx.recv() {
                // Skip queued intermediate edits and derive only the latest input.
                let latest = request_rx.try_iter().last().unwrap_or(request);
                let user_key = spectre_rs_core::gen_user_key(
                    &latest.user_name,
                    &latest.user_secret,
                    Scope::Authentication,
                );
                let result = DerivedKey {
                    revision: latest.revision,
                    user_key,
                };
                if result_tx.send(result).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });

        Self { requests, results }
    }

    pub fn request(&self, request: DeriveRequest) {
        if self.requests.send(request).is_err() {
            log::error!("The key derivation thread has stopped");
        }
    }

    /// The results that have come in since the last call.
    pub fn results(&self) -> impl Iterator<Item = DerivedKey> + '_ {
        self.results.try_iter()
    }
}
