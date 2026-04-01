use std::fmt;

use crate::crypto::PublicKey;

pub mod import;
pub mod rotate;
pub mod show;

/// Printed above `keys show` and `keys rotate` public-key listings.
pub(crate) const PUBLIC_KEY_LIST_LEGEND: &str =
    "Legend: 🔑 = public key that matches your local private key.";

/// One line in a public-key list: optional 🔑 when this recipient matches the user’s local private key.
///
/// Used for `keys show` output and as the interactive selection row type for `keys rotate`.
#[derive(Clone)]
pub(crate) struct PublicKeyListRow {
    pub(crate) key: PublicKey,
    pub(crate) matches_local_private_key: bool,
}

impl PublicKeyListRow {
    pub(crate) fn new(
        recipient: PublicKey,
        public_key_from_local_private: Option<&PublicKey>,
    ) -> Self {
        let matches_local_private_key =
            public_key_from_local_private.is_some_and(|pub_key| pub_key == &recipient);
        Self {
            key: recipient,
            matches_local_private_key,
        }
    }
}

impl fmt::Display for PublicKeyListRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = if self.matches_local_private_key {
            "🔑 "
        } else {
            "   "
        };
        write!(f, "{prefix}{}", self.key)
    }
}
