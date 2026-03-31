use std::fmt;

pub mod import;
pub mod rotate;
pub mod show;

/// Printed above `keys show` and `keys rotate` public-key listings.
pub(crate) const PUBLIC_KEY_LIST_LEGEND: &str =
    "Legend: 🔑 = public key that matches your local private key.";

/// One line in a public-key list: optional 🔑 when this recipient matches the user’s local private key.
///
/// Used for `keys show` output and as the `inquire::Select` option type for `keys rotate`.
#[derive(Clone)]
pub(crate) struct PublicKeyListRow {
    pub(crate) key: String,
    pub(crate) matches_local_private_key: bool,
}

impl PublicKeyListRow {
    pub(crate) fn new(
        recipient: impl Into<String>,
        public_key_from_local_private_key: Option<&str>,
    ) -> Self {
        let key = recipient.into();
        let matches_local_private_key =
            public_key_from_local_private_key.is_some_and(|pub_key| pub_key == key.as_str());
        Self {
            key,
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
