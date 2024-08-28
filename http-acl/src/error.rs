//! Error types for the HTTP ACL library.

use thiserror::Error;

/// Represents an error that can occur when adding a new allowed or denied entity to an ACL.
#[non_exhaustive]
#[derive(Error, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddError {
    /// The entity is already allowed so it cannot be denied.
    #[error("The entity is already allowed so it cannot be denied.")]
    AlreadyAllowed,
    /// The entity is already denied so it cannot be allowed.
    #[error("The entity is already denied so it cannot be allowed.")]
    AlreadyDenied,
    /// The entity is not allowed or denied because it is invalid.
    #[error("The entity is not allowed or denied because it is invalid.")]
    Invalid,
}
