/// Represents an error that can occur when adding a new allowed or denied entity to an ACL.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddError {
    /// The entity is already allowed so it cannot be denied.
    AlreadyAllowed,
    /// The entity is already denied so it cannot be allowed.
    AlreadyDenied,
    /// The entity is not allowed or denied because it is invalid.
    Invalid,
}

impl std::fmt::Display for AddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddError::AlreadyAllowed => {
                write!(f, "The entity is already allowed so it cannot be denied.")
            }
            AddError::AlreadyDenied => {
                write!(f, "The entity is already denied so it cannot be allowed.")
            }
            AddError::Invalid => write!(
                f,
                "The entity is not allowed or denied because it is invalid."
            ),
        }
    }
}
