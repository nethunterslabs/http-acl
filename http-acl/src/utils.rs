use std::collections::HashSet;
use std::hash::Hash;

pub mod authority;
pub(crate) mod ip;
pub mod url;

// Taken from https://stackoverflow.com/a/46767732
pub(crate) fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}
