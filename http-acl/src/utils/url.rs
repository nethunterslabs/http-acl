//! URL utilities.

use url::Url;

/// Get the path from a URL.
pub fn get_url_path(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    Some(url.path().to_string())
}
