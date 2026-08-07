//! URL utilities.

use percent_encoding::percent_decode_str;
use url::Url;

/// Extracts the percent-decoded path from a full URL string, ready to pass to
/// [`HttpAcl::is_url_path_allowed`](crate::HttpAcl::is_url_path_allowed).
///
/// Returns `None` if `url` isn't a valid URL, or if its path isn't valid UTF-8 once
/// decoded.
pub fn get_url_path(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    let decoded = percent_decode_str(url.path()).decode_utf8().ok()?;
    Some(decoded.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_url_path_decodes_percent_encoding() {
        assert_eq!(
            get_url_path("https://example.com/api/versions").as_deref(),
            Some("/api/versions")
        );
        assert_eq!(
            get_url_path("https://example.com/countries/vi%E1%BB%87t%20nam").as_deref(),
            Some("/countries/việt nam")
        );
    }

    #[test]
    fn test_get_url_path_invalid_url() {
        assert_eq!(get_url_path("not a url"), None);
    }
}
