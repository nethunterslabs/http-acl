use url::Url;

pub fn get_url_path(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    Some(url.path().to_string())
}
