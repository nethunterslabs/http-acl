# http-acl-reqwest

An ACL middleware for reqwest.

## Why?

Systems which allow users to create arbitrary HTTP requests or specify arbitrary URLs to fetch like webhooks are vulnerable to SSRF attacks. An example is a malicious user could own a domain which resolves to a private IP address and then use that domain to make requests to internal services.

This crate provides a simple ACL to allow you to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can then be used to ensure that the user's request meets the ACL's requirements before the request is made.

## Usage

```rust
use http_acl_reqwest::{HttpAcl, HttpAclMiddleware};
use reqwest::Client;
use reqwest_middleware::ClientBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let acl = HttpAcl::builder()
        .add_denied_host("example.com".to_string())
        .unwrap()
        .build();

    let middleware = HttpAclMiddleware::new(acl);

    let client = ClientBuilder::new(Client::builder().build().unwrap())
        .with(middleware)
        .build();

    assert!(client.get("http://example.com/").send().await.is_err());

    Ok(())
}
```

## Documentation

See [docs.rs](https://docs.rs/http-acl-reqwest).
