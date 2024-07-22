# http-acl-reqwest

An ACL middleware for reqwest.

## Why?

Systems which allow users to create arbitrary HTTP requests or specify arbitrary URLs to fetch like webhooks are vulnerable to SSRF attacks. An example is a malicious user could own a domain which resolves to a private IP address and then use that domain to make requests to internal services.

This crate provides a simple ACL to allow you to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can then be used to ensure that the user's request meets the ACL's requirements before the request is made.

<div class="warning">
  <blockquote style="background:rgba(255,229,100,0.2);padding:0.75em;margin:0.2em;">
    <strong>Warning:</strong>
    <br>
    The DNS resolver needs to be set on the reqwest Client to ensure that the ACL is enforced. If the DNS resolver is not set, the ACL will not be enforced on IP addresses resolved by the DNS resolver.
  </blockquote>
</div>

## Usage

```rust
use http_acl_reqwest::{HttpAcl, HttpAclMiddleware};
use reqwest::Client;
use reqwest_middleware::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an HTTP ACL
    let acl = HttpAcl::builder()
        .add_denied_host("example.com".to_string())
        .unwrap()
        .build();

    // Create the HTTP ACL middleware
    let middleware = HttpAclMiddleware::new(acl.clone());

    // Create a reqwest client with the DNS resolver
    let client = Client::builder()
        .dns_resolver(middleware.dns_resolver())
        .build()
        .unwrap();

    // Create a reqwest client with the middleware
    let client_with_middleware = ClientBuilder::new(client)
        .with(middleware)
        .build();

    // Make a request to a denied host
    assert!(client_with_middleware.get("http://example.com/").send().await.is_err());

    Ok(())
}
```

## Documentation

See [docs.rs](https://docs.rs/http-acl-reqwest).
