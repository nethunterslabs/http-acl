# http-acl-reqwest

An ACL middleware for reqwest.

## Why?

Systems which allow users to create arbitrary HTTP requests or specify arbitrary URLs to fetch like webhooks are vulnerable to SSRF attacks. An example is a malicious user could own a domain which resolves to a private IP address and then use that domain to make requests to internal services.

This crate provides a simple ACL to allow you to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can then be used to ensure that the user's request meets the ACL's requirements before the request is made.

## What it checks

`HttpAclMiddleware` checks a request's scheme, method, host or IP, port, headers, and URL path, in that order, plus any custom `ValidateFn` you've attached to the ACL, denying on the first check that fails. See the [`http-acl`](https://docs.rs/http-acl) documentation for how the allow list, deny list, and per-category default combine for each of these.

That covers the request as originally built, which on its own is not enough: a request to an allowed host can still reach a denied address if the hostname resolves to one, or if the server redirects there. Wire up the DNS resolver and redirect policy below to close both gaps.

<div class="warning">
  <blockquote style="background:rgba(255,229,100,0.2);padding:0.75em;margin:0.2em;">
    <strong>Warning:</strong>
    <br>
    The DNS resolver needs to be set on the reqwest Client to ensure that the ACL is enforced. If the DNS resolver is not set, the ACL will not be enforced on IP addresses resolved by the DNS resolver.
    <br><br>
    The redirect policy also needs to be set on the reqwest Client. By default reqwest follows HTTP redirects internally before the middleware ever sees them, so a redirect to a denied host or IP (e.g. an internal address) would otherwise bypass the ACL entirely.
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

    // Create a reqwest client with the DNS resolver and redirect policy
    let client = Client::builder()
        .dns_resolver(middleware.dns_resolver())
        .redirect(middleware.redirect_policy())
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

## Static DNS mappings

A hostname can be pinned to a fixed address via `add_static_dns_mapping` and `add_trusted_static_dns_mapping` on the `HttpAcl` builder. The former's resolved address is still checked against the IP/port ACL, like any other resolved address; the latter bypasses that check entirely, so only use it for a mapping you trust regardless of what the ACL would otherwise say (e.g. deliberately pinning a hostname to an internal address). Both need the DNS resolver above to be set to take effect.

## Documentation

See [docs.rs](https://docs.rs/http-acl-reqwest).
