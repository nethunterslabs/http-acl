use std::net::ToSocketAddrs;

use anyhow::anyhow;
use http::Extensions;
use http_acl::utils::authority::{Authority, Host};
use reqwest::{Request, Response};
use reqwest_middleware::{Error, Middleware, Next};

pub use http_acl;

#[derive(Debug, Clone)]
pub struct HttpAclMiddleware {
    acl: http_acl::HttpAcl,
}

impl HttpAclMiddleware {
    pub fn new(acl: http_acl::HttpAcl) -> Self {
        Self { acl }
    }
}

#[async_trait::async_trait]
impl Middleware for HttpAclMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> std::result::Result<Response, Error> {
        let scheme = req.url().scheme();
        let acl_scheme_match = self.acl.is_scheme_allowed(scheme);
        if acl_scheme_match.is_denied() {
            return Err(Error::Middleware(anyhow!(
                "scheme {} is denied - {}",
                scheme,
                acl_scheme_match
            )));
        }

        let method = req.method().as_str();
        let acl_method_match = self.acl.is_method_allowed(method);
        if acl_method_match.is_denied() {
            return Err(Error::Middleware(anyhow!(
                "method {} is denied - {}",
                method,
                acl_method_match
            )));
        }

        if let Some(host) = req.url().host_str() {
            let authority = Authority::parse(host)
                .map_err(|_| Error::Middleware(anyhow!("invalid host: {}", host)))?;

            match authority.host {
                Host::Ip(ip) => {
                    let acl_ip_match = self.acl.is_ip_allowed(&ip);
                    if acl_ip_match.is_denied() {
                        return Err(Error::Middleware(anyhow!(
                            "ip {} is denied - {}",
                            ip,
                            acl_ip_match
                        )));
                    }
                }
                Host::Domain(domain) => {
                    let acl_host_match = self.acl.is_host_allowed(&domain);
                    if acl_host_match.is_denied() {
                        return Err(Error::Middleware(anyhow!(
                            "host {} is denied - {}",
                            domain,
                            acl_host_match
                        )));
                    }
                }
            }

            if let Some(port) = req.url().port_or_known_default() {
                let acl_port_match = self.acl.is_port_allowed(port);
                if acl_port_match.is_denied() {
                    return Err(Error::Middleware(anyhow!(
                        "port {} is denied - {}",
                        port,
                        acl_port_match
                    )));
                }
            }

            // IP addresses are resolved twice, once here and once when the request is made.
            for socket_addr in host
                .to_socket_addrs()
                .map_err(|_| Error::Middleware(anyhow!("invalid host: {}", host)))?
            {
                let acl_ip_match = self.acl.is_ip_allowed(&socket_addr.ip());
                if acl_ip_match.is_denied() {
                    return Err(Error::Middleware(anyhow!(
                        "ip {} is denied - {}",
                        socket_addr.ip(),
                        acl_ip_match
                    )));
                }
            }

            let acl_url_path_match = self.acl.is_url_path_allowed(req.url().path());
            if acl_url_path_match.is_denied() {
                return Err(Error::Middleware(anyhow!(
                    "path {} is denied - {}",
                    req.url().path(),
                    acl_url_path_match
                )));
            }

            next.run(req, extensions).await
        } else {
            return Err(Error::Middleware(anyhow!("missing host")));
        }
    }
}

#[cfg(test)]
mod tests {
    use http_acl::HttpAcl;

    use super::*;

    #[tokio::test]
    async fn test_http_acl_middleware() {
        let acl = HttpAcl::builder()
            .add_denied_host("example.com".to_string())
            .unwrap()
            .build();

        let middleware = HttpAclMiddleware::new(acl);

        let client =
            reqwest_middleware::ClientBuilder::new(reqwest::Client::builder().build().unwrap())
                .with(middleware)
                .build();

        let request = client.get("http://example.com/").send().await;

        assert!(request.is_err());
        assert_eq!(request
            .unwrap_err()
            .to_string(),
            "Middleware error: host example.com is denied - The entiy is denied according to the denied ACL."
        );
    }
}
