#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use std::future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::anyhow;
use http::Extensions;
use http_acl::utils::authority::{Authority, Host};
use reqwest::{
    dns::{Name, Resolve, Resolving},
    Request, Response,
};
use reqwest_middleware::{Error, Middleware, Next};
use thiserror::Error;

pub use http_acl::{self, HttpAcl, HttpAclBuilder};

#[derive(Debug, Clone)]
/// A reqwest middleware that enforces an HTTP ACL.
pub struct HttpAclMiddleware {
    acl: Arc<HttpAcl>,
}

impl HttpAclMiddleware {
    /// Create a new HTTP ACL middleware.
    pub fn new(acl: HttpAcl) -> Self {
        Self { acl: Arc::new(acl) }
    }

    /// Get the ACL.
    pub fn acl(&self) -> Arc<HttpAcl> {
        self.acl.clone()
    }

    /// Create a DNS resolver that enforces the ACL.
    pub fn dns_resolver(&self) -> Arc<HttpAclDnsResolver> {
        Arc::new(HttpAclDnsResolver::new(self))
    }

    /// Create a DNS resolver that enforces the ACL with a custom DNS resolver.
    pub fn with_dns_resolver(&self, dns_resolver: Arc<dyn Resolve>) -> Arc<HttpAclDnsResolver> {
        Arc::new(HttpAclDnsResolver::with_dns_resolver(self, dns_resolver))
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

type BoxError = Box<dyn std::error::Error + Send + Sync>;

struct GaiResolver;

impl Resolve for GaiResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = name
                .as_str()
                .to_socket_addrs()
                .map_err(|e| Box::new(e) as BoxError)?;
            Ok(Box::new(addresses.into_iter()) as Box<dyn Iterator<Item = SocketAddr> + Send>)
        })
    }
}

/// A DNS resolver that enforces an HTTP ACL.
pub struct HttpAclDnsResolver {
    dns_resolver: Arc<dyn Resolve>,
    acl: Arc<HttpAcl>,
}

impl HttpAclDnsResolver {
    /// Create a new ACL resolver.
    pub fn new(middleware: &HttpAclMiddleware) -> Self {
        Self {
            dns_resolver: Arc::new(GaiResolver),
            acl: middleware.acl(),
        }
    }

    /// Create a new ACL resolver with a custom DNS resolver.
    pub fn with_dns_resolver(
        middleware: &HttpAclMiddleware,
        dns_resolver: Arc<dyn Resolve>,
    ) -> Self {
        Self {
            dns_resolver,
            acl: middleware.acl(),
        }
    }
}

impl Resolve for HttpAclDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        if self.acl.is_host_allowed(name.as_str()).is_denied() {
            let err: BoxError = Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Host denied by ACL",
            ));
            return Box::pin(future::ready(Err(err)));
        }

        let acl = self.acl.clone();
        let resolver = self.dns_resolver.clone();

        Box::pin(async move {
            let resolved = resolver.resolve(name).await;
            match resolved {
                Ok(addresses) => {
                    let filtered = addresses
                        .into_iter()
                        .filter(|addr| {
                            acl.is_ip_allowed(&addr.ip()).is_allowed()
                                && acl.is_port_allowed(addr.port()).is_allowed()
                        })
                        .collect::<Vec<_>>();
                    Ok(Box::new(filtered.into_iter())
                        as Box<dyn Iterator<Item = SocketAddr> + Send>)
                }
                Err(e) => Err(e),
            }
        })
    }
}

#[derive(Error, Debug)]
/// An error that can occur when resolving a host.
pub enum HttpAclError {
    /// Host resolution denied by ACL.
    #[error("Host resolution denied by ACL: {host}")]
    HostDenied {
        /// The host that was denied.
        host: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_acl_middleware() {
        let acl = HttpAcl::builder()
            .add_denied_host("example.com".to_string())
            .unwrap()
            .build();

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
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
