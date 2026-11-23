// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prototype: reach a service that another sandbox exposes, by its service name.
//!
//! The gateway publishes an exposed service as
//! `<workspace>--<sandbox>--<service>.<base-domain>` and routes a request for
//! that name to the owning sandbox. A workload cannot use the name today: it
//! resolves to an address that destination policy rejects.
//!
//! With this module the supervisor treats a name directly under the service
//! base domain as living at the gateway. Policy DNS answers it with the
//! gateway's address, and the dial uses the gateway's port, so a workload can
//! use the published service URL unchanged. Policy still decides whether the
//! workload may reach the name at all.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

/// Overrides the service base domain. A gateway without wildcard SANs
/// publishes services under the built-in default.
const BASE_DOMAIN_ENV: &str = "OPENSHELL_SERVICE_BASE_DOMAIN";
const DEFAULT_BASE_DOMAIN: &str = "openshell.localhost";
/// The gateway endpoint that the compute driver gives the supervisor.
const GATEWAY_ENDPOINT_ENV: &str = "OPENSHELL_ENDPOINT";

/// Where the names of gateway-exposed services are served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayRoute {
    base_domain: String,
    host: String,
    port: u16,
}

impl GatewayRoute {
    fn new(base_domain: &str, endpoint: &str) -> Option<Self> {
        let base_domain = base_domain.trim().trim_matches('.').to_ascii_lowercase();
        let uri = endpoint.trim().parse::<http::Uri>().ok()?;
        let default_port = match uri.scheme_str()? {
            "http" => 80,
            "https" => 443,
            _ => return None,
        };
        let host = uri
            .host()?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if base_domain.is_empty() || host.is_empty() {
            return None;
        }
        Some(Self {
            base_domain,
            host,
            port: uri.port_u16().unwrap_or(default_port),
        })
    }

    /// True when `name` is one label directly under the service base domain.
    fn serves(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        name.strip_suffix(self.base_domain.as_str())
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    }

    /// The gateway host: a DNS name or an IP literal.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// The gateway address, when the endpoint names the gateway by address.
    pub(crate) fn address(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    fn dial_target(&self, addrs: &[SocketAddr]) -> (u16, Vec<SocketAddr>) {
        let addrs = addrs
            .iter()
            .map(|addr| SocketAddr::new(addr.ip(), self.port))
            .collect();
        (self.port, addrs)
    }
}

fn configured() -> Option<&'static GatewayRoute> {
    static ROUTE: OnceLock<Option<GatewayRoute>> = OnceLock::new();
    ROUTE
        .get_or_init(|| {
            let base_domain =
                std::env::var(BASE_DOMAIN_ENV).unwrap_or_else(|_| DEFAULT_BASE_DOMAIN.to_string());
            let endpoint = std::env::var(GATEWAY_ENDPOINT_ENV).ok()?;
            GatewayRoute::new(&base_domain, &endpoint)
        })
        .as_ref()
}

/// The gateway route for `name`, when `name` is the name of a gateway service.
pub(crate) fn route_for(name: &str) -> Option<&'static GatewayRoute> {
    configured().filter(|route| route.serves(name))
}

/// The port and addresses to dial when `host` is the name of a gateway service.
///
/// The approved addresses stay. The port becomes the gateway's own port: the
/// published service URL carries the port of the client that asked for it,
/// which need not be the port the gateway listens on.
pub(crate) fn dial_target(host: &str, addrs: &[SocketAddr]) -> Option<(u16, Vec<SocketAddr>)> {
    route_for(host).map(|route| route.dial_target(addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(endpoint: &str) -> GatewayRoute {
        GatewayRoute::new("openshell.localhost", endpoint).expect("valid gateway endpoint")
    }

    #[test]
    fn serves_one_label_under_the_base_domain() {
        let route = route("http://openshell.openshell.svc.cluster.local:8080");

        assert!(route.serves("team--srv--rest.openshell.localhost"));
        assert!(route.serves("Team--Srv.OpenShell.Localhost."));
        assert!(!route.serves("openshell.localhost"));
        assert!(!route.serves("a.b.openshell.localhost"));
        assert!(!route.serves("evilopenshell.localhost"));
        assert!(!route.serves("srv.openshell.localhost.example.com"));
    }

    #[test]
    fn reads_the_host_and_port_of_the_gateway_endpoint() {
        let named = route("http://openshell.openshell.svc.cluster.local:8080");
        assert_eq!(named.host(), "openshell.openshell.svc.cluster.local");
        assert_eq!(named.port, 8080);
        assert_eq!(named.address(), None);

        assert_eq!(route("https://Gateway.Example").port, 443);
        assert_eq!(route("https://Gateway.Example").host(), "gateway.example");
        assert_eq!(route("http://gateway.example/").port, 80);

        let v4 = route("https://10.0.0.7:8443");
        assert_eq!(v4.address(), Some("10.0.0.7".parse().unwrap()));
        assert_eq!(v4.port, 8443);
        assert_eq!(
            route("https://[fd00::7]:8443").address(),
            Some("fd00::7".parse().unwrap())
        );
    }

    #[test]
    fn rejects_an_endpoint_without_a_web_scheme_or_a_base_domain() {
        assert_eq!(
            GatewayRoute::new("openshell.localhost", "gateway:8080"),
            None
        );
        assert_eq!(
            GatewayRoute::new("openshell.localhost", "unix:///run/gw.sock"),
            None
        );
        assert_eq!(GatewayRoute::new(" . ", "http://gateway:8080"), None);
    }

    #[test]
    fn dial_target_keeps_the_addresses_and_takes_the_gateway_port() {
        let route = route("http://openshell.openshell.svc.cluster.local:8080");
        let approved: Vec<SocketAddr> = vec!["10.96.0.20:39259".parse().unwrap()];

        let (port, addrs) = route.dial_target(&approved);

        assert_eq!(port, 8080);
        assert_eq!(
            addrs,
            vec!["10.96.0.20:8080".parse::<SocketAddr>().unwrap()]
        );
    }
}
