// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential gating: which endpoints a provider credential may reach, and
//! what the supervisor forwards upstream in REST bodies and WebSocket frames.
//!
//! Ported from the e2e tests added in ai-openshell/openshell#5264.
//!
//! The tests need upstream servers that a sandbox reaches through the
//! supervisor and that say what arrived. [`Upstream`] is one of two things.
//! With `OPENSHELL_TEST_UPSTREAM=sandbox`, it is a throwaway server that the
//! test starts in a sandbox of its own and exposes as gateway services; the
//! client's sandbox reaches it by the service URLs the gateway publishes, and
//! what arrived comes back through the client's sandbox, so the machine that
//! runs the tests serves nothing. Without the variable, it is recording
//! servers in this process ([`host_server_support`]), which sandboxes must
//! reach on the test host as `host.openshell.internal`.

use std::time::Duration;

use host_server_support::{HttpRecorder, Request, TEST_HOST, WebSocketRecorder};
use testkit::policy::{self, Access, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{
    Context, Error, GrpcCode, PYTHON_BINARIES, Result, ResultExt as _, Sandbox, YamlFile,
};

const TOKEN_ENV: &str = "E2E_GATING_TOKEN";
const TEST_SECRET: &str = "e2e-gating-secret-value";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

/// POSTs a body containing the provider's token to the host in `argv[1]` on
/// the port in `argv[2]` at the path in `argv[3]`, directly rather than
/// through a proxy, and prints the answer.
const BODY_CLIENT: &str = r#"
import os, sys, urllib.request
body = ("prefix-" + os.environ["E2E_GATING_TOKEN"] + "-suffix").encode()
request = urllib.request.Request(f"http://{sys.argv[1]}:{sys.argv[2]}{sys.argv[3]}", data=body, headers={"Content-Type": "text/plain"})
sys.stdout.write(urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10).read().decode())
"#;

/// Upgrades to WebSocket at the host in `argv[1]` on the port in `argv[2]` at
/// the path in `argv[3]`, sends one binary frame, and waits briefly for the
/// connection to be closed.
const WEBSOCKET_CLIENT: &str = r#"
import base64, os, socket, sys
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with socket.create_connection((host, port), timeout=10) as sock:
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit(f"closed during the upgrade: {response!r}")
        response += chunk
    if not response.startswith(b"HTTP/1.1 101"):
        sys.exit(f"upgrade failed: {response!r}")
    payload, mask = b"binary-credential-channel", os.urandom(4)
    sock.sendall(bytes([0x82, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    sock.settimeout(3)
    try:
        sock.recv(4096)
    except (TimeoutError, ConnectionError):
        pass
"#;

/// GETs the path in `argv[3]` from the host in `argv[1]` on the port in
/// `argv[2]` and prints the answer, including the answer to a failed request.
const GET_CLIENT: &str = r#"
import sys, urllib.error, urllib.request
try:
    answer = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://{sys.argv[1]}:{sys.argv[2]}{sys.argv[3]}", timeout=10).read()
except urllib.error.HTTPError as error:
    answer = error.read()
sys.stdout.write(answer.decode())
"#;

/// Where the upstream servers run: `sandbox` starts a throwaway server in a
/// sandbox for each upstream; unset, the servers run in this process.
const UPSTREAM_ENV: &str = "OPENSHELL_TEST_UPSTREAM";
/// The server a sandbox upstream runs. It answers a REST request with what
/// it received, and reports what the WebSocket connection to `/ws/<id>`
/// carried at `/seen/<id>` on the REST port.
const SERVER: &str = include_str!("../../../support/upstream-server/server.py");
const SERVER_REST_PORT: u16 = 8080;
const SERVER_WEBSOCKET_PORT: u16 = 8081;
/// Names the one WebSocket connection a sandbox upstream receives.
const SERVER_CONNECTION: &str = "frame";
/// How long the server may take to start, and to see a WebSocket connection
/// end.
const SERVER_WAIT: Duration = Duration::from_secs(20);

/// Prints `TOKEN_ABSENT`, `TOKEN_PLACEHOLDER`, or `TOKEN_UNSAFE` for the
/// provider's environment variable, without printing its value.
const TOKEN_PRESENCE: &str = r#"if [ "${E2E_GATING_TOKEN+x}" != x ]; then
  echo TOKEN_ABSENT
else
  case "$E2E_GATING_TOKEN" in
    openshell:resolve:env:*) echo TOKEN_PLACEHOLDER ;;
    *) echo TOKEN_UNSAFE ;;
  esac
fi"#;

/// A provider whose profile declares the REST and WebSocket servers as its
/// endpoints keeps the credential placeholder in a REST body.
#[testkit::test]
async fn profile_rest_endpoint_keeps_body_placeholder(cx: &mut Context) -> testkit::Result {
    let upstream = Upstream::start(cx, "rest").await?;
    let provider = install_gating_provider(cx, Some(&upstream)).await?;

    let mut policy = policy::base();
    upstream
        .allow_rest(&mut policy)
        .rest(Access::Full)
        .request_body_credential_rewrite(false);
    let sandbox = create_sandbox(cx, "rest", policy, &[&provider]).await?;
    expect_placeholder_body(&upstream.post_token(&sandbox).await?)
}

/// A provider's WebSocket endpoint completes the handshake but doesn't
/// forward a binary frame, which the supervisor can't inspect for the
/// credential. The same client in a sandbox without the provider gets its
/// binary frame through, which shows the denial comes from the credential.
#[testkit::test]
async fn profile_websocket_endpoint_denies_binary_frames(cx: &mut Context) -> testkit::Result {
    let upstream = Upstream::start(cx, "ws").await?;
    let provider = install_gating_provider(cx, Some(&upstream)).await?;

    let control = Upstream::start(cx, "ctl").await?;
    let binary_seen = send_binary_frame(cx, "wsctl", &control, &[]).await?;
    testkit::ensure!(
        binary_seen,
        "the binary frame didn't reach upstream from a sandbox without the provider"
    );

    let binary_seen = send_binary_frame(cx, "ws", &upstream, &[&provider]).await?;
    testkit::ensure!(
        !binary_seen,
        "credentialed WebSocket binary frame reached upstream"
    );
    Ok(())
}

/// The gateway rejects a policy that binds a provider to an L4-only
/// endpoint or to an endpoint with `tls: skip`, and accepts an L4 endpoint
/// that opts in to uninspected credentials.
#[testkit::test]
async fn policy_binding_requires_inspection_or_opt_in(cx: &mut Context) -> testkit::Result {
    let upstream = Upstream::start(cx, "adm").await?;
    let provider = install_gating_provider(cx, None).await?;

    let mut l4 = policy::base();
    upstream.allow_rest(&mut l4).credential_binding(&provider);
    // The wording checks follow the #5264 tests.
    let error = expect_rejected(cx, "l4", l4, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("L4-only"), "{error}");

    let mut tls_skip = policy::base();
    upstream
        .allow_rest(&mut tls_skip)
        .rest(Access::Full)
        .tls_skip()
        .credential_binding(&provider);
    let error = expect_rejected(cx, "tls", tls_skip, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("tls:") && error.contains("skip"), "{error}");

    let mut opt_in = policy::base();
    upstream
        .allow_rest(&mut opt_in)
        .allow_uninspected_credentials()
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "optin", opt_in, &[&provider]).await?;
    sandbox.exec(["true"]).await?.success()?;
    Ok(())
}

/// A policy binding to a REST endpoint without body rewriting sends the
/// credential placeholder upstream, not the secret.
#[testkit::test]
async fn policy_binding_rest_body_keeps_placeholder_without_rewrite(
    cx: &mut Context,
) -> testkit::Result {
    let upstream = Upstream::start(cx, "body").await?;
    let provider = install_gating_provider(cx, None).await?;

    let mut policy = policy::base();
    upstream
        .allow_rest(&mut policy)
        .rest(Access::Full)
        .request_body_credential_rewrite(false)
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "body", policy, &[&provider]).await?;
    expect_placeholder_body(&upstream.post_token(&sandbox).await?)
}

/// A policy binding with `request_body_credential_rewrite: true` replaces
/// the placeholder in the REST body with the secret upstream.
#[testkit::test]
async fn policy_binding_rest_body_rewrite_sends_secret_upstream(
    cx: &mut Context,
) -> testkit::Result {
    let upstream = Upstream::start(cx, "rw").await?;
    let provider = install_gating_provider(cx, None).await?;

    let mut policy = policy::base();
    upstream
        .allow_rest(&mut policy)
        .rest(Access::Full)
        .request_body_credential_rewrite(true)
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "rw", policy, &[&provider]).await?;
    let request = upstream.post_token(&sandbox).await?;
    testkit::ensure!(
        request.body == format!("prefix-{TEST_SECRET}-suffix"),
        "expected the secret in the body upstream; got {}",
        redact(&request)
    );
    Ok(())
}

/// Binding and unbinding a provider with `policy set --wait` adds and
/// removes its environment variable in a running sandbox.
#[testkit::test]
async fn policy_binding_updates_provider_environment_live(cx: &mut Context) -> testkit::Result {
    let upstream = Upstream::start(cx, "live").await?;
    let provider = install_gating_provider(cx, None).await?;

    let policy_binding = |bind: bool| {
        let mut policy = policy::base();
        let endpoint = upstream
            .allow_rest(&mut policy)
            .rest(Access::Full)
            .request_body_credential_rewrite(false);
        if bind {
            endpoint.credential_binding(&provider);
        }
        policy
    };
    let (unbound, bound) = (policy_binding(false), policy_binding(true));

    let sandbox = create_sandbox(cx, "live", unbound.clone(), &[&provider]).await?;
    wait_for_token(&sandbox, "TOKEN_ABSENT").await?;

    set_policy(cx, &sandbox, &bound)
        .await
        .context("bind the provider")?;
    wait_for_token(&sandbox, "TOKEN_PLACEHOLDER").await?;

    set_policy(cx, &sandbox, &unbound)
        .await
        .context("unbind the provider")?;
    wait_for_token(&sandbox, "TOKEN_ABSENT").await
}

/// Run [`WEBSOCKET_CLIENT`] against `upstream` in a sandbox with
/// `providers`, and return whether its binary frame reached `upstream`.
async fn send_binary_frame(
    cx: &Context,
    suffix: &str,
    upstream: &Upstream,
    providers: &[&str],
) -> Result<bool> {
    let mut policy = policy::base();
    upstream
        .allow_websocket(&mut policy)
        .websocket(Access::ReadWrite);
    upstream.allow_reading_what_arrived(&mut policy);
    let sandbox = create_sandbox(cx, suffix, policy, providers).await?;
    upstream.binary_frame_seen(&sandbox).await
}

/// The upstream servers a sandbox's client talks to, and how a test learns
/// what they received.
enum Upstream {
    /// Recording servers in this process. Sandboxes must reach the test host
    /// as `host.openshell.internal`.
    TestHost {
        rest: HttpRecorder,
        websocket: WebSocketRecorder,
    },
    /// A throwaway server for this upstream: [`SERVER`] as the main command
    /// of a sandbox of its own, with each port exposed as a gateway service.
    /// A client's sandbox reaches it at the addresses in the service URLs the
    /// gateway publishes.
    Sandbox { rest: Address, websocket: Address },
}

/// Where a client in a sandbox reaches one upstream server.
#[derive(Clone)]
struct Address {
    host: String,
    port: u16,
}

impl Address {
    fn on_test_host(port: u16) -> Self {
        Self {
            host: TEST_HOST.to_string(),
            port,
        }
    }

    /// The host and port of a service URL. The clients in this module speak
    /// plain HTTP, so the URL must be plain HTTP too.
    fn of_service_url(url: &str) -> Result<Self> {
        let unusable = || {
            Error::msg(format!(
                "a sandbox upstream needs a plain HTTP service URL; the gateway published {url}"
            ))
        };
        let rest = url.strip_prefix("http://").ok_or_else(unusable)?;
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| unusable())?),
            None => (authority, 80),
        };
        testkit::ensure!(!host.is_empty(), "the service URL {url} has no host");
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

impl Upstream {
    /// A server in a sandbox of its own when [`UPSTREAM_ENV`] is `sandbox`,
    /// or new servers on the test host. `suffix` tells apart the upstreams of
    /// one test; a sandbox name leaves room for four characters of it.
    async fn start(cx: &Context, suffix: &str) -> Result<Self> {
        match env(UPSTREAM_ENV).as_deref() {
            None => Ok(Self::TestHost {
                rest: HttpRecorder::start("ok").await?,
                websocket: WebSocketRecorder::start().await?,
            }),
            Some("sandbox") => Self::start_in_sandbox(cx, suffix).await,
            Some(other) => Err(Error::msg(format!(
                "{UPSTREAM_ENV}={other:?}; expected `sandbox` or unset"
            ))),
        }
    }

    async fn start_in_sandbox(cx: &Context, suffix: &str) -> Result<Self> {
        let server = cx
            .sandbox(&format!("u{suffix}"))
            .image(testkit::python_image())
            .command(["python3", "-c", SERVER])
            .create_ready()
            .await
            .context("start the upstream server's sandbox")?;
        // Loopback inside the server's own sandbox doesn't pass a supervisor.
        server
            .poll_exec(
                "the upstream server to answer",
                SERVER_WAIT,
                [
                    "python3".to_string(),
                    "-c".to_string(),
                    GET_CLIENT.to_string(),
                    "127.0.0.1".to_string(),
                    SERVER_REST_PORT.to_string(),
                    "/healthz".to_string(),
                ],
                |output| output.stdout.contains("ok"),
            )
            .await?;
        Ok(Self::Sandbox {
            rest: expose(cx, &server, SERVER_REST_PORT, "rest").await?,
            websocket: expose(cx, &server, SERVER_WEBSOCKET_PORT, "ws").await?,
        })
    }

    fn rest(&self) -> Address {
        match self {
            Self::TestHost { rest, .. } => Address::on_test_host(rest.port),
            Self::Sandbox { rest, .. } => rest.clone(),
        }
    }

    fn websocket(&self) -> Address {
        match self {
            Self::TestHost { websocket, .. } => Address::on_test_host(websocket.port),
            Self::Sandbox { websocket, .. } => websocket.clone(),
        }
    }

    /// Let the image's Python reach the REST server.
    fn allow_rest<'a>(
        &self,
        policy: &'a mut proto::SandboxPolicy,
    ) -> &'a mut proto::NetworkEndpoint {
        allow(policy, &self.rest())
    }

    /// Let the image's Python reach the WebSocket server.
    fn allow_websocket<'a>(
        &self,
        policy: &'a mut proto::SandboxPolicy,
    ) -> &'a mut proto::NetworkEndpoint {
        allow(policy, &self.websocket())
    }

    /// Let the sandbox ask a sandbox upstream what its WebSocket connection
    /// carried. The servers on the test host are asked directly.
    fn allow_reading_what_arrived(&self, policy: &mut proto::SandboxPolicy) {
        if matches!(self, Self::Sandbox { .. }) {
            self.allow_rest(policy).rest(Access::Full);
        }
    }

    /// Run [`BODY_CLIENT`] in `sandbox` and return the one request the REST
    /// server received.
    async fn post_token(&self, sandbox: &Sandbox) -> Result<Request> {
        let Address { host, port } = self.rest();
        let answer =
            run_python(sandbox, BODY_CLIENT, &[&host, &port.to_string(), "/token"]).await?;
        match self {
            Self::TestHost { rest, .. } => one_request(rest).await,
            Self::Sandbox { .. } => echoed_request(&answer),
        }
    }

    /// Run [`WEBSOCKET_CLIENT`] in `sandbox` and return whether its binary
    /// frame reached the WebSocket server.
    async fn binary_frame_seen(&self, sandbox: &Sandbox) -> Result<bool> {
        let Address { host, port } = self.websocket();
        let port = port.to_string();
        match self {
            Self::TestHost { websocket, .. } => {
                run_python(sandbox, WEBSOCKET_CLIENT, &[&host, &port, "/ws"]).await?;
                websocket
                    .wait_for_handshake()
                    .await
                    .context("upstream should receive the WebSocket handshake")?;
                websocket.wait_until_finished().await
            }
            Self::Sandbox { rest, .. } => {
                let path = format!("/ws/{SERVER_CONNECTION}");
                run_python(sandbox, WEBSOCKET_CLIENT, &[&host, &port, &path]).await?;
                // The server marks the connection finished when it ends, so
                // this reads what happened rather than waiting it out.
                let finished = |answer: &str| {
                    serde_json::from_str::<serde_json::Value>(answer)
                        .is_ok_and(|seen| seen["finished"] == true)
                };
                let output = sandbox
                    .poll_exec(
                        "the upstream server to see the WebSocket connection end",
                        SERVER_WAIT,
                        [
                            "python3".to_string(),
                            "-c".to_string(),
                            GET_CLIENT.to_string(),
                            rest.host.clone(),
                            rest.port.to_string(),
                            format!("/seen/{SERVER_CONNECTION}"),
                        ],
                        |output| finished(&output.stdout),
                    )
                    .await?;
                let seen: serde_json::Value = serde_json::from_str(&output.stdout)
                    .map_err(|error| Error::msg(format!("read the server's answer: {error}")))?;
                testkit::ensure!(
                    seen["handshake"] == true,
                    "upstream should receive the WebSocket handshake; the server saw {seen}"
                );
                Ok(seen["binary"] == true)
            }
        }
    }
}

/// Let the image's Python reach `address`.
fn allow<'a>(
    policy: &'a mut proto::SandboxPolicy,
    address: &Address,
) -> &'a mut proto::NetworkEndpoint {
    policy::allow(
        policy,
        "credential_gating",
        &address.host,
        address.port,
        PYTHON_BINARIES,
    )
}

/// Expose `port` of `server` as the gateway service `service`, and return
/// the address in the URL the gateway publishes for it.
async fn expose(cx: &Context, server: &Sandbox, port: u16, service: &str) -> Result<Address> {
    cx.cli([
        "service",
        "expose",
        server.name(),
        &port.to_string(),
        service,
    ])
    .await?
    .success()
    .context("service expose")?;
    let listed: serde_json::Value = cx
        .cli(["service", "list", server.name(), "--output", "json"])
        .await?
        .success()
        .context("service list")?
        .json()?;
    let url = listed["services"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["service"] == service)
        .and_then(|entry| entry["url"].as_str())
        .ok_or_else(|| {
            Error::msg(format!(
                "the gateway lists no URL for service {service}: {listed}"
            ))
        })?;
    Address::of_service_url(url)
}

/// The request in a sandbox upstream's answer to it. The server also sends
/// the SHA-256 of the body it read, which shows whether the body in the
/// answer was changed on its way back through the supervisor.
fn echoed_request(answer: &str) -> Result<Request> {
    let echoed: serde_json::Value = serde_json::from_str(answer).map_err(|error| {
        Error::msg(format!(
            "the upstream server's answer is not JSON ({error}): {}",
            answer.replace(TEST_SECRET, "<secret>")
        ))
    })?;
    let field = |name: &str| {
        echoed[name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::msg(format!("the upstream server's answer has no `{name}`")))
    };
    let request = Request {
        head: field("head")?,
        body: field("body")?,
    };
    let digest = openshell_crypto::sha256(request.body.as_bytes())
        .map_err(|error| Error::msg(format!("hash the body: {error}")))?
        .iter()
        .fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    testkit::ensure!(
        digest == field("body_sha256")?,
        "the body in the server's answer is not the body the server read; got {}",
        redact(&request)
    );
    Ok(request)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Install a run-unique provider holding `TEST_SECRET` in `TOKEN_ENV`. With
/// `endpoints`, its profile declares that upstream's REST and WebSocket
/// servers as its endpoints; without, a policy must bind the provider
/// explicitly.
async fn install_gating_provider(cx: &Context, endpoints: Option<&Upstream>) -> Result<String> {
    let name = cx.name("cg");
    let endpoints = endpoints.map_or_else(String::new, |upstream| {
        let (rest, websocket) = (upstream.rest(), upstream.websocket());
        format!(
            "endpoints:
  - host: {}
    port: {}
    protocol: rest
    access: full
  - host: {}
    port: {}
    protocol: websocket
    access: read-write
",
            rest.host, rest.port, websocket.host, websocket.port
        )
    });
    let binaries: String = PYTHON_BINARIES
        .iter()
        .map(|path| format!("  - path: {path}\n"))
        .collect();
    let profile = format!(
        "id: {name}
display_name: E2E Credential Gating
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
{endpoints}binaries:
{binaries}"
    );
    cx.install_provider(&name, &profile, &[(TOKEN_ENV, TEST_SECRET)])
        .await?;
    Ok(name)
}

fn sandbox_with(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    providers: &[&str],
) -> testkit::SandboxBuilder {
    cx.sandbox(suffix)
        .policy(policy)
        .image(testkit::python_image())
        .spec(|spec| spec.providers = providers.iter().map(ToString::to_string).collect())
        .command(["sleep", "infinity"])
}

/// Create a long-running sandbox from the Python image with `policy` and
/// `providers`, and wait until it is Ready.
async fn create_sandbox(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    providers: &[&str],
) -> Result<Sandbox> {
    sandbox_with(cx, suffix, policy, providers)
        .create_ready()
        .await
}

/// Fail unless the gateway rejects the sandbox as a failed precondition, and
/// return the rejection.
async fn expect_rejected(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    provider: &str,
) -> Result<String> {
    match sandbox_with(cx, suffix, policy, &[provider]).create().await {
        Ok(sandbox) => Err(Error::msg(format!(
            "the gateway accepted sandbox {}",
            sandbox.name()
        ))),
        Err(error) if error.grpc_code() == Some(GrpcCode::FailedPrecondition) => {
            Ok(error.to_string())
        }
        Err(error) => Err(error.context("expected a failed precondition")),
    }
}

/// Run `script` with the image's Python and `args`, and return what it
/// printed.
async fn run_python(sandbox: &Sandbox, script: &str, args: &[&str]) -> Result<String> {
    let command = ["python3", "-c", script]
        .into_iter()
        .chain(args.iter().copied());
    let output = sandbox
        .exec(command)
        .await?
        .success()
        .context("run the client in the sandbox")?;
    Ok(output.stdout)
}

/// The one request `server` saw.
async fn one_request(server: &HttpRecorder) -> Result<Request> {
    let mut requests = server.wait_for_requests(1).await?;
    testkit::ensure!(
        requests.len() == 1,
        "expected one request upstream; got {}",
        requests.len()
    );
    Ok(requests.remove(0))
}

/// Fail unless `request`, the one the upstream received, has the credential
/// placeholder in place of the token in its body, and the secret appears
/// nowhere in it.
fn expect_placeholder_body(request: &Request) -> Result {
    testkit::ensure!(
        request
            .body
            .starts_with(&format!("prefix-{PLACEHOLDER_PREFIX}"))
            && request.body.ends_with("-suffix")
            && !request.head.contains(TEST_SECRET)
            && !request.body.contains(TEST_SECRET),
        "expected the placeholder in the body upstream and no secret; got {}",
        redact(request)
    );
    Ok(())
}

/// `request` for a failure message, with the secret replaced.
fn redact(request: &Request) -> String {
    format!("{}\n\n{}", request.head, request.body).replace(TEST_SECRET, "<secret>")
}

/// Wait until new exec sessions report `expected` from [`TOKEN_PRESENCE`].
async fn wait_for_token(sandbox: &Sandbox, expected: &str) -> Result {
    sandbox
        .poll_exec(
            &format!("the provider environment to report {expected}"),
            Duration::from_secs(30),
            ["sh", "-lc", TOKEN_PRESENCE],
            |output| output.stdout.contains(expected),
        )
        .await?;
    Ok(())
}

/// Replace `sandbox`'s policy with `policy` and wait until it is applied.
async fn set_policy(cx: &Context, sandbox: &Sandbox, policy: &proto::SandboxPolicy) -> Result {
    let file = YamlFile::new(&policy::to_yaml(policy)?)?;
    cx.cli([
        "policy",
        "set",
        sandbox.name(),
        "--policy",
        file.path()?,
        "--wait",
        "--timeout",
        "120",
    ])
    .await?
    .success()
    .context("policy set")?;
    Ok(())
}
