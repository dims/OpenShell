// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The result bundle of a run: `run.json`, `junit.xml` and `SHA256SUMS`.
//!
//! `run --output-dir DIR` writes the bundle. `run.json` records what was
//! tested (the gateway, its compute drivers and extensions, the CLI), what
//! tested it (this program and the selection), and each test's result.
//! `junit.xml` is the report `--junit` writes. `SHA256SUMS` covers both, in
//! the format `sha256sum --check` reads. Both result files carry the run ID,
//! so the files of one run can be told from another's.
//!
//! The gateway and the CLI are read before the first test, so a gateway that
//! stops during the run is still recorded. A fact that cannot be read is
//! recorded as an error and does not fail the run: `GetGatewayInfo`, which
//! names the compute driver, needs a role an ordinary user may not have.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use openshell_sdk::OpenShellClient;
use openshell_sdk::raw::proto;
use quick_junit::Report;
use serde::Serialize;

use super::junit;
use super::supervisor::{Options, Outcome, TestRun};
use crate::cli::Cli;
use crate::error::ResultExt as _;
use crate::gateway::Gateway;
use crate::image::{BASE_IMAGE_ENV, PYTHON_IMAGE_ENV};

pub const MANIFEST_FILE: &str = "run.json";
pub const JUNIT_FILE: &str = "junit.xml";
pub const CHECKSUMS_FILE: &str = "SHA256SUMS";

/// The layout of `run.json`. Raise it when a field changes meaning.
const SCHEMA_VERSION: u32 = 1;
/// How long reading the gateway may take before the run goes on without it.
const FACTS_TIMEOUT: Duration = Duration::from_secs(30);
/// Settings that choose what the tests run, recorded when set.
const RECORDED_ENV: [&str; 2] = [BASE_IMAGE_ENV, PYTHON_IMAGE_ENV];

/// `run.json`: one run of the program against one gateway.
#[derive(Debug, Serialize)]
pub struct Manifest {
    schema_version: u32,
    run_id: String,
    started_at: String,
    finished_at: String,
    duration_seconds: f64,
    runner: Runner,
    gateway: GatewayFacts,
    cli: CliFacts,
    selection: SelectionFacts,
    environment: BTreeMap<&'static str, String>,
    totals: Totals,
    /// The exit code the test results give: 0, 1 or 2 as `run` documents.
    exit_code: u8,
    tests: Vec<TestResult>,
}

/// This program.
#[derive(Debug, Serialize)]
struct Runner {
    program: String,
    /// The version of the OpenShell source the program was built from.
    version: &'static str,
    /// SHA-256 of the program file.
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    os: &'static str,
    arch: &'static str,
    timeout_seconds: f64,
    grace_seconds: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

/// The gateway under test, as the tests find it.
#[derive(Debug, Default, Serialize)]
struct GatewayFacts {
    /// The name it is registered under with the CLI, if it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<&'static str>,
    /// From `Health`.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// From `GetGatewayInfo`; absent when the caller may not read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<GatewayInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

impl GatewayFacts {
    fn failed(error: String) -> Self {
        Self {
            errors: vec![error],
            ..Self::default()
        }
    }
}

#[derive(Debug, Serialize)]
struct GatewayInfo {
    gateway_version: String,
    compute_drivers: Vec<ComputeDriver>,
    extensions: Vec<Extension>,
}

#[derive(Debug, Serialize)]
struct ComputeDriver {
    /// The name the gateway selects the driver by.
    name: String,
    /// What the driver reports about itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    driver_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    driver_version: Option<String>,
}

/// One extension the gateway negotiated with at startup.
#[derive(Debug, Serialize)]
struct Extension {
    kind: String,
    configured_name: String,
    implementation_name: String,
    implementation_version: String,
    protocol: String,
    supported_capabilities: Vec<String>,
    required_capabilities: Vec<String>,
}

/// The `openshell` CLI the tests run.
#[derive(Debug, Default, Serialize)]
struct CliFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

/// Which tests were asked for.
#[derive(Debug, Serialize)]
struct SelectionFacts {
    filters: Vec<String>,
    include_ignored: bool,
    /// The `OPENSHELL_TEST_UNSUPPORTED` entries in force.
    unsupported: Vec<UnsupportedEntry>,
}

#[derive(Debug, Serialize)]
struct UnsupportedEntry {
    test: String,
    issue: String,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct Totals {
    selected: usize,
    passed: usize,
    /// Failed or timed out.
    failed: usize,
    /// Could not run, or interrupted.
    errors: usize,
    /// Ignored and not asked for.
    skipped: usize,
    unsupported: usize,
    /// Selected, but the run was interrupted first.
    not_run: usize,
}

impl Totals {
    fn of(runs: &[TestRun<'_>], not_run: usize) -> Self {
        let mut totals = Self {
            selected: runs.len() + not_run,
            not_run,
            ..Self::default()
        };
        for run in runs {
            match &run.outcome {
                Outcome::Passed => totals.passed += 1,
                Outcome::Failed(_) | Outcome::TimedOut(_) => totals.failed += 1,
                Outcome::Error(_) | Outcome::Interrupted => totals.errors += 1,
                Outcome::Skipped => totals.skipped += 1,
                Outcome::Unsupported(_) => totals.unsupported += 1,
            }
        }
        totals
    }
}

#[derive(Debug, Serialize)]
struct TestResult {
    name: String,
    family: &'static str,
    description: &'static str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Absent for a test that did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<f64>,
}

impl TestResult {
    fn of(run: &TestRun<'_>) -> Self {
        Self {
            name: run.test.name(),
            family: run.test.family(),
            description: run.test.info.description,
            outcome: outcome_name(&run.outcome),
            message: run.outcome.message().map(Cow::into_owned),
            duration_seconds: run.duration.map(seconds),
        }
    }
}

const fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Passed => "passed",
        Outcome::Skipped => "skipped",
        Outcome::Unsupported(_) => "unsupported",
        Outcome::Failed(_) => "failed",
        Outcome::TimedOut(_) => "timed_out",
        Outcome::Error(_) => "error",
        Outcome::Interrupted => "interrupted",
    }
}

/// What is known before the first test runs.
pub struct Start {
    run_id: String,
    started: SystemTime,
    runner: Runner,
    gateway: GatewayFacts,
    cli: CliFacts,
    selection: SelectionFacts,
    environment: BTreeMap<&'static str, String>,
}

impl Start {
    /// Read this program, the gateway and the CLI. What cannot be read is
    /// recorded as an error, so this never fails.
    pub fn collect(program: &str, exe: &Path, options: &Options) -> Self {
        let started = SystemTime::now();
        let mut runner = Runner {
            program: program.to_string(),
            version: openshell_core::VERSION,
            sha256: None,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            timeout_seconds: seconds(options.timeout),
            grace_seconds: seconds(options.grace),
            errors: Vec::new(),
        };
        match file_sha256(exe) {
            Ok(digest) => runner.sha256 = Some(digest),
            Err(error) => runner
                .errors
                .push(format!("hash {}: {error}", exe.display())),
        }
        let (gateway, cli) = target();
        Self {
            run_id: crate::context::generate_run_id(),
            started,
            runner,
            gateway,
            cli,
            selection: SelectionFacts {
                filters: options.selection.filters.clone(),
                include_ignored: options.selection.include_ignored,
                unsupported: options
                    .selection
                    .unsupported
                    .entries()
                    .map(|(test, issue)| UnsupportedEntry {
                        test: test.to_string(),
                        issue: issue.to_string(),
                    })
                    .collect(),
            },
            environment: RECORDED_ENV
                .into_iter()
                .filter_map(|name| {
                    let value = std::env::var(name).ok()?;
                    (!value.trim().is_empty()).then_some((name, value))
                })
                .collect(),
        }
    }

    /// The ID of this run, which `run.json` and `junit.xml` both carry.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Add the results. `exit_code` is the one the test results give.
    pub fn finish(self, runs: &[TestRun<'_>], not_run: usize, exit_code: u8) -> Manifest {
        let finished = SystemTime::now();
        Manifest {
            schema_version: SCHEMA_VERSION,
            run_id: self.run_id,
            started_at: rfc3339(self.started),
            finished_at: rfc3339(finished),
            duration_seconds: seconds(finished.duration_since(self.started).unwrap_or_default()),
            runner: self.runner,
            gateway: self.gateway,
            cli: self.cli,
            selection: self.selection,
            environment: self.environment,
            totals: Totals::of(runs, not_run),
            exit_code,
            tests: runs.iter().map(TestResult::of).collect(),
        }
    }
}

/// The gateway and the CLI, found as the tests find them.
fn target() -> (GatewayFacts, CliFacts) {
    let gateway = match Gateway::from_env() {
        Ok(gateway) => gateway,
        Err(error) => {
            return (
                GatewayFacts::failed(format!("find the gateway: {error}")),
                CliFacts::default(),
            );
        }
    };
    let mut facts = GatewayFacts {
        name: gateway.name.clone(),
        endpoint: Some(gateway.endpoint.clone()),
        workspace: Some(gateway.workspace.clone()),
        auth: Some(gateway.auth()),
        ..GatewayFacts::default()
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            facts
                .errors
                .push(format!("start the async runtime: {error}"));
            return (facts, CliFacts::default());
        }
    };
    let cli = runtime.block_on(async {
        let read = tokio::time::timeout(FACTS_TIMEOUT, read_gateway(&gateway, &mut facts)).await;
        if read.is_err() {
            facts.errors.push(format!(
                "reading the gateway took longer than {}s",
                FACTS_TIMEOUT.as_secs()
            ));
        }
        read_cli(&gateway).await
    });
    (facts, cli)
}

async fn read_gateway(gateway: &Gateway, facts: &mut GatewayFacts) {
    let client = match gateway.connect().await {
        Ok(client) => client,
        Err(error) => {
            facts.errors.push(error.to_string());
            return;
        }
    };
    match client.health().await {
        Ok(health) => facts.version = Some(health.version),
        Err(error) => facts.errors.push(format!("health: {error}")),
    }
    match gateway_info(&client).await {
        Ok(info) => facts.info = Some(info),
        Err(error) => facts.errors.push(error.to_string()),
    }
}

async fn gateway_info(client: &OpenShellClient) -> crate::Result<GatewayInfo> {
    let info = client
        .raw_grpc_fresh()
        .await?
        .get_gateway_info(proto::GetGatewayInfoRequest {})
        .await
        .context("get gateway info")?
        .into_inner();
    Ok(GatewayInfo {
        gateway_version: info.gateway_version,
        compute_drivers: info
            .compute_drivers
            .into_iter()
            .map(|driver| {
                let (driver_name, driver_version) = driver
                    .capabilities
                    .map(|reported| (reported.driver_name, reported.driver_version))
                    .unzip();
                ComputeDriver {
                    name: driver.name,
                    driver_name,
                    driver_version,
                }
            })
            .collect(),
        extensions: info
            .extensions
            .into_iter()
            .map(|extension| Extension {
                kind: proto::ExtensionKind::try_from(extension.kind).map_or_else(
                    |_| extension.kind.to_string(),
                    |kind| kind.as_str_name().to_string(),
                ),
                configured_name: extension.configured_name,
                implementation_name: extension.implementation_name,
                implementation_version: extension.implementation_version,
                protocol: format!("{}.{}", extension.protocol_major, extension.protocol_minor),
                supported_capabilities: extension.supported_capabilities,
                required_capabilities: extension.required_capabilities,
            })
            .collect(),
    })
}

async fn read_cli(gateway: &Gateway) -> CliFacts {
    let cli = Cli::from_env(gateway);
    let mut facts = CliFacts {
        path: Some(cli.binary().display().to_string()),
        ..CliFacts::default()
    };
    match cli.run(["--version"]).await {
        Ok(output) if output.exit_code == 0 => {
            facts.version = Some(output.stdout.trim().to_string());
        }
        Ok(output) => facts.errors.push(format!(
            "`{}` exited with code {}",
            output.command, output.exit_code
        )),
        Err(error) => facts.errors.push(error.to_string()),
    }
    facts
}

/// Write the bundle into `dir`, creating it.
pub fn write(dir: &Path, manifest: &Manifest, report: &Report) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    junit::write(&dir.join(JUNIT_FILE), report)?;
    let mut json = serde_json::to_vec_pretty(manifest).map_err(std::io::Error::other)?;
    json.push(b'\n');
    std::fs::write(dir.join(MANIFEST_FILE), json)?;
    let mut sums = String::new();
    for name in [JUNIT_FILE, MANIFEST_FILE] {
        let _ = writeln!(sums, "{}  {name}", file_sha256(&dir.join(name))?);
    }
    std::fs::write(dir.join(CHECKSUMS_FILE), sums)
}

fn file_sha256(path: &Path) -> std::io::Result<String> {
    let crypto = |error: openshell_crypto::CryptoError| std::io::Error::other(error.to_string());
    let mut file = std::fs::File::open(path)?;
    let mut digest = openshell_crypto::sha256_digest().map_err(crypto)?;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]).map_err(crypto)?;
    }
    digest.finish().map(|bytes| hex(&bytes)).map_err(crypto)
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Seconds, to the millisecond.
fn seconds(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 1000.0).round() / 1000.0
}

fn rfc3339(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        CHECKSUMS_FILE, CliFacts, GatewayFacts, JUNIT_FILE, MANIFEST_FILE, Runner, SelectionFacts,
        Start, hex, rfc3339, write,
    };
    use crate::program::junit;
    use crate::program::supervisor::{Outcome, TestRun};
    use crate::registry::Test;
    use crate::registry::tests::test;

    const FIRST: Test = test("suite::m", "first", false);
    const SECOND: Test = test("suite::m", "second", false);
    const LATER: Test = test("suite::m", "later", true);

    fn start() -> Start {
        Start {
            run_id: "run12345".to_string(),
            started: SystemTime::now(),
            runner: Runner {
                program: "openshell-conformance".to_string(),
                version: "0.0.0",
                sha256: Some("00".repeat(32)),
                os: "linux",
                arch: "x86_64",
                timeout_seconds: 900.0,
                grace_seconds: 10.0,
                errors: Vec::new(),
            },
            gateway: GatewayFacts {
                endpoint: Some("http://127.0.0.1:8080".to_string()),
                auth: Some("plaintext"),
                version: Some("1.2.3".to_string()),
                ..GatewayFacts::default()
            },
            cli: CliFacts::default(),
            selection: SelectionFacts {
                filters: vec!["m::".to_string()],
                include_ignored: false,
                unsupported: Vec::new(),
            },
            environment: BTreeMap::new(),
        }
    }

    fn run(test: &'static Test, outcome: Outcome, millis: Option<u64>) -> TestRun<'static> {
        TestRun {
            test,
            outcome,
            duration: millis.map(Duration::from_millis),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn runs() -> Vec<TestRun<'static>> {
        vec![
            run(&FIRST, Outcome::Passed, Some(1234)),
            run(
                &SECOND,
                Outcome::TimedOut("timed out after 1s".into()),
                Some(1000),
            ),
            run(&LATER, Outcome::Skipped, None),
        ]
    }

    #[test]
    fn manifest_records_the_run_and_every_result() {
        let manifest = serde_json::to_value(start().finish(&runs(), 2, 2)).unwrap();
        assert_eq!(manifest["schema_version"], 1);
        assert_eq!(manifest["run_id"], "run12345");
        assert_eq!(manifest["exit_code"], 2);
        assert_eq!(
            manifest["totals"],
            serde_json::json!({
                "selected": 5,
                "passed": 1,
                "failed": 1,
                "errors": 0,
                "skipped": 1,
                "unsupported": 0,
                "not_run": 2,
            })
        );
        assert_eq!(
            manifest["tests"],
            serde_json::json!([
                {
                    "name": "m::first",
                    "family": "conformance",
                    "description": "A test.",
                    "outcome": "passed",
                    "duration_seconds": 1.234,
                },
                {
                    "name": "m::second",
                    "family": "conformance",
                    "description": "A test.",
                    "outcome": "timed_out",
                    "message": "timed out after 1s",
                    "duration_seconds": 1.0,
                },
                {
                    "name": "m::later",
                    "family": "conformance",
                    "description": "A test.",
                    "outcome": "skipped",
                },
            ])
        );
        // What could not be read is left out, not written as null.
        assert_eq!(
            manifest["gateway"],
            serde_json::json!({
                "endpoint": "http://127.0.0.1:8080",
                "auth": "plaintext",
                "version": "1.2.3",
            })
        );
        assert_eq!(manifest["cli"], serde_json::json!({}));
    }

    #[test]
    fn bundle_files_share_the_run_id_and_match_their_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("nested").join("bundle");
        let start = start();
        let runs = runs();
        let report = junit::report("openshell-conformance", &runs, Some(start.run_id()));
        write(&bundle, &start.finish(&runs, 0, 1), &report).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(manifest["run_id"], "run12345");
        let xml = std::fs::read_to_string(bundle.join(JUNIT_FILE)).unwrap();
        assert!(
            xml.contains(r#"<property name="run-id" value="run12345"/>"#),
            "{xml}"
        );

        let sums = std::fs::read_to_string(bundle.join(CHECKSUMS_FILE)).unwrap();
        let expected: String = [JUNIT_FILE, MANIFEST_FILE]
            .into_iter()
            .map(|name| {
                let digest =
                    openshell_crypto::sha256(&std::fs::read(bundle.join(name)).unwrap()).unwrap();
                format!("{}  {name}\n", hex(&digest))
            })
            .collect();
        assert_eq!(sums, expected);
    }

    #[test]
    fn timestamps_are_utc_rfc3339() {
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
