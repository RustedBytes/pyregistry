use super::*;
use crate::{
    WheelArchiveSnapshot, WheelAuditFindingKind, WheelSourceSecurityScanResult,
    WheelVirusScanResult,
};
use std::path::Path;

struct FakeReader {
    archive: WheelArchiveSnapshot,
}

impl crate::WheelArchiveReader for FakeReader {
    fn read_wheel(&self, _path: &Path) -> Result<WheelArchiveSnapshot, ApplicationError> {
        Ok(self.archive.clone())
    }

    fn read_wheel_bytes(
        &self,
        _wheel_filename: &str,
        _bytes: &[u8],
    ) -> Result<WheelArchiveSnapshot, ApplicationError> {
        Ok(self.archive.clone())
    }
}

struct FakeVirusScanner;

impl crate::WheelVirusScanner for FakeVirusScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError> {
        let findings = archive
            .entries
            .iter()
            .filter(|entry| entry.contents.windows(5).any(|window| window == b"EICAR"))
            .map(|entry| WheelAuditFinding {
                kind: WheelAuditFindingKind::VirusSignatureMatch,
                path: Some(entry.path.clone()),
                summary: "YARA virus signature matched wheel entry".into(),
                evidence: vec!["rule=Test_EICAR".into()],
            })
            .collect();

        Ok(WheelVirusScanResult {
            scanned_file_count: archive.entries.len(),
            signature_rule_count: 1,
            skipped_rule_count: 0,
            findings,
        })
    }
}

struct FakeSourceSecurityScanner;

impl crate::WheelSourceSecurityScanner for FakeSourceSecurityScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        let findings = archive
            .entries
            .iter()
            .filter(|entry| entry.contents.windows(7).any(|window| window == b"AKIAIOS"))
            .map(|entry| WheelAuditFinding {
                kind: WheelAuditFindingKind::SourceSecurityFinding,
                path: Some(entry.path.clone()),
                summary: "FoxGuard critical finding: possible hardcoded secret".into(),
                evidence: vec!["rule=secret/aws-access-key-id".into()],
            })
            .collect();

        Ok(WheelSourceSecurityScanResult {
            scanned_file_count: archive.entries.len(),
            findings,
        })
    }
}

struct FailingVirusScanner;

impl crate::WheelVirusScanner for FailingVirusScanner {
    fn scan_archive(
        &self,
        _archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError> {
        Err(ApplicationError::External("yara rules unavailable".into()))
    }
}

struct FailingSourceSecurityScanner;

impl crate::WheelSourceSecurityScanner for FailingSourceSecurityScanner {
    fn scan_archive(
        &self,
        _archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        Err(ApplicationError::External(
            "source scanner unavailable".into(),
        ))
    }
}

#[test]
fn reports_requested_audit_signals() {
    let reader = Arc::new(FakeReader {
        archive: WheelArchiveSnapshot {
            wheel_filename: "demo_pkg-0.1.0-py3-none-any.whl".into(),
            entries: vec![
                WheelArchiveEntry {
                    path: "demo_pkg/data/install.sh".into(),
                    contents: b"#!/bin/sh\ncurl https://example.com".to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg/native.bin".into(),
                    contents: b"\x7fELF\0https://evil.example/socket".to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg/startup.pth".into(),
                    contents: b"import sitecustomize".to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg/loader.py".into(),
                    contents: br#"
import requests as http
from subprocess import Popen

def run(payload):
    eval(payload)
    Popen(["sh", "-c", payload])
    http.get("https://example.com/bootstrap")
"#
                    .to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg-0.1.0.dist-info/METADATA".into(),
                    contents: br#"Name: demo-pkg
Requires-Dist: pip>=24
Requires-Dist: helper @ https://example.com/helper.whl
"#
                    .to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg/payload.dat".into(),
                    contents: b"EICAR test payload".to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg/secrets.py".into(),
                    contents: b"AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'".to_vec(),
                },
            ],
        },
    });
    let use_case = WheelAuditUseCase::new(
        reader,
        Arc::new(FakeVirusScanner),
        Arc::new(FakeSourceSecurityScanner),
    );

    let report = use_case
        .audit(AuditWheelCommand {
            project_name: "demo-pkg".into(),
            wheel_path: "demo_pkg-0.1.0-py3-none-any.whl".into(),
        })
        .expect("audit report");

    assert_eq!(report.scanned_file_count, 7);
    assert_eq!(report.source_security_scan.finding_count, 1);
    assert_eq!(report.virus_scan.signature_rule_count, 1);
    assert_eq!(report.virus_scan.match_count, 1);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::UnexpectedExecutable)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::NetworkString)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::PostInstallClue)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::PythonAstSuspiciousBehavior)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::SuspiciousDependency)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::VirusSignatureMatch)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::SourceSecurityFinding)
    );
}

#[test]
fn python_ast_audit_resolves_aliases_and_risky_calls() {
    let findings = python_ast_findings(&[WheelArchiveEntry {
        path: "demo_pkg/worker.py".into(),
        contents: br#"
import ctypes
from urllib.request import urlopen as open_url
from pickle import loads
from os import system as run_shell

def bootstrap(payload):
    open_url("https://example.com/payload")
    loads(payload)
    run_shell("whoami")
    ctypes.CDLL("libnative.so")
"#
        .to_vec(),
    }]);

    assert_eq!(findings.len(), 1);
    let evidence = findings[0].evidence.join("\n");
    assert!(evidence.contains("network call: urllib.request.urlopen"));
    assert!(evidence.contains("unsafe deserialization call: pickle.loads"));
    assert!(evidence.contains("process execution call: os.system"));
    assert!(evidence.contains("native library loading call: ctypes.cdll"));
}

#[test]
fn python_ast_audit_walks_broad_python_syntax() {
    let findings = python_ast_findings(&[WheelArchiveEntry {
        path: "demo_pkg/complex.py".into(),
        contents: br#"
import os as operating_system
from subprocess import *
from urllib.request import urlopen as open_url
from importlib import import_module
from pip._internal.cli.main import main as pip_main
import ctypes

type NativeLoader = ctypes.CDLL

class Base:
    pass

def decorator(*args, **kwargs):
    def wrap(fn):
        return fn
    return wrap

def call():
    return 1

def manager():
    return open(__file__)

pairs = [(1, 2)]
seq = [1, 2]

async def stream(items):
    async for item in items:
        await item
    async with manager() as res:
        yield res

def generator():
    yield from seq
    yield None

@decorator(arg=compile("1", "x", "exec"))
class Demo(Base, option=call()):
    @decorator()
    def method(self, payload: str) -> int:
        global G
        x = 0
        def inner():
            nonlocal x
            x += 1
            return x
        values: list[int] = [n for n in range(3) if n > 0]
        mapping = {k: v for k, v in pairs}
        unique = {item for item in seq}
        generated = (item for item in seq)
        merged = {**{"a": 1}, "b": 2}
        starred = [*seq]
        sliced = seq[0:2:1]
        tuple_value = (values, mapping, unique, generated, merged, starred, sliced)
        try:
            if payload and (captured := payload):
                raise RuntimeError(captured) from None
        except Exception as exc:
            payload = str(exc)
        try:
            pass
        except* Exception as exc:
            payload = str(exc)
        else:
            del values
        finally:
            assert True, "ok"
        formatted = f"{payload!r:>10}"
        match payload:
            case {"items": [1, *rest]} if rest:
                pass
            case Demo(first, second=value):
                pass
            case None | False:
                pass
            case _:
                pass
        with manager() as handle:
            data = handle.read()
        while False:
            break
        for value in [1, 2]:
            continue
        import_module("json")
        pip_main()
        ctypes.CDLL("libnative.so")
        return operating_system.system(formatted) if payload else open_url("https://example.com")
"#
        .to_vec(),
    }]);

    assert_eq!(findings.len(), 1);
    let evidence = findings[0].evidence.join("\n");
    assert!(evidence.contains("dynamic code execution call: compile"));
    assert!(evidence.contains("dynamic import call: importlib.import_module"));
    assert!(evidence.contains("native library loading call: ctypes.cdll"));
    assert!(evidence.contains("network call: urllib.request.urlopen"));
    assert!(evidence.contains("package installer invocation: pip._internal.cli.main.main"));
    assert!(evidence.contains("process execution call: os.system"));
}

#[test]
fn clean_archive_reports_no_findings() {
    let reader = Arc::new(FakeReader {
        archive: WheelArchiveSnapshot {
            wheel_filename: "demo_pkg-0.1.0-py3-none-any.whl".into(),
            entries: vec![
                WheelArchiveEntry {
                    path: "demo_pkg/__init__.py".into(),
                    contents: b"VALUE = 1\n".to_vec(),
                },
                WheelArchiveEntry {
                    path: "demo_pkg-0.1.0.dist-info/METADATA".into(),
                    contents: b"Name: demo-pkg\nRequires-Dist: requests>=2\n".to_vec(),
                },
            ],
        },
    });
    let use_case = WheelAuditUseCase::new(
        reader.clone(),
        Arc::new(FakeVirusScanner),
        Arc::new(FakeSourceSecurityScanner),
    );

    let bytes_archive = reader
        .read_wheel_bytes("demo_pkg-0.1.0-py3-none-any.whl", b"unused")
        .expect("fake reader bytes path");
    assert_eq!(bytes_archive.entries.len(), 2);

    let report = use_case
        .audit(AuditWheelCommand {
            project_name: "demo-pkg".into(),
            wheel_path: "demo_pkg-0.1.0-py3-none-any.whl".into(),
        })
        .expect("clean audit report");

    assert!(report.findings.is_empty());
    assert!(report.source_security_scan.enabled);
    assert_eq!(report.source_security_scan.finding_count, 0);
    assert!(report.virus_scan.enabled);
    assert_eq!(report.virus_scan.match_count, 0);
}

#[test]
fn python_ast_audit_skips_non_python_invalid_large_and_clean_sources() {
    let findings = python_ast_findings(&[
        WheelArchiveEntry {
            path: "demo_pkg/data.txt".into(),
            contents: b"import socket".to_vec(),
        },
        WheelArchiveEntry {
            path: "demo_pkg/huge.py".into(),
            contents: vec![b'a'; MAX_PYTHON_SOURCE_BYTES + 1],
        },
        WheelArchiveEntry {
            path: "demo_pkg/binary.py".into(),
            contents: vec![0xff, 0xfe, 0xfd],
        },
        WheelArchiveEntry {
            path: "demo_pkg/broken.py".into(),
            contents: b"def nope(:\n".to_vec(),
        },
        WheelArchiveEntry {
            path: "demo_pkg/clean.py".into(),
            contents: b"def add(left, right):\n    return left + right\n".to_vec(),
        },
    ]);

    assert!(findings.is_empty());
}

#[test]
fn helper_detectors_cover_edge_cases() {
    assert!(is_script_path("bin/install.ps1"));
    assert!(!is_script_path("package/module.py"));
    assert!(is_known_extension_module("native/module.pyd"));
    assert!(has_shebang(b"#!/usr/bin/env python\n"));
    assert!(looks_like_executable_binary(b"MZbinary"));
    assert!(looks_like_executable_binary(&[0xfe, 0xed, 0xfa, 0xce]));
    assert!(looks_like_executable_binary(&[0xfe, 0xed, 0xfa, 0xcf]));
    assert!(looks_like_executable_binary(&[0xcf, 0xfa, 0xed, 0xfe]));
    assert!(looks_like_executable_binary(&[0xca, 0xfe, 0xba, 0xbe]));
    assert!(
        !unexpected_executable_findings(&[WheelArchiveEntry {
            path: "demo_pkg/native.pyd".into(),
            contents: b"MZbinary".to_vec(),
        }])
        .iter()
        .any(|finding| finding
            .evidence
            .iter()
            .any(|item| item == "native executable header"))
    );

    assert!(is_binary_content(b"abc\0https://example"));
    assert!(is_binary_content(&[0x01, 0x02, 0x03, b'a', b'b']));
    assert!(!is_binary_content(b"plain text"));
    assert_eq!(ascii_strings(b"\0abcd\x01efgh\x02"), "abcd\nefgh");
    assert_eq!(
        find_patterns("curl wget socket", &["curl", "wget", "socket"], 2),
        vec!["curl".to_string(), "wget".to_string()]
    );
    assert_eq!(
        metadata_field("Name: demo\nVersion: 1.0.0\n", "Name"),
        Some("demo")
    );
    assert_eq!(
        dependency_name("Requests[security]>=2; python_version > '3'"),
        Some("requests".into())
    );
    assert_eq!(dependency_name("   "), None);
}

#[test]
fn direct_classifiers_cover_security_keyword_matrix() {
    for module in [
        "pty",
        "socket",
        "http.client",
        "ftplib",
        "smtplib",
        "requests",
        "httpx",
        "aiohttp",
        "paramiko",
        "cffi",
        "mmap",
        "marshal",
        "shelve",
        "dill",
        "cloudpickle",
        "ensurepip",
    ] {
        assert!(
            import_evidence(module).is_some(),
            "{module} should be classified"
        );
    }
    assert!(import_evidence("json").is_none());

    for call in [
        "eval",
        "__import__",
        "os.popen",
        "os.execv",
        "os.spawnv",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "pty.spawn",
        "socket.socket",
        "socket.create_connection",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "ftplib.FTP",
        "smtplib.SMTP",
        "requests.post",
        "httpx.delete",
        "aiohttp.request",
        "paramiko.SSHClient",
        "ctypes.windll.LoadLibrary",
        "pickle.load",
        "marshal.loads",
        "shelve.open",
        "dill.load",
        "cloudpickle.loads",
        "pip.main",
        "ensurepip.bootstrap",
    ] {
        assert!(call_evidence(call).is_some(), "{call} should be classified");
    }
    assert!(call_evidence("json.loads").is_none());
    assert!(network_client_call("requests.get", "requests"));
    assert!(!network_client_call("requests.session", "requests"));
    assert!(!network_client_call("httpx.get", "requests"));
    assert!(native_library_loading_call("ctypes.cdll.load_library"));
    assert!(native_library_loading_call("ctypes.foo.loadlibrary"));
}

#[test]
fn scanner_failures_are_reported_without_hiding_local_findings() {
    let reader = Arc::new(FakeReader {
        archive: WheelArchiveSnapshot {
            wheel_filename: "demo_pkg-0.1.0-py3-none-any.whl".into(),
            entries: vec![WheelArchiveEntry {
                path: "demo_pkg/startup.pth".into(),
                contents: b"import sitecustomize".to_vec(),
            }],
        },
    });
    let use_case = WheelAuditUseCase::new(
        reader,
        Arc::new(FailingVirusScanner),
        Arc::new(FailingSourceSecurityScanner),
    );

    let report = use_case
        .audit(AuditWheelCommand {
            project_name: "demo-pkg".into(),
            wheel_path: "demo_pkg-0.1.0-py3-none-any.whl".into(),
        })
        .expect("audit should still produce report");

    assert_eq!(report.scanned_file_count, 1);
    assert!(!report.source_security_scan.enabled);
    assert_eq!(
        report.source_security_scan.scan_error.as_deref(),
        Some("external dependency failure: source scanner unavailable")
    );
    assert!(!report.virus_scan.enabled);
    assert_eq!(
        report.virus_scan.scan_error.as_deref(),
        Some("external dependency failure: yara rules unavailable")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == WheelAuditFindingKind::PostInstallClue)
    );
}
