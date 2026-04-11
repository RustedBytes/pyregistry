use crate::{
    ApplicationError, AuditStoredWheelCommand, AuditWheelCommand, WheelArchiveEntry,
    WheelArchiveReader, WheelAuditFinding, WheelAuditFindingKind, WheelAuditReport,
    WheelSourceSecurityScanSummary, WheelSourceSecurityScanner, WheelVirusScanSummary,
    WheelVirusScanner,
};
use log::{debug, info, warn};
use pyregistry_domain::ProjectName;
use rustpython_parser::{Parse, ast};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const MAX_PYTHON_AST_EVIDENCE: usize = 12;
const MAX_PYTHON_SOURCE_BYTES: usize = 1024 * 1024;

pub struct WheelAuditUseCase {
    archive_reader: Arc<dyn WheelArchiveReader>,
    virus_scanner: Arc<dyn WheelVirusScanner>,
    source_security_scanner: Arc<dyn WheelSourceSecurityScanner>,
}

impl WheelAuditUseCase {
    #[must_use]
    pub fn new(
        archive_reader: Arc<dyn WheelArchiveReader>,
        virus_scanner: Arc<dyn WheelVirusScanner>,
        source_security_scanner: Arc<dyn WheelSourceSecurityScanner>,
    ) -> Self {
        Self {
            archive_reader,
            virus_scanner,
            source_security_scanner,
        }
    }

    pub fn audit(&self, command: AuditWheelCommand) -> Result<WheelAuditReport, ApplicationError> {
        info!(
            "auditing wheel `{}` for project `{}`",
            command.wheel_path.display(),
            command.project_name
        );
        let archive = self.archive_reader.read_wheel(&command.wheel_path)?;
        self.audit_archive(command.project_name, archive)
    }

    pub(crate) fn audit_archive(
        &self,
        project_name: String,
        archive: crate::WheelArchiveSnapshot,
    ) -> Result<WheelAuditReport, ApplicationError> {
        let expected_project = ProjectName::new(project_name.clone())?;
        debug!(
            "loaded wheel archive `{}` with {} file(s)",
            archive.wheel_filename,
            archive.entries.len()
        );

        let mut findings = Vec::new();
        findings.extend(unexpected_executable_findings(&archive.entries));
        findings.extend(network_string_findings(&archive.entries));
        findings.extend(post_install_findings(&archive.entries));
        findings.extend(python_ast_findings(&archive.entries));
        findings.extend(suspicious_dependency_findings(
            &archive.entries,
            expected_project.normalized(),
        ));
        let source_security_scan = match self.source_security_scanner.scan_archive(&archive) {
            Ok(result) => {
                if result.findings.is_empty() {
                    info!(
                        "source security scan completed for `{}` with no findings (files={})",
                        archive.wheel_filename, result.scanned_file_count
                    );
                } else {
                    warn!(
                        "source security scan found {} issue(s) in `{}`",
                        result.findings.len(),
                        archive.wheel_filename
                    );
                }
                let summary = WheelSourceSecurityScanSummary::from_result(&result);
                findings.extend(result.findings);
                summary
            }
            Err(error) => {
                warn!(
                    "source security scan did not complete for `{}`: {}",
                    archive.wheel_filename, error
                );
                WheelSourceSecurityScanSummary::failed(error.to_string())
            }
        };
        let virus_scan = match self.virus_scanner.scan_archive(&archive) {
            Ok(result) => {
                if result.findings.is_empty() {
                    info!(
                        "YARA virus scan completed for `{}` with no signature matches (rules={}, skipped={})",
                        archive.wheel_filename,
                        result.signature_rule_count,
                        result.skipped_rule_count
                    );
                } else {
                    warn!(
                        "YARA virus scan matched {} signature(s) in `{}`",
                        result.findings.len(),
                        archive.wheel_filename
                    );
                }
                let summary = WheelVirusScanSummary::from_result(&result);
                findings.extend(result.findings);
                summary
            }
            Err(error) => {
                warn!(
                    "YARA virus scan did not complete for `{}`: {}",
                    archive.wheel_filename, error
                );
                WheelVirusScanSummary::failed(error.to_string())
            }
        };

        if findings.is_empty() {
            info!(
                "wheel audit completed for `{}` with no suspicious findings",
                archive.wheel_filename
            );
        } else {
            warn!(
                "wheel audit completed for `{}` with {} finding(s)",
                archive.wheel_filename,
                findings.len()
            );
        }

        Ok(WheelAuditReport {
            project_name,
            wheel_filename: archive.wheel_filename,
            scanned_file_count: archive.entries.len(),
            source_security_scan,
            virus_scan,
            findings,
        })
    }
}

impl crate::PyregistryApp {
    pub async fn audit_stored_wheel(
        &self,
        command: AuditStoredWheelCommand,
    ) -> Result<WheelAuditReport, ApplicationError> {
        info!(
            "auditing stored artifact `{}` for tenant `{}` project `{}` version `{}`",
            command.filename, command.tenant_slug, command.project_name, command.version
        );
        if !command.filename.ends_with(".whl") {
            return Err(ApplicationError::Conflict(format!(
                "artifact `{}` is not a wheel file",
                command.filename
            )));
        }

        let artifact = self
            .find_artifact(
                &command.tenant_slug,
                &command.project_name,
                &command.version,
                &command.filename,
            )
            .await?;
        let bytes = self
            .download_artifact(
                &command.tenant_slug,
                &command.project_name,
                &command.version,
                &command.filename,
            )
            .await?;

        let archive = self
            .wheel_archive_reader
            .read_wheel_bytes(&artifact.filename, &bytes)?;
        WheelAuditUseCase::new(
            self.wheel_archive_reader.clone(),
            self.wheel_virus_scanner.clone(),
            self.wheel_source_security_scanner.clone(),
        )
        .audit_archive(command.project_name, archive)
    }
}

fn unexpected_executable_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        let path = entry.path.to_ascii_lowercase();
        let mut evidence = Vec::new();

        if is_script_path(&path) {
            evidence.push("script-like filename".into());
        }
        if path.contains(".data/scripts/") {
            evidence.push("installed script payload".into());
        }
        if has_shebang(&entry.contents) {
            evidence.push("shebang header".into());
        }
        if looks_like_executable_binary(&entry.contents) && !is_known_extension_module(&path) {
            evidence.push("native executable header".into());
        }

        if !evidence.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::UnexpectedExecutable,
                path: Some(entry.path.clone()),
                summary: "unexpected executable or shell-oriented payload found".into(),
                evidence,
            });
        }
    }

    findings
}

fn network_string_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        if !is_binary_content(&entry.contents) {
            continue;
        }

        let matches = find_patterns(
            &ascii_strings(&entry.contents),
            &[
                "http://",
                "https://",
                "socket",
                "connect(",
                "connect ",
                "webhook",
                "curl",
                "wget",
                "invoke-webrequest",
                "powershell",
                "ws://",
                "wss://",
                "urllib",
                "requests",
                "tcp",
                "udp",
            ],
            4,
        );

        if !matches.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::NetworkString,
                path: Some(entry.path.clone()),
                summary: "binary payload contains network-related strings".into(),
                evidence: matches,
            });
        }
    }

    findings
}

fn post_install_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        let path = entry.path.to_ascii_lowercase();
        let mut evidence = Vec::new();

        if path.ends_with(".pth") {
            evidence.push("`.pth` file executes import-time code".into());
        }
        if path.ends_with("sitecustomize.py") || path.ends_with("usercustomize.py") {
            evidence.push("Python startup hook".into());
        }
        if path.ends_with("entry_points.txt") {
            evidence.push("entry point definitions present".into());
        }
        if path.contains(".data/scripts/") {
            evidence.push("script installed into environment".into());
        }

        if !path.ends_with(".py") {
            let content_text = String::from_utf8_lossy(&entry.contents);
            let text_matches = find_patterns(
                &content_text,
                &[
                    "subprocess",
                    "os.system",
                    "pip._internal",
                    "sitecustomize",
                    "usercustomize",
                    "atexit",
                    "exec(",
                    "eval(",
                ],
                4,
            );
            evidence.extend(text_matches);
        }

        if !evidence.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::PostInstallClue,
                path: Some(entry.path.clone()),
                summary: "package contents include post-install or startup behavior clues".into(),
                evidence,
            });
        }
    }

    findings
}

fn python_ast_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        if !entry.path.to_ascii_lowercase().ends_with(".py") {
            continue;
        }
        if entry.contents.len() > MAX_PYTHON_SOURCE_BYTES {
            debug!(
                "skipping RustPython AST audit for `{}` because source is larger than {} bytes",
                entry.path, MAX_PYTHON_SOURCE_BYTES
            );
            continue;
        }

        let Ok(source) = std::str::from_utf8(&entry.contents) else {
            debug!(
                "skipping RustPython AST audit for `{}` because source is not UTF-8",
                entry.path
            );
            continue;
        };

        let suite = match ast::Suite::parse(source, &entry.path) {
            Ok(suite) => suite,
            Err(error) => {
                debug!(
                    "RustPython AST audit could not parse `{}`: {}",
                    entry.path, error
                );
                continue;
            }
        };

        let mut analyzer = PythonAstAnalyzer::default();
        analyzer.visit_suite(&suite);
        let evidence = analyzer.into_evidence();
        if evidence.is_empty() {
            continue;
        }

        debug!(
            "RustPython AST audit found {} suspicious signal(s) in `{}`",
            evidence.len(),
            entry.path
        );
        findings.push(WheelAuditFinding {
            kind: WheelAuditFindingKind::PythonAstSuspiciousBehavior,
            path: Some(entry.path.clone()),
            summary: "Python source contains suspicious imports or runtime behavior".into(),
            evidence,
        });
    }

    findings
}

#[derive(Default)]
struct PythonAstAnalyzer {
    import_aliases: BTreeMap<String, String>,
    evidence: BTreeSet<String>,
}

impl PythonAstAnalyzer {
    fn visit_suite(&mut self, suite: &[ast::Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::FunctionDef(function_def) => {
                for decorator in &function_def.decorator_list {
                    self.visit_expr(decorator);
                }
                if let Some(returns) = function_def.returns.as_deref() {
                    self.visit_expr(returns);
                }
                self.visit_suite(&function_def.body);
            }
            ast::Stmt::AsyncFunctionDef(function_def) => {
                for decorator in &function_def.decorator_list {
                    self.visit_expr(decorator);
                }
                if let Some(returns) = function_def.returns.as_deref() {
                    self.visit_expr(returns);
                }
                self.visit_suite(&function_def.body);
            }
            ast::Stmt::ClassDef(class_def) => {
                for base in &class_def.bases {
                    self.visit_expr(base);
                }
                for keyword in &class_def.keywords {
                    self.visit_expr(&keyword.value);
                }
                for decorator in &class_def.decorator_list {
                    self.visit_expr(decorator);
                }
                self.visit_suite(&class_def.body);
            }
            ast::Stmt::Return(return_stmt) => {
                if let Some(value) = return_stmt.value.as_deref() {
                    self.visit_expr(value);
                }
            }
            ast::Stmt::Delete(delete_stmt) => {
                for target in &delete_stmt.targets {
                    self.visit_expr(target);
                }
            }
            ast::Stmt::Assign(assign_stmt) => {
                for target in &assign_stmt.targets {
                    self.visit_expr(target);
                }
                self.visit_expr(&assign_stmt.value);
            }
            ast::Stmt::TypeAlias(type_alias) => {
                self.visit_expr(&type_alias.name);
                self.visit_expr(&type_alias.value);
            }
            ast::Stmt::AugAssign(assign_stmt) => {
                self.visit_expr(&assign_stmt.target);
                self.visit_expr(&assign_stmt.value);
            }
            ast::Stmt::AnnAssign(assign_stmt) => {
                self.visit_expr(&assign_stmt.target);
                self.visit_expr(&assign_stmt.annotation);
                if let Some(value) = assign_stmt.value.as_deref() {
                    self.visit_expr(value);
                }
            }
            ast::Stmt::For(for_stmt) => {
                self.visit_expr(&for_stmt.target);
                self.visit_expr(&for_stmt.iter);
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
            }
            ast::Stmt::AsyncFor(for_stmt) => {
                self.visit_expr(&for_stmt.target);
                self.visit_expr(&for_stmt.iter);
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
            }
            ast::Stmt::While(while_stmt) => {
                self.visit_expr(&while_stmt.test);
                self.visit_suite(&while_stmt.body);
                self.visit_suite(&while_stmt.orelse);
            }
            ast::Stmt::If(if_stmt) => {
                self.visit_expr(&if_stmt.test);
                self.visit_suite(&if_stmt.body);
                self.visit_suite(&if_stmt.orelse);
            }
            ast::Stmt::With(with_stmt) => {
                self.visit_with_items(&with_stmt.items);
                self.visit_suite(&with_stmt.body);
            }
            ast::Stmt::AsyncWith(with_stmt) => {
                self.visit_with_items(&with_stmt.items);
                self.visit_suite(&with_stmt.body);
            }
            ast::Stmt::Match(match_stmt) => {
                self.visit_expr(&match_stmt.subject);
                for case in &match_stmt.cases {
                    self.visit_pattern(&case.pattern);
                    if let Some(guard) = case.guard.as_deref() {
                        self.visit_expr(guard);
                    }
                    self.visit_suite(&case.body);
                }
            }
            ast::Stmt::Raise(raise_stmt) => {
                if let Some(exc) = raise_stmt.exc.as_deref() {
                    self.visit_expr(exc);
                }
                if let Some(cause) = raise_stmt.cause.as_deref() {
                    self.visit_expr(cause);
                }
            }
            ast::Stmt::Try(try_stmt) => {
                self.visit_suite(&try_stmt.body);
                self.visit_except_handlers(&try_stmt.handlers);
                self.visit_suite(&try_stmt.orelse);
                self.visit_suite(&try_stmt.finalbody);
            }
            ast::Stmt::TryStar(try_stmt) => {
                self.visit_suite(&try_stmt.body);
                self.visit_except_handlers(&try_stmt.handlers);
                self.visit_suite(&try_stmt.orelse);
                self.visit_suite(&try_stmt.finalbody);
            }
            ast::Stmt::Assert(assert_stmt) => {
                self.visit_expr(&assert_stmt.test);
                if let Some(msg) = assert_stmt.msg.as_deref() {
                    self.visit_expr(msg);
                }
            }
            ast::Stmt::Import(import_stmt) => {
                for alias in &import_stmt.names {
                    self.record_import(
                        alias.name.as_str(),
                        alias.asname.as_ref().map(|name| name.as_str()),
                    );
                }
            }
            ast::Stmt::ImportFrom(import_stmt) => {
                if let Some(module) = &import_stmt.module {
                    for alias in &import_stmt.names {
                        self.record_from_import(
                            module.as_str(),
                            alias.name.as_str(),
                            alias.asname.as_ref().map(|name| name.as_str()),
                        );
                    }
                }
            }
            ast::Stmt::Expr(expr_stmt) => self.visit_expr(&expr_stmt.value),
            ast::Stmt::Global(_)
            | ast::Stmt::Nonlocal(_)
            | ast::Stmt::Pass(_)
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue(_) => {}
        }
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        match expr {
            ast::Expr::BoolOp(expr) => {
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::NamedExpr(expr) => {
                self.visit_expr(&expr.target);
                self.visit_expr(&expr.value);
            }
            ast::Expr::BinOp(expr) => {
                self.visit_expr(&expr.left);
                self.visit_expr(&expr.right);
            }
            ast::Expr::UnaryOp(expr) => self.visit_expr(&expr.operand),
            ast::Expr::Lambda(expr) => self.visit_expr(&expr.body),
            ast::Expr::IfExp(expr) => {
                self.visit_expr(&expr.test);
                self.visit_expr(&expr.body);
                self.visit_expr(&expr.orelse);
            }
            ast::Expr::Dict(expr) => {
                for key in expr.keys.iter().flatten() {
                    self.visit_expr(key);
                }
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::Set(expr) => {
                for element in &expr.elts {
                    self.visit_expr(element);
                }
            }
            ast::Expr::ListComp(expr) => {
                self.visit_expr(&expr.elt);
                self.visit_comprehensions(&expr.generators);
            }
            ast::Expr::SetComp(expr) => {
                self.visit_expr(&expr.elt);
                self.visit_comprehensions(&expr.generators);
            }
            ast::Expr::DictComp(expr) => {
                self.visit_expr(&expr.key);
                self.visit_expr(&expr.value);
                self.visit_comprehensions(&expr.generators);
            }
            ast::Expr::GeneratorExp(expr) => {
                self.visit_expr(&expr.elt);
                self.visit_comprehensions(&expr.generators);
            }
            ast::Expr::Await(expr) => self.visit_expr(&expr.value),
            ast::Expr::Yield(expr) => {
                if let Some(value) = expr.value.as_deref() {
                    self.visit_expr(value);
                }
            }
            ast::Expr::YieldFrom(expr) => self.visit_expr(&expr.value),
            ast::Expr::Compare(expr) => {
                self.visit_expr(&expr.left);
                for comparator in &expr.comparators {
                    self.visit_expr(comparator);
                }
            }
            ast::Expr::Call(expr) => {
                if let Some(call_path) = self.resolved_call_path(&expr.func) {
                    self.record_call(&call_path);
                }
                self.visit_expr(&expr.func);
                for arg in &expr.args {
                    self.visit_expr(arg);
                }
                for keyword in &expr.keywords {
                    self.visit_expr(&keyword.value);
                }
            }
            ast::Expr::FormattedValue(expr) => {
                self.visit_expr(&expr.value);
                if let Some(format_spec) = expr.format_spec.as_deref() {
                    self.visit_expr(format_spec);
                }
            }
            ast::Expr::JoinedStr(expr) => {
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::Attribute(expr) => self.visit_expr(&expr.value),
            ast::Expr::Subscript(expr) => {
                self.visit_expr(&expr.value);
                self.visit_expr(&expr.slice);
            }
            ast::Expr::Starred(expr) => self.visit_expr(&expr.value),
            ast::Expr::List(expr) => {
                for element in &expr.elts {
                    self.visit_expr(element);
                }
            }
            ast::Expr::Tuple(expr) => {
                for element in &expr.elts {
                    self.visit_expr(element);
                }
            }
            ast::Expr::Slice(expr) => {
                if let Some(lower) = expr.lower.as_deref() {
                    self.visit_expr(lower);
                }
                if let Some(upper) = expr.upper.as_deref() {
                    self.visit_expr(upper);
                }
                if let Some(step) = expr.step.as_deref() {
                    self.visit_expr(step);
                }
            }
            ast::Expr::Constant(_) | ast::Expr::Name(_) => {}
        }
    }

    fn visit_with_items(&mut self, items: &[ast::WithItem]) {
        for item in items {
            self.visit_expr(&item.context_expr);
            if let Some(optional_vars) = item.optional_vars.as_deref() {
                self.visit_expr(optional_vars);
            }
        }
    }

    fn visit_except_handlers(&mut self, handlers: &[ast::ExceptHandler]) {
        for handler in handlers {
            match handler {
                ast::ExceptHandler::ExceptHandler(handler) => {
                    if let Some(type_) = handler.type_.as_deref() {
                        self.visit_expr(type_);
                    }
                    self.visit_suite(&handler.body);
                }
            }
        }
    }

    fn visit_comprehensions(&mut self, comprehensions: &[ast::Comprehension]) {
        for comprehension in comprehensions {
            self.visit_expr(&comprehension.target);
            self.visit_expr(&comprehension.iter);
            for condition in &comprehension.ifs {
                self.visit_expr(condition);
            }
        }
    }

    fn visit_pattern(&mut self, pattern: &ast::Pattern) {
        match pattern {
            ast::Pattern::MatchValue(pattern) => self.visit_expr(&pattern.value),
            ast::Pattern::MatchSequence(pattern) => {
                for pattern in &pattern.patterns {
                    self.visit_pattern(pattern);
                }
            }
            ast::Pattern::MatchMapping(pattern) => {
                for key in &pattern.keys {
                    self.visit_expr(key);
                }
                for pattern in &pattern.patterns {
                    self.visit_pattern(pattern);
                }
            }
            ast::Pattern::MatchClass(pattern) => {
                self.visit_expr(&pattern.cls);
                for pattern in &pattern.patterns {
                    self.visit_pattern(pattern);
                }
                for pattern in &pattern.kwd_patterns {
                    self.visit_pattern(pattern);
                }
            }
            ast::Pattern::MatchAs(pattern) => {
                if let Some(pattern) = pattern.pattern.as_deref() {
                    self.visit_pattern(pattern);
                }
            }
            ast::Pattern::MatchOr(pattern) => {
                for pattern in &pattern.patterns {
                    self.visit_pattern(pattern);
                }
            }
            ast::Pattern::MatchSingleton(_) | ast::Pattern::MatchStar(_) => {}
        }
    }

    fn record_import(&mut self, module: &str, asname: Option<&str>) {
        let binding = asname.unwrap_or_else(|| module.split('.').next().unwrap_or(module));
        self.import_aliases
            .insert(binding.to_string(), module.to_string());
        if let Some(evidence) = import_evidence(module) {
            self.evidence.insert(evidence);
        }
    }

    fn record_from_import(&mut self, module: &str, imported_name: &str, asname: Option<&str>) {
        if imported_name == "*" {
            if let Some(evidence) = import_evidence(module) {
                self.evidence.insert(evidence);
            }
            return;
        }

        let full_name = format!("{module}.{imported_name}");
        let binding = asname.unwrap_or(imported_name);
        self.import_aliases.insert(binding.to_string(), full_name);
        if let Some(evidence) = import_evidence(module) {
            self.evidence.insert(evidence);
        }
    }

    fn record_call(&mut self, call_path: &str) {
        if let Some(evidence) = call_evidence(call_path) {
            self.evidence.insert(evidence);
        }
    }

    fn resolved_call_path(&self, expr: &ast::Expr) -> Option<String> {
        let raw_path = call_path(expr)?;
        let (root, suffix) = raw_path
            .split_once('.')
            .map_or((raw_path.as_str(), ""), |(root, suffix)| (root, suffix));

        if let Some(resolved_root) = self.import_aliases.get(root) {
            if suffix.is_empty() {
                Some(resolved_root.clone())
            } else {
                Some(format!("{resolved_root}.{suffix}"))
            }
        } else {
            Some(raw_path)
        }
    }

    fn into_evidence(self) -> Vec<String> {
        self.evidence
            .into_iter()
            .take(MAX_PYTHON_AST_EVIDENCE)
            .collect()
    }
}

fn call_path(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => Some(name.id.to_string()),
        ast::Expr::Attribute(attribute) => {
            let base = call_path(&attribute.value)?;
            Some(format!("{base}.{}", attribute.attr))
        }
        _ => None,
    }
}

fn import_evidence(module: &str) -> Option<String> {
    let module = module.to_ascii_lowercase();
    let root = module.split('.').next().unwrap_or(module.as_str());

    match root {
        "subprocess" | "pty" => Some(format!("process-capable import: {module}")),
        "socket" | "urllib" | "http" | "ftplib" | "smtplib" | "requests" | "httpx" | "aiohttp"
        | "paramiko" => Some(format!("network-capable import: {module}")),
        "ctypes" | "cffi" | "mmap" => Some(format!("native-code interface import: {module}")),
        "pickle" | "marshal" | "shelve" | "dill" | "cloudpickle" => {
            Some(format!("unsafe deserialization import: {module}"))
        }
        "pip" | "ensurepip" => Some(format!("package installer import: {module}")),
        _ => None,
    }
}

fn call_evidence(call_path: &str) -> Option<String> {
    let call_path = call_path.to_ascii_lowercase();

    if matches!(
        call_path.as_str(),
        "eval" | "exec" | "compile" | "__import__"
    ) {
        return Some(format!("dynamic code execution call: {call_path}"));
    }

    if call_path == "os.system"
        || call_path == "os.popen"
        || call_path.starts_with("os.exec")
        || call_path.starts_with("os.spawn")
        || call_path == "subprocess.popen"
        || call_path == "subprocess.run"
        || call_path == "subprocess.call"
        || call_path == "subprocess.check_call"
        || call_path == "subprocess.check_output"
        || call_path == "pty.spawn"
    {
        return Some(format!("process execution call: {call_path}"));
    }

    if call_path == "socket.socket"
        || call_path == "socket.create_connection"
        || call_path == "urllib.request.urlopen"
        || call_path == "http.client.httpconnection"
        || call_path == "http.client.httpsconnection"
        || call_path == "ftplib.ftp"
        || call_path == "smtplib.smtp"
        || network_client_call(&call_path, "requests")
        || network_client_call(&call_path, "httpx")
        || network_client_call(&call_path, "aiohttp")
        || call_path == "paramiko.sshclient"
    {
        return Some(format!("network call: {call_path}"));
    }

    if native_library_loading_call(&call_path) {
        return Some(format!("native library loading call: {call_path}"));
    }

    if matches!(
        call_path.as_str(),
        "pickle.load"
            | "pickle.loads"
            | "marshal.load"
            | "marshal.loads"
            | "shelve.open"
            | "dill.load"
            | "dill.loads"
            | "cloudpickle.load"
            | "cloudpickle.loads"
    ) {
        return Some(format!("unsafe deserialization call: {call_path}"));
    }

    if matches!(
        call_path.as_str(),
        "pip.main" | "pip._internal.main" | "pip._internal.cli.main.main" | "ensurepip.bootstrap"
    ) {
        return Some(format!("package installer invocation: {call_path}"));
    }

    if call_path == "importlib.import_module" {
        return Some(format!("dynamic import call: {call_path}"));
    }

    None
}

fn network_client_call(call_path: &str, module: &str) -> bool {
    let Some(method) = call_path.strip_prefix(&format!("{module}.")) else {
        return false;
    };
    matches!(
        method,
        "request" | "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
    )
}

fn native_library_loading_call(call_path: &str) -> bool {
    matches!(
        call_path,
        "ctypes.cdll"
            | "ctypes.pydll"
            | "ctypes.windll"
            | "ctypes.cdll.loadlibrary"
            | "ctypes.pydll.loadlibrary"
            | "ctypes.windll.loadlibrary"
            | "ctypes.cdll.load_library"
            | "ctypes.pydll.load_library"
            | "ctypes.windll.load_library"
    ) || (call_path.starts_with("ctypes.")
        && (call_path.ends_with(".loadlibrary") || call_path.ends_with(".load_library")))
}

fn suspicious_dependency_findings(
    entries: &[WheelArchiveEntry],
    expected_project_normalized: &str,
) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        if !entry.path.ends_with("METADATA") {
            continue;
        }

        let metadata = String::from_utf8_lossy(&entry.contents);
        let mut evidence = Vec::new();

        if let Some(name) = metadata_field(&metadata, "Name") {
            if let Ok(metadata_project) = ProjectName::new(name.to_string()) {
                if metadata_project.normalized() != expected_project_normalized {
                    evidence.push(format!(
                        "metadata project name `{}` does not match requested project `{}`",
                        metadata_project.original(),
                        expected_project_normalized
                    ));
                }
            }
        }

        for dependency in metadata
            .lines()
            .filter_map(|line| line.strip_prefix("Requires-Dist:"))
            .map(str::trim)
        {
            let dependency_lower = dependency.to_ascii_lowercase();
            if dependency_lower.contains(" @ ")
                || dependency_lower.contains("://")
                || dependency_lower.contains("git+")
                || dependency_lower.contains("file:")
            {
                evidence.push(format!("direct URL or file dependency: {dependency}"));
                continue;
            }

            let suspicious_name = dependency_name(dependency);
            if matches!(
                suspicious_name.as_deref(),
                Some(
                    "pip"
                        | "setuptools"
                        | "wheel"
                        | "virtualenv"
                        | "poetry"
                        | "poetry-core"
                        | "twine"
                        | "build"
                        | "installer"
                        | "pip-tools"
                        | "pytest"
                        | "tox"
                        | "nox"
                )
            ) {
                evidence.push(format!("unusual runtime dependency: {dependency}"));
            }
        }

        if !evidence.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::SuspiciousDependency,
                path: Some(entry.path.clone()),
                summary: "METADATA contains suspicious dependency signals".into(),
                evidence,
            });
        }
    }

    findings
}

fn is_script_path(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some("sh" | "bash" | "command" | "ps1" | "bat" | "cmd")
    )
}

fn is_known_extension_module(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some("so" | "pyd" | "dll" | "dylib")
    )
}

fn has_shebang(contents: &[u8]) -> bool {
    contents.starts_with(b"#!")
}

fn looks_like_executable_binary(contents: &[u8]) -> bool {
    contents.starts_with(b"\x7fELF")
        || contents.starts_with(b"MZ")
        || contents.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || contents.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || contents.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || contents.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

fn is_binary_content(contents: &[u8]) -> bool {
    if contents.is_empty() {
        return false;
    }
    if contents.contains(&0) {
        return true;
    }

    let suspicious = contents
        .iter()
        .filter(|byte| !(byte.is_ascii_graphic() || byte.is_ascii_whitespace()))
        .count();
    suspicious * 5 > contents.len()
}

fn ascii_strings(contents: &[u8]) -> String {
    let mut out = String::new();
    let mut current = String::new();

    for byte in contents {
        let ch = *byte as char;
        if ch.is_ascii_graphic() || ch == ' ' {
            current.push(ch);
        } else {
            if current.len() >= 4 {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&current);
            }
            current.clear();
        }
    }

    if current.len() >= 4 {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&current);
    }

    out
}

fn find_patterns(haystack: &str, patterns: &[&str], limit: usize) -> Vec<String> {
    let lower = haystack.to_ascii_lowercase();
    let mut hits = Vec::new();

    for pattern in patterns {
        if lower.contains(pattern) {
            hits.push((*pattern).to_string());
        }
        if hits.len() >= limit {
            break;
        }
    }

    hits
}

fn metadata_field<'a>(metadata: &'a str, field: &str) -> Option<&'a str> {
    metadata
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn dependency_name(requirement: &str) -> Option<String> {
    requirement
        .split([' ', ';', '[', '(', '<', '>', '=', '!'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
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
}
