use pyregistry_application::{AuditWheelCommand, WheelAuditUseCase};
use pyregistry_infrastructure::{
    FoxGuardWheelSourceSecurityScanner, YaraWheelVirusScanner, ZipWheelArchiveReader,
};
use std::path::PathBuf;
use std::sync::Arc;

#[hotpath::main]
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let wheel = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("usage: profile_wheel WHEEL [ITERATIONS]"))?,
    );
    let iterations: usize = args.next().map_or(Ok(5), |value| value.parse())?;
    anyhow::ensure!(iterations > 0, "iterations must be positive");
    let audit = WheelAuditUseCase::new(
        Arc::new(ZipWheelArchiveReader),
        Arc::new(YaraWheelVirusScanner::from_rules_dir(
            "supplied/signature-base/yara",
        )),
        Arc::new(FoxGuardWheelSourceSecurityScanner::default()),
    );
    for _ in 0..iterations {
        let report = audit.audit(AuditWheelCommand {
            project_name: "demo".into(),
            wheel_path: wheel.clone(),
        })?;
        std::hint::black_box(report);
    }
    Ok(())
}
