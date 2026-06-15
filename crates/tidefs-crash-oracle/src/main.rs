#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use tidefs_crash_oracle::write_model_crash_report;

fn main() {
    let output = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("validation/artifacts/crash-oracle/model-crash-matrices.json")
    });

    match write_model_crash_report(&output) {
        Ok(report) => {
            println!(
                "wrote {} matrix case(s) to {}",
                report.case_count(),
                output.display()
            );
        }
        Err(err) => {
            eprintln!("tidefs-crash-oracle: {err}");
            std::process::exit(1);
        }
    }
}
