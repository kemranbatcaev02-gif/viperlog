use std::fs::File;
use std::io::{self, Read, Write};
use clap::Parser;
use colored::*;

use viperlog::cli::{CliArgs, Commands};
use viperlog::pipeline::{AuditReport, StreamPipeline};

fn print_banner() {
    println!("{}", "╭───────────────────────────────────────────────────╮".bright_purple());
    println!(
        "{}   {}    {} {}",
        "│".bright_purple(),
        "⚡ ViperLog".bright_yellow().bold(),
        "High-Speed SIMD Log & PII Scrubber".bright_white(),
        "│".bright_purple()
    );
    println!("{}", "╰───────────────────────────────────────────────────╯".bright_purple());
}

fn print_report(report: &AuditReport, mode: &str) {
    println!("\n{}", format!("=== ViperLog Execution Summary ({}) ===", mode).bold().underline());
    println!("{:<24} {:>12}", "Total lines processed:".white(), report.total_lines.to_string().bright_cyan());
    println!("{:<24} {:>12}", "Total data processed:".white(), format!("{:.2} MB", report.total_bytes as f64 / (1024.0 * 1024.0)).bright_cyan());
    println!("{:<24} {:>12}", "Time elapsed:".white(), format!("{:.3}s", report.elapsed_millis as f64 / 1000.0).bright_cyan());
    println!("{:<24} {:>12}", "Throughput:".white(), format!("{:.1} MB/s", report.throughput_mbs).bright_green().bold());

    let total_leaks: usize = report.matches_by_type.values().sum();
    println!("\n{}: {}", "Sensitive Data Detections".bold(), if total_leaks > 0 {
        format!("{} leaks found", total_leaks).bright_red().bold()
    } else {
        "0 (clean)".bright_green().bold()
    });

    if total_leaks > 0 {
        println!("{}", "─".repeat(50).dimmed());
        for (pii, count) in &report.matches_by_type {
            println!("  • {:<30} {:>8} masked", pii.to_string().yellow(), count.to_string().bright_red());
        }
        println!("{}", "─".repeat(50).dimmed());
    }
}

fn run_demo() -> io::Result<()> {
    print_banner();
    println!("\n{}", "Executing interactive PII scrubbing demo...".cyan().bold());

    let dirty_logs = r#"
2026-10-27 19:40:12 [INFO] User login success: alice.smith@enterprise.com from ip 198.51.100.44
2026-10-27 19:40:14 [WARN] Payment retry for customer: card 4242-4242-4242-4242 cvv 892 exp 12/28
2026-10-27 19:40:15 [DEBUG] Auth header present: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4
2026-10-27 19:40:16 [ERROR] External API sync failed: endpoint="https://api.stripe.com/v1/charges" key=sk_mock_9988aabbccddee1122334455
2026-10-27 19:40:18 [INFO] Uploading build report to S3 with access_key=AKIAIOSFODNN7EXAMPLE secret=password12345
2026-10-27 19:40:20 [INFO] System health check status=OK memory_usage=14.2%
"#;

    println!("\n{}", "── [BEFORE: Raw Dirty Log (Contains Critical Leaks)] ──".bright_red().bold());
    println!("{}", dirty_logs.trim());

    let pipeline = StreamPipeline::new();
    let mut clean_output = Vec::new();

    let report = pipeline.process_stream(dirty_logs.as_bytes(), &mut clean_output)?;

    println!("\n{}", "── [AFTER: Scrubbed Log (All PII Masked)] ──".bright_green().bold());
    println!("{}", String::from_utf8_lossy(&clean_output).trim());

    print_report(&report, "DEMO MODE");
    Ok(())
}

fn main() -> io::Result<()> {
    let args = CliArgs::parse();

    if let Some(cmd) = args.command {
        match cmd {
            Commands::Demo => return run_demo(),
            Commands::Audit { file } => {
                print_banner();
                println!("Auditing log file: {}", file.display().to_string().cyan());
                let f = File::open(&file)?;
                let pipeline = StreamPipeline::new();
                let report = pipeline.audit_stream(f)?;
                print_report(&report, "AUDIT MODE");
                return Ok(());
            }
            Commands::Scrub { input, output } => {
                let pipeline = StreamPipeline::new();
                let reader: Box<dyn Read> = match input {
                    Some(p) => Box::new(File::open(p)?),
                    None => Box::new(io::stdin()),
                };
                let writer: Box<dyn Write> = match output {
                    Some(p) => Box::new(File::create(p)?),
                    None => Box::new(io::stdout()),
                };
                let _ = pipeline.process_stream(reader, writer)?;
                return Ok(());
            }
        }
    }

    if args.audit {
        print_banner();
        let reader: Box<dyn Read> = match &args.input {
            Some(p) => {
                println!("Auditing log file: {}", p.display().to_string().cyan());
                Box::new(File::open(p)?)
            }
            None => Box::new(io::stdin()),
        };
        let pipeline = StreamPipeline::new();
        let report = pipeline.audit_stream(reader)?;
        print_report(&report, "AUDIT MODE");
        return Ok(());
    }

    let pipeline = StreamPipeline::new();

    if args.in_place {
        let input_path = args.input.expect("--in-place requires --input <FILE>");
        let content = std::fs::read_to_string(&input_path)?;
        let mut temp_out = Vec::with_capacity(content.len());
        let report = pipeline.process_stream(content.as_bytes(), &mut temp_out)?;
        std::fs::write(&input_path, temp_out)?;
        print_banner();
        println!("File scrubbed in-place: {}", input_path.display().to_string().green());
        print_report(&report, "IN-PLACE SCRUB");
        return Ok(());
    }

    let reader: Box<dyn Read> = match &args.input {
        Some(p) => Box::new(File::open(p)?),
        None => Box::new(io::stdin()),
    };

    let writer: Box<dyn Write> = match &args.output {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };

    let _ = pipeline.process_stream(reader, writer)?;
    Ok(())
}
