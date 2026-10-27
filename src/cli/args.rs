use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "viperlog",
    author = "Kemran",
    version = "0.1.0",
    about = "⚡ Blisteringly fast, SIMD-accelerated log scrubber and PII masker",
    long_about = "ViperLog scans text and structured logs for sensitive data (credit cards, tokens, emails, IPs) \
using SIMD instructions and multi-threaded parallel processing."
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Input file path (reads from STDIN if omitted)
    #[arg(short, long, global = true)]
    pub input: Option<PathBuf>,

    /// Output file path (writes to STDOUT if omitted)
    #[arg(short, long, global = true)]
    pub output: Option<PathBuf>,

    /// Run audit only: print detailed leak detection statistics without rewriting
    #[arg(short, long, global = true)]
    pub audit: bool,

    /// Overwrite input file in-place with scrubbed content
    #[arg(long, global = true)]
    pub in_place: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Mask PII from logs (default mode)
    Scrub {
        #[arg(short, long)]
        input: Option<PathBuf>,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Fast security audit: report detected leaks and throughput without modifying files
    Audit {
        /// Target log file to analyze
        file: PathBuf,
    },

    /// Run an interactive demo showcasing PII detection and masking
    Demo,
}
