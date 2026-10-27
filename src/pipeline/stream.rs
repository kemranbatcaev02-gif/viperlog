use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::time::Instant;
use rayon::prelude::*;

use crate::engine::{MatchSpan, PiiType, ScrubScanner};

#[derive(Debug, Default, Clone)]
pub struct AuditReport {
    pub total_lines: usize,
    pub total_bytes: usize,
    pub matches_by_type: HashMap<PiiType, usize>,
    pub elapsed_millis: u128,
    pub throughput_mbs: f64,
}

pub struct StreamPipeline {
    scanner: ScrubScanner,
    batch_size: usize,
}

impl StreamPipeline {
    pub fn new() -> Self {
        Self {
            scanner: ScrubScanner::new(),
            batch_size: 4096,
        }
    }

    pub fn process_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> std::io::Result<AuditReport> {
        let mut buf_reader = BufReader::with_capacity(256 * 1024, reader);
        let mut buf_writer = BufWriter::with_capacity(256 * 1024, writer);

        let mut lines_batch = Vec::with_capacity(self.batch_size);
        let mut total_lines = 0;
        let mut total_bytes = 0;
        let mut type_counts: HashMap<PiiType, usize> = HashMap::new();

        let start_time = Instant::now();
        let mut line_buf = String::with_capacity(1024);

        loop {
            line_buf.clear();
            let bytes_read = buf_reader.read_line(&mut line_buf)?;
            if bytes_read == 0 {
                break;
            }

            total_bytes += bytes_read;
            total_lines += 1;

            let has_crlf = line_buf.ends_with("\r\n");
            let has_lf = line_buf.ends_with('\n');
            let content = if has_crlf {
                &line_buf[..line_buf.len() - 2]
            } else if has_lf {
                &line_buf[..line_buf.len() - 1]
            } else {
                &line_buf[..]
            };

            lines_batch.push(content.to_string());

            if lines_batch.len() >= self.batch_size {
                self.flush_batch(&mut lines_batch, &mut buf_writer, &mut type_counts, has_crlf)?;
            }
        }

        if !lines_batch.is_empty() {
            self.flush_batch(&mut lines_batch, &mut buf_writer, &mut type_counts, true)?;
        }

        buf_writer.flush()?;

        let elapsed = start_time.elapsed().as_millis();
        let seconds = (elapsed as f64) / 1000.0;
        let mb_processed = (total_bytes as f64) / (1024.0 * 1024.0);
        let throughput = if seconds > 0.0 { mb_processed / seconds } else { 0.0 };

        Ok(AuditReport {
            total_lines,
            total_bytes,
            matches_by_type: type_counts,
            elapsed_millis: elapsed,
            throughput_mbs: throughput,
        })
    }

    pub fn audit_stream<R: Read>(&self, reader: R) -> std::io::Result<AuditReport> {
        let mut buf_reader = BufReader::with_capacity(256 * 1024, reader);
        let mut lines_batch = Vec::with_capacity(self.batch_size);

        let mut total_lines = 0;
        let mut total_bytes = 0;
        let mut type_counts: HashMap<PiiType, usize> = HashMap::new();

        let start_time = Instant::now();
        let mut line_buf = String::with_capacity(1024);

        loop {
            line_buf.clear();
            let bytes_read = buf_reader.read_line(&mut line_buf)?;
            if bytes_read == 0 {
                break;
            }

            total_bytes += bytes_read;
            total_lines += 1;
            lines_batch.push(line_buf.clone());

            if lines_batch.len() >= self.batch_size {
                self.audit_batch(&lines_batch, &mut type_counts);
                lines_batch.clear();
            }
        }

        if !lines_batch.is_empty() {
            self.audit_batch(&lines_batch, &mut type_counts);
        }

        let elapsed = start_time.elapsed().as_millis();
        let seconds = (elapsed as f64) / 1000.0;
        let mb_processed = (total_bytes as f64) / (1024.0 * 1024.0);
        let throughput = if seconds > 0.0 { mb_processed / seconds } else { 0.0 };

        Ok(AuditReport {
            total_lines,
            total_bytes,
            matches_by_type: type_counts,
            elapsed_millis: elapsed,
            throughput_mbs: throughput,
        })
    }

    fn flush_batch<W: Write>(
        &self,
        batch: &mut Vec<String>,
        writer: &mut BufWriter<W>,
        counts: &mut HashMap<PiiType, usize>,
        use_crlf: bool,
    ) -> std::io::Result<()> {
        let processed: Vec<_> = batch
            .par_iter()
            .map(|line| self.scanner.scrub_line(line))
            .collect();

        let line_ending = if use_crlf { "\r\n" } else { "\n" };

        for item in processed {
            for m in item.matches {
                *counts.entry(m.pii_type).or_insert(0) += 1;
            }
            writer.write_all(item.cleaned_text.as_bytes())?;
            writer.write_all(line_ending.as_bytes())?;
        }

        batch.clear();
        Ok(())
    }

    fn audit_batch(&self, batch: &[String], counts: &mut HashMap<PiiType, usize>) {
        let batch_matches: Vec<Vec<MatchSpan>> = batch
            .par_iter()
            .map(|line| self.scanner.audit_line(line))
            .collect();

        for matches in batch_matches {
            for m in matches {
                *counts.entry(m.pii_type).or_insert(0) += 1;
            }
        }
    }
}
