use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Cell, Row, Table};
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use sysinfo::System;
use walkdir::WalkDir;

/// File encryption and randomness analyzer
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Analyze files for encryption, randomness, and file types using magic numbers and entropy",
    long_about = "enro - File Analysis Tool\n\n\
                  Analyzes files to detect:\n  \
                  - Archive formats (ZIP, RAR, 7Z, TAR, GZIP, etc.)\n  \
                  - Document types (PDF, DOCX, etc.)\n  \
                  - Image formats (PNG, JPEG, GIF, etc.)\n  \
                  - Encrypted or highly compressed data\n  \
                  - Random data blobs\n  \
                  - Plain text files\n\n\
                  Uses magic number detection and Shannon entropy calculation to classify files."
)]
struct Args {
    /// File or directory to analyze
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Recursively scan directories
    #[arg(short, long)]
    recursive: bool,

    /// Minimum file size to analyze (in bytes)
    #[arg(short, long, default_value = "0")]
    min_size: u64,

    /// Maximum number of bytes to read for analysis (omit to scan entire file)
    #[arg(short = 'b', long)]
    max_bytes: Option<usize>,

    /// Simple output format (no colors, no tables)
    #[arg(short, long)]
    simple: bool,

    /// Show only summary (no individual file details)
    #[arg(long)]
    summary_only: bool,

    /// Number of threads to use for parallel processing (default: CPU cores)
    #[arg(short = 'j', long)]
    threads: Option<usize>,

    /// Entropy threshold range (format: min-max, e.g., 7.5-8.0)
    #[arg(short = 't', long, value_name = "MIN-MAX")]
    threshold: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum FileType {
    Archive(String),
    Document(String),
    Image(String),
    Encrypted,
    Random,
    PlainText,
    Binary,
    Compressed,
}

impl FileType {
    #[allow(dead_code)]
    fn display(&self) -> String {
        match self {
            FileType::Archive(name) => format!("📦 Archive ({})", name),
            FileType::Document(name) => format!("📄 Document ({})", name),
            FileType::Image(name) => format!("🖼️  Image ({})", name),
            FileType::Encrypted => "🔒 Encrypted".to_string(),
            FileType::Random => "🎲 Random Data".to_string(),
            FileType::PlainText => "📄 Plain Text".to_string(),
            FileType::Binary => "⚙️  Binary".to_string(),
            FileType::Compressed => "🗜️  Compressed".to_string(),
        }
    }

    fn display_plain(&self) -> String {
        match self {
            FileType::Archive(name) => format!("Archive ({})", name),
            FileType::Document(name) => format!("Document ({})", name),
            FileType::Image(name) => format!("Image ({})", name),
            FileType::Encrypted => "Encrypted".to_string(),
            FileType::Random => "Random Data".to_string(),
            FileType::PlainText => "Plain Text".to_string(),
            FileType::Binary => "Binary".to_string(),
            FileType::Compressed => "Compressed".to_string(),
        }
    }
}

struct FileAnalysis {
    path: PathBuf,
    file_type: FileType,
    entropy: f64,
    size: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Configure thread pool if specified
    if let Some(threads) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .context("Failed to set thread count")?;
    }

    let files = collect_files(&args)?;

    if files.is_empty() {
        if !args.simple {
            println!("{}", "No files to analyze.".yellow());
        }
        return Ok(());
    }

    if !args.simple {
        println!("Analyzing {} file(s)...\n", files.len());
    }

    let pb = ProgressBar::new(files.len() as u64);
    
    // Get terminal width and calculate bar width
    let term_width = if let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() {
        w as usize
    } else {
        80 // Default width if unable to detect
    };
    
    // Reserve space for other elements: spinner (2) + brackets (2) + elapsed (18) + pos/len (15) + eta (10) + padding (10) = ~57
    let bar_width = if term_width > 60 {
        (term_width - 60).min(40)
    } else {
        20 // Minimum bar width
    };
    
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!(
                "{{spinner:.green}} [{{elapsed_precise}}] [{{bar:{}.cyan/blue}}] {{pos}}/{{len}} ({{eta}})",
                bar_width
            ))
            .unwrap()
            .progress_chars("#>-"),
    );

    // Use parallel processing with rayon
    let pb_mutex = Mutex::new(&pb);
    let results: Vec<FileAnalysis> = files
        .par_iter()
        .filter_map(|file_path| {
            if let Ok(pb_guard) = pb_mutex.lock() {
                pb_guard.set_message(format!("{}", file_path.display()));
            }
            
            let result = analyze_file(file_path, args.max_bytes).ok();
            
            if let Ok(pb_guard) = pb_mutex.lock() {
                pb_guard.inc(1);
            }
            
            result
        })
        .collect();

    if !args.simple {
        pb.finish_with_message("Analysis complete!");
    } else {
        pb.finish_and_clear();
    }

    // Filter by entropy threshold if provided
    let filtered_results = if let Some(threshold) = &args.threshold {
        if let Some((min_str, max_str)) = threshold.split_once('-') {
            if let (Ok(min), Ok(max)) = (min_str.parse::<f64>(), max_str.parse::<f64>()) {
                results.into_iter()
                    .filter(|r| r.entropy >= min && r.entropy <= max)
                    .collect()
            } else {
                eprintln!("Warning: Invalid threshold format. Expected format: min-max (e.g., 7.5-8.0)");
                results
            }
        } else {
            eprintln!("Warning: Invalid threshold format. Expected format: min-max (e.g., 7.5-8.0)");
            results
        }
    } else {
        results
    };

    if args.simple {
        display_simple(&filtered_results);
    } else if args.summary_only {
        display_summary_only(&filtered_results);
    } else {
        display_results(&filtered_results);
    }

    Ok(())
}

fn collect_files(args: &Args) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if args.path.is_file() {
        files.push(args.path.clone());
    } else if args.path.is_dir() {
        if args.recursive {
            for entry in WalkDir::new(&args.path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.len() >= args.min_size {
                            files.push(entry.path().to_path_buf());
                        }
                    }
                }
            }
        } else {
            for entry in fs::read_dir(&args.path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.len() >= args.min_size {
                            files.push(entry.path());
                        }
                    }
                }
            }
        }
    } else {
        anyhow::bail!("Path does not exist: {}", args.path.display());
    }

    Ok(files)
}

// Calculate optimal chunk size based on available RAM and thread count
fn get_optimal_chunk_size() -> usize {
    static CHUNK_SIZE: OnceLock<usize> = OnceLock::new();
    
    *CHUNK_SIZE.get_or_init(|| {
        let mut sys = System::new_all();
        sys.refresh_memory();
        
        let available_ram = sys.available_memory() as usize;
        let thread_count = rayon::current_num_threads();
        
        // Calculate: available_ram / (threads + 2), capped at 1GB
        let divisor = (thread_count * 2).max(4); // Ensure at least 4 to avoid too large chunks
        let chunk_size = available_ram / divisor;
        const MAX_CHUNK: usize = 1024 * 1024 * 1024; // 1GB
        const MIN_CHUNK: usize = 1024 * 1024; // 1MB minimum
        
        chunk_size.min(MAX_CHUNK).max(MIN_CHUNK)
    })
}

fn analyze_file(path: &Path, max_bytes: Option<usize>) -> Result<FileAnalysis> {
    let metadata = fs::metadata(path).context("Failed to read file metadata")?;
    let size = metadata.len();

    let mut file = File::open(path).context("Failed to open file")?;
    
    // Use dynamically calculated chunk size
    let chunk_size = get_optimal_chunk_size();
    
    let bytes_to_read = if let Some(max) = max_bytes {
        max.min(size as usize)
    } else {
        size as usize // Read entire file
    };
    
    // For small files, read all at once
    if bytes_to_read <= chunk_size {
        let mut buffer = vec![0u8; bytes_to_read];
        let bytes_read = file.read(&mut buffer).context("Failed to read file")?;
        buffer.truncate(bytes_read);
        
        let file_type = detect_file_type(&buffer);
        let entropy = calculate_entropy(&buffer);
        
        return Ok(FileAnalysis {
            path: path.to_path_buf(),
            file_type,
            entropy,
            size,
        });
    }
    
    // For large files, read in chunks and aggregate statistics
    let mut total_read = 0;
    let mut first_chunk = Vec::new();
    let mut byte_counts = [0u64; 256];
    
    while total_read < bytes_to_read {
        let current_chunk_size = chunk_size.min(bytes_to_read - total_read);
        let mut chunk = vec![0u8; current_chunk_size];
        let bytes_read = file.read(&mut chunk).context("Failed to read file chunk")?;
        
        if bytes_read == 0 {
            break; // EOF
        }
        
        chunk.truncate(bytes_read);
        
        // Save first chunk for file type detection
        if total_read == 0 {
            first_chunk = chunk.clone();
        }
        
        // Count byte frequencies for entropy calculation
        for &byte in &chunk {
            byte_counts[byte as usize] += 1;
        }
        
        total_read += bytes_read;
    }
    
    // Detect file type from first chunk
    let file_type = detect_file_type(&first_chunk);
    
    // Calculate entropy from aggregated byte counts
    let entropy = calculate_entropy_from_counts(&byte_counts, total_read);

    Ok(FileAnalysis {
        path: path.to_path_buf(),
        file_type,
        entropy,
        size,
    })
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.is_empty() {
        return FileType::PlainText;
    }

    // Check our custom magic numbers for archives
    if let Some(archive_type) = check_magic_number(data) {
        return FileType::Archive(archive_type);
    }

    // Try infer crate as fallback for file type detection
    if let Some(kind) = infer::get(data) {
        let mime = kind.mime_type();
        let ext = kind.extension().to_uppercase();
        
        // Archive types
        if mime.starts_with("application/x-") || mime.starts_with("application/zip") 
            || mime == "application/gzip" || mime == "application/x-bzip2" 
            || mime == "application/x-xz" || mime == "application/x-tar" {
            return FileType::Archive(ext);
        }
        
        // Document formats (PDF, Office docs, etc.)
        if mime == "application/pdf" {
            return FileType::Document("PDF".to_string());
        }
        if mime.starts_with("application/vnd.openxmlformats") {
            return FileType::Document(ext);
        }
        if mime.starts_with("application/vnd.ms-") || mime.starts_with("application/msword") {
            return FileType::Document(ext);
        }
        
        // Image formats
        if mime.starts_with("image/") {
            return FileType::Image(ext);
        }
        
        // Other compressed formats
        if mime.contains("compress") || mime.contains("zip") {
            return FileType::Compressed;
        }
    }

    // Calculate entropy to detect encryption/randomness
    let entropy = calculate_entropy(data);

    // High entropy (> 7.5) suggests encryption or compression
    if entropy > 7.5 {
        // Check if it's a compressed format we might have missed
        if is_compressed_format(data) {
            return FileType::Compressed;
        }
        // If very high entropy and not a known format, likely encrypted or random
        if entropy > 7.9 {
            return FileType::Encrypted;
        }
        return FileType::Random;
    }

    // Check if it's mostly text
    if is_text_data(data) {
        return FileType::PlainText;
    }

    FileType::Binary
}

fn check_magic_number(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    // ZIP (PK)
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) || data.starts_with(&[0x50, 0x4B, 0x05, 0x06]) {
        return Some("ZIP".to_string());
    }

    // RAR
    if data.starts_with(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) {
        return Some("RAR".to_string());
    }

    // 7z
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some("7Z".to_string());
    }

    // GZIP
    if data.starts_with(&[0x1F, 0x8B]) {
        return Some("GZIP".to_string());
    }

    // TAR (POSIX)
    if data.len() > 262 && &data[257..262] == b"ustar" {
        return Some("TAR".to_string());
    }

    // BZ2
    if data.starts_with(&[0x42, 0x5A, 0x68]) {
        return Some("BZIP2".to_string());
    }

    // XZ
    if data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some("XZ".to_string());
    }

    // ISO
    if data.len() > 32774 && &data[32769..32774] == b"CD001" {
        return Some("ISO".to_string());
    }

    // CAB
    if data.starts_with(&[0x4D, 0x53, 0x43, 0x46]) {
        return Some("CAB".to_string());
    }

    // ARJ
    if data.starts_with(&[0x60, 0xEA]) {
        return Some("ARJ".to_string());
    }

    // LZH/LHA
    if data.len() > 2 && data[2..4] == [0x2D, 0x6C] {
        return Some("LZH".to_string());
    }

    None
}

fn is_compressed_format(data: &[u8]) -> bool {
    // Additional compressed format checks
    if data.len() < 4 {
        return false;
    }

    // ZSTD
    if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return true;
    }

    // LZ4
    if data.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        return true;
    }

    false
}

fn is_text_data(data: &[u8]) -> bool {
    let sample_size = data.len().min(8192);
    let sample = &data[..sample_size];
    
    // Check for null bytes which indicate binary
    if sample.contains(&0) {
        return false;
    }
    
    // Try UTF-8 validation first
    if let Ok(text) = std::str::from_utf8(sample) {
        // Valid UTF-8 - check if it's mostly printable
        let printable = text.chars()
            .filter(|c| c.is_whitespace() || !c.is_control())
            .count();
        if printable as f64 / text.chars().count() as f64 > 0.90 {
            return true;
        }
    }
    
    // Check for Windows-1251 (Cyrillic) and other 8-bit encodings
    // Windows-1251 uses ranges: 0x20-0x7E (ASCII), 0xA0-0xFF (Cyrillic), plus common control chars
    let mut valid_chars = 0;
    for &byte in sample {
        if (byte >= 0x20 && byte <= 0x7E) ||  // ASCII printable
           byte >= 0xA0 ||                     // Extended ASCII / Cyrillic range (0xA0-0xFF)
           byte == b'\n' || byte == b'\r' || byte == b'\t' {
            valid_chars += 1;
        }
    }
    
    // If more than 95% are valid text characters (ASCII or extended), consider it text
    valid_chars as f64 / sample_size as f64 > 0.95
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    calculate_entropy_from_counts(&frequency, data.len())
}

fn calculate_entropy_from_counts(frequency: &[u64; 256], total_bytes: usize) -> f64 {
    if total_bytes == 0 {
        return 0.0;
    }

    let len = total_bytes as f64;
    let mut entropy = 0.0;

    for &count in frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn display_simple(results: &[FileAnalysis]) {
    println!("Path,Type,Entropy,Size");
    for analysis in results {
        let file_path = if let Ok(cwd) = std::env::current_dir() {
            analysis.path.strip_prefix(&cwd)
                .unwrap_or(&analysis.path)
                .display()
                .to_string()
        } else {
            analysis.path.display().to_string()
        };

        let type_str = match &analysis.file_type {
            FileType::Archive(name) => format!("Archive({})", name),
            FileType::Document(name) => format!("Document({})", name),
            FileType::Image(name) => format!("Image({})", name),
            FileType::Encrypted => "Encrypted".to_string(),
            FileType::Random => "Random".to_string(),
            FileType::PlainText => "PlainText".to_string(),
            FileType::Binary => "Binary".to_string(),
            FileType::Compressed => "Compressed".to_string(),
        };

        println!(
            "{},{},{:.2},{}",
            escape_csv(&file_path),
            escape_csv(&type_str),
            analysis.entropy,
            analysis.size
        );
    }
}

fn display_results(results: &[FileAnalysis]) {
    // Get terminal width for dynamic bar sizing
    let term_width = if let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() {
        w as usize
    } else {
        100 // Default width if unable to detect
    };
    
    // Use a conservative width to account for unicode rendering
    let bar_width = (term_width.saturating_sub(5)).min(80);
    let separator = "=".repeat(bar_width);
    let thin_separator = "-".repeat(bar_width);

    println!("\n{}", separator.cyan());
    println!("{}", "ANALYSIS RESULTS".bold().cyan());
    println!("{}", separator.cyan());

    let mut table = Table::new();
    let format = prettytable::format::FormatBuilder::new()
        .column_separator(' ')
        .borders(' ')
        .separators(&[], prettytable::format::LineSeparator::new(' ', ' ', ' ', ' '))
        .padding(1, 1)
        .build();
    table.set_format(format);
    
    table.add_row(Row::new(vec![
        Cell::new("File").style_spec("Fb"),
        Cell::new("Type").style_spec("Fb"),
        Cell::new("Entropy").style_spec("Fb"),
        Cell::new("Size").style_spec("Fb"),
    ]));

    for analysis in results {
        let file_path = if let Ok(cwd) = std::env::current_dir() {
            analysis.path.strip_prefix(&cwd)
                .unwrap_or(&analysis.path)
                .display()
                .to_string()
        } else {
            analysis.path.display().to_string()
        };

        let type_str = analysis.file_type.display_plain();
        let entropy_str = format!("{:.2}/8.0", analysis.entropy);
        let size_str = format_size(analysis.size);

        let entropy_colored = if analysis.entropy > 7.5 {
            entropy_str.red().to_string()
        } else if analysis.entropy > 6.0 {
            entropy_str.yellow().to_string()
        } else {
            entropy_str.green().to_string()
        };

        table.add_row(Row::new(vec![
            Cell::new(&file_path),
            Cell::new(&type_str),
            Cell::new(&entropy_colored),
            Cell::new(&size_str),
        ]));
    }

    table.printstd();

    // Summary statistics
    println!("\n{}", thin_separator.dimmed());
    println!("{}", "SUMMARY".bold());
    println!("{}", thin_separator.dimmed());

    let mut type_counts = std::collections::HashMap::new();
    for analysis in results {
        let key = format!("{:?}", analysis.file_type);
        *type_counts.entry(key).or_insert(0) += 1;
    }

    for (file_type, count) in type_counts {
        println!("  {} {}", "•".cyan(), format!("{}: {}", file_type, count).bold());
    }

    let avg_entropy: f64 = results.iter().map(|a| a.entropy).sum::<f64>() / results.len() as f64;
    println!(
        "\n  {} {}",
        "•".cyan(),
        format!("Average Entropy: {:.2}/8.0", avg_entropy).bold()
    );

    let high_entropy_count = results.iter().filter(|a| a.entropy > 7.5).count();
    if high_entropy_count > 0 {
        println!(
            "  {} {}",
            "⚠️".yellow(),
            format!(
                "{} file(s) with high entropy (possibly encrypted/compressed)",
                high_entropy_count
            )
            .yellow()
            .bold()
        );
    }

    println!();
}

fn display_summary_only(results: &[FileAnalysis]) {
    // Get terminal width for dynamic bar sizing
    let term_width = if let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() {
        w as usize
    } else {
        100 // Default width if unable to detect
    };
    
    // Use a conservative width to account for unicode rendering
    let bar_width = (term_width.saturating_sub(5)).min(80);
    let separator = "=".repeat(bar_width);
    let thin_separator = "-".repeat(bar_width);

    println!("\n{}", separator.cyan());
    println!("{}", "SUMMARY".bold().cyan());
    println!("{}", separator.cyan());

    let mut type_counts = std::collections::HashMap::new();
    for analysis in results {
        let key = format!("{:?}", analysis.file_type);
        *type_counts.entry(key).or_insert(0) += 1;
    }

    println!("\n{}", "File Types:".bold());
    for (file_type, count) in type_counts {
        println!("  {} {}", "•".cyan(), format!("{}: {}", file_type, count).bold());
    }

    let avg_entropy: f64 = results.iter().map(|a| a.entropy).sum::<f64>() / results.len() as f64;
    
    println!("\n{}", "Statistics:".bold());
    println!(
        "  {} {}",
        "•".cyan(),
        format!("Total Files: {}", results.len()).bold()
    );
    println!(
        "  {} {}",
        "•".cyan(),
        format!("Average Entropy: {:.2}/8.0", avg_entropy).bold()
    );

    let high_entropy_count = results.iter().filter(|a| a.entropy > 7.5).count();
    if high_entropy_count > 0 {
        println!(
            "  {} {}",
            "⚠️".yellow(),
            format!(
                "{} file(s) with high entropy (possibly encrypted/compressed)",
                high_entropy_count
            )
            .yellow()
            .bold()
        );
    }

    println!("\n{}", thin_separator.dimmed());
}

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_idx])
}
