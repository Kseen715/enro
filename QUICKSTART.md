# EnRO - Quick Start Guide

## What is EnRO?

EnRO (**E**ncryption & **R**andomness **O**bserver) is a cross-platform command-line tool that analyzes files to detect:
- Encrypted data
- Random blobs  
- Archive files (ZIP, RAR, 7Z, GZIP, TAR, etc.)
- Compressed files
- Plain text
- Binary executables

## Quick Start

### Build the Project

```powershell
# Windows (PowerShell)
cargo build --release

# The executable will be at:
# target\x86_64-pc-windows-gnu\release\enro.exe
```

```bash
# Linux/macOS
cargo build --release

# The executable will be at:
# target/release/enro
```

### Basic Usage Examples

```bash
# Analyze a single file
enro file.bin

# Analyze all files in a directory
enro /path/to/directory

# Recursively scan all subdirectories
enro -r /path/to/directory

# Only analyze files larger than 1KB
enro -r . -m 1024

# Limit analysis to first 10MB of each file
enro -r . -b 10485760
```

## How It Works

### 1. Magic Number Detection
The tool checks file headers for known signatures:
- ZIP: `PK\x03\x04`
- RAR: `Rar!\x1A\x07`
- GZIP: `\x1F\x8B`
- 7Z: `7z\xBC\xAF\x27\x1C`
- And 15+ more formats...

### 2. Shannon Entropy Analysis
Calculates information density to detect randomness:
- **7.9-8.0 bits**: Likely encrypted or truly random
- **7.5-7.9 bits**: High entropy (compressed/encrypted)
- **6.0-7.5 bits**: Medium entropy (binary data)
- **< 6.0 bits**: Low entropy (plain text)

### 3. Smart Classification
Combines both techniques to accurately identify file types


## Example Output

```
🔍 File Analysis Tool v1.0

Analyzing 3 file(s)...

  [00:00:00] [########################################] 3/3 (0s)

═══════════════════════════════════════════════════════════════
ANALYSIS RESULTS
═══════════════════════════════════════════════════════════════
+-------------+------------------+----------+----------+
| File        | Type             | Entropy  | Size     |
+-------------+------------------+----------+----------+
| archive.zip | 📦 Archive (ZIP) | 7.94/8.0 | 3.55 KB  |
| plain.txt   | 📄 Plain Text    | 4.32/8.0 | 106.00 B |
| random.bin  | 🎲 Random Data   | 7.78/8.0 | 1.00 KB  |
+-------------+------------------+----------+----------+

───────────────────────────────────────────────────────────────
SUMMARY
───────────────────────────────────────────────────────────────
  • Archive("ZIP"): 1
  • PlainText: 1
  • Random: 1

  • Average Entropy: 6.68/8.0
  ⚠️ 2 file(s) with high entropy (possibly encrypted/compressed)
```

## Use Cases

1. **Security Analysis** - Detect encrypted or suspicious files
2. **Forensics** - Identify file types by content, not extension
3. **Data Classification** - Automatically categorize files
4. **Archive Discovery** - Find hidden or misnamed archives
5. **Entropy Profiling** - Assess data randomness for research

## Supported Archive Formats

ZIP • RAR • 7Z • GZIP • TAR • BZIP2 • XZ • ISO • CAB • ARJ • LZH • ZSTD • LZ4

## Performance

- Default: Analyzes first **1MB** of each file
- Configurable with `-b` flag
- Fast byte-level entropy calculation
- Minimal memory footprint

## Tips

💡 Use `-m` to skip small files and speed up large directory scans  
💡 Adjust `-b` for very large files to limit read time  
💡 Combine with other tools via piping (output is table-formatted)  
💡 High entropy (>7.5) often indicates encryption or compression  

## Building from Source

### Prerequisites
- **Rust** 1.70+ (install from https://rustup.rs)
- **Windows**: MinGW-w64 or Visual Studio Build Tools
- **Linux/macOS**: Standard build tools (gcc, make)

### Build
```bash
git clone <repository>
cd enro
cargo build --release
```

## License

MIT or Apache-2.0

## Contributing

Contributions welcome! Areas for enhancement:
- Additional magic number signatures
- Machine learning classification
- Export to JSON/CSV
- More compression formats
- Performance optimizations
