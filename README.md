# EnRO - File Encryption & Randomness Observer

A cross-platform (Linux/Windows/macOS) command-line tool written in Rust that analyzes files to detect:
- 🔒 **Encrypted data**
- 🎲 **Random blobs**
- 📦 **Archives** (ZIP, RAR, 7Z, GZIP, TAR, BZIP2, XZ, ISO, CAB, ARJ, LZH, etc.)
- 🗜️ **Compressed files**
- 📄 **Plain text**
- ⚙️ **Binary files**

## Features

- **Magic Number Detection**: Identifies file types by their magic bytes/signatures
- **Entropy Analysis**: Calculates Shannon entropy to detect encryption and randomness
- **Recursive Directory Scanning**: Use `-r` flag to analyze entire directory trees
- **Beautiful Output**: Colored terminal output with progress bars and formatted tables
- **Cross-Platform**: Works on Linux, Windows, and macOS
- **Fast & Efficient**: Written in Rust for maximum performance

## Prerequisites

### Windows
You need either:
- **Visual Studio 2017 or later** with C++ build tools, OR
- **Visual Studio Build Tools** with C++ workload

Download from: https://visualstudio.microsoft.com/downloads/

Alternatively, install MinGW-w64 and use the GNU toolchain:
```powershell
# Install via chocolatey
choco install mingw

# Then build with GNU target
cargo build --target x86_64-pc-windows-gnu
```

### Linux
```bash
# Rust should work out of the box
# If you don't have Rust installed:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### macOS
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Installation

### Build from Source

```bash
# Clone or navigate to the project directory
cd enro

# Build release version
cargo build --release

# The binary will be at target/release/enro (or enro.exe on Windows)
```

### Install Globally

```bash
cargo install --path .
```

## Usage

### Basic Usage

```bash
# Analyze a single file
enro file.bin

# Analyze all files in current directory
enro .

# Recursively analyze all files in a directory
enro -r /path/to/directory

# Analyze with minimum file size filter (1KB)
enro -r . -m 1024

# Limit analysis to first 10MB of each file
enro -r . -b 10485760
```

### Command-Line Options

```
Usage: enro [OPTIONS] <PATH>

Arguments:
  <PATH>  File or directory to analyze

Options:
  -r, --recursive           Recursively scan directories
  -m, --min-size <MIN_SIZE> Minimum file size to analyze in bytes [default: 0]
  -b, --max-bytes <MAX_BYTES> Maximum bytes to read for analysis [default: 1048576]
  -h, --help               Print help
  -V, --version            Print version
```

## How It Works

### Magic Number Detection

The tool checks file headers for known magic bytes to identify:
- **ZIP** (PK\x03\x04)
- **RAR** (Rar!\x1A\x07)
- **7Z** (7z\xBC\xAF\x27\x1C)
- **GZIP** (\x1F\x8B)
- **TAR** (ustar at offset 257)
- **BZIP2** (BZh)
- **XZ** (\xFD7zXZ\x00)
- **ISO** (CD001 at offset 32769)
- **CAB** (MSCF)
- **ZSTD** (\x28\xB5\x2F\xFD)
- **LZ4** (\x04\x22\x4D\x18)
- And more...

### Entropy Analysis

Shannon entropy is calculated using the formula:

```
H(X) = -Σ P(xi) * log₂(P(xi))
```

Where P(xi) is the probability of byte value i appearing in the file.

**Entropy scale (0-8 bits):**
- **7.9-8.0**: Likely encrypted or truly random data
- **7.5-7.9**: High entropy - possibly compressed or encrypted
- **6.0-7.5**: Medium entropy - binary data
- **< 6.0**: Low entropy - likely plain text or structured data

### Classification Logic

1. Check magic numbers for known archive formats
2. Calculate Shannon entropy
3. If entropy > 7.5 and not a known compressed format → **Encrypted or Random**
4. If entropy > 7.9 → **Encrypted**
5. Check if data is mostly text (ASCII printable) → **Plain Text**
6. Otherwise → **Binary**

## Example Output

```
🔍 File Analysis Tool v1.0

Analyzing 11 file(s)...

  [00:00:00] [########################################] 11/11 (0s)
================================================================================
ANALYSIS RESULTS
================================================================================
  File                              Type             Entropy      Size
  test_files\archive.zip            Archive (ZIP)    7.94/8.0   3.55 KB
  test_files\file with spaces.txt   Plain Text       2.58/8.0   12.00 B
  test_files\file,with,commas.txt   Plain Text       2.73/8.0   9.00 B
  test_files\output.csv             Plain Text       5.07/8.0   359.00 B
  test_files\plain.txt              Plain Text       4.32/8.0   106.00 B
  test_files\random.bin             Random Data      7.78/8.0   1.00 KB
  test_files\real.pdf               Document (PDF)   7.86/8.0   12.95 KB
  test_files\renamed.dat            Archive (ZIP)    7.94/8.0   3.55 KB
  test_files\test.7z                Archive (ZIP)    3.94/8.0   135.00 B
  test_files\test.pdf               Document (PDF)   4.24/8.0   25.00 B
  test_files\test.txt               Plain Text       2.58/8.0   6.00 B

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------
  • PlainText: 5
  • Document("PDF"): 2
  • Random: 1
  • Archive("ZIP"): 3

  • Average Entropy: 5.18/8.0
  ⚠️ 4 file(s) with high entropy (possibly encrypted/compressed)
```

## Performance

- Efficient byte-level entropy calculation
- Parallel file system traversal for recursive scans
- Minimal memory footprint

## License

MIT or Apache-2.0 (choose your preference)

## Contributing

Contributions welcome! Feel free to:
- Add more magic number signatures
- Improve classification algorithms
- Enhance output formatting
- Add new features

## Troubleshooting

### Windows Build Issues

If you get "linker `link.exe` not found":

1. Install Visual Studio Build Tools with C++ support
2. OR use MinGW: `rustup target add x86_64-pc-windows-gnu` and build with `cargo build --target x86_64-pc-windows-gnu`

### Permission Errors

On Unix systems, you may need to make the binary executable:
```bash
chmod +x target/release/enro
```
