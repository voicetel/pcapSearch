# pcapSearch - Advanced SIP Packet Capture Analyzer

pcapSearch is a high-performance command-line tool for searching and extracting SIP (Session Initiation Protocol) traffic from network capture files. It supports both traditional PCAP and modern PCAPNG file formats, and is optimized for processing capture files of any size efficiently.

## Features

- **Multiple Search Criteria**: Filter SIP traffic by source number, destination number, user, user agent, IP address, or Call ID
- **Multiple File Formats**: Support for both PCAP and PCAPNG formats, including compressed (.gz) files
- **Smart Processing Modes**:
  - Auto-selects the most efficient processing mode based on file size
  - Standard mode for small files (fast, in-memory processing)
  - Stream mode for medium files (balanced memory usage and performance)
  - Chunk mode for extremely large files (minimal memory usage)
- **High Performance**:
  - Parallel processing leveraging multiple CPU cores
  - Optimized Berkeley Packet Filter (BPF) pre-filtering
  - Efficient memory usage even for multi-gigabyte captures
- **Chronologically Ordered Output**: All packets are properly ordered by timestamp in the output file
- **Detailed Logging**: Optional verbose mode for debugging and analysis information

## Installation

### Prerequisites

- Go 1.16 or later
- libpcap development libraries

#### Installing libpcap

**Ubuntu/Debian**:
```bash
sudo apt-get install libpcap-dev
```

**RHEL/CentOS/Fedora**:
```bash
sudo yum install libpcap-devel
```

**macOS**:
```bash
brew install libpcap
```

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/voicetel/pcapSearch.git
cd pcapSearch
```

2. Build the application:
```bash
go mod init github.com/voicetel/pcapSearch
go mod tidy
go build pcapSearch.go
```

## Usage

```
./pcapSearch file.pcap|file.pcapng|file.pcap.gz|file.pcapng.gz [options]
```

### Options

```
  -auto
    	Automatically select the best mode based on file size (default: true)
  -chunk
    	Use chunked processing for very large files (lowest memory usage)
  -chunk-size int
    	Number of packets per chunk in chunk mode (default 100000)
  -dst string
    	Filter by DST Number
  -force-mode
    	Force the specified mode instead of auto-selecting based on file size
  -id string
    	Filter by Call ID
  -ip string
    	Filter by IP Address
  -o string
    	Output PCAP file (default: timestamp.pcap)
  -src string
    	Filter by SRC Number
  -stream
    	Stream output directly to file (reduces memory usage)
  -ua string
    	Filter by User Agent
  -usr string
    	Filter by User
  -v	Verbose mode: display detailed processing information
  -workers string
    	Number of worker goroutines (0 = use all CPU cores, N% = use percentage of cores)
```

### Examples

**Search for a specific Call ID**:
```bash
./pcapSearch capture.pcap -id "a84b4c76e66710"
```

**Search for calls from a specific phone number (source)**:
```bash
./pcapSearch capture.pcap -src "+15551234567"
```

**Search for calls to a specific phone number (destination)**:
```bash
./pcapSearch capture.pcap -dst "+15559876543"
```

**Search for calls between two specific numbers**:
```bash
./pcapSearch capture.pcap -src "+15551234567" -dst "+15559876543"
```

**Search for SIP traffic from specific IP and extract to a named output file**:
```bash
./pcapSearch capture.pcapng -ip 192.168.1.100 -o extracted.pcap
```

**Search for a specific User-Agent string**:
```bash
./pcapSearch capture.pcap -ua "Asterisk PBX"
```

**Search for a specific SIP user**:
```bash
./pcapSearch capture.pcap -usr "alice@example.com"
```

**Search for a specific source number in a large capture file, using 50% of CPU cores**:
```bash
./pcapSearch large_capture.pcap.gz -src "1234567890" -workers 50%
```

**Process a very large file in verbose mode with custom chunk size**:
```bash
./pcapSearch huge_capture.pcapng -chunk -chunk-size 200000 -v -src "12345678"
```

**Search for calls to a toll-free number with verbose output**:
```bash
./pcapSearch capture.pcap -dst "1800" -v
```

**Extract all SIP traffic from a specific IP during a specific call**:
```bash
./pcapSearch capture.pcap -ip 10.0.0.100 -id "call-12345@bob.example.com"
```

**Extract each call to a separate file**:
```bash
./pcapSearch capture.pcap -src "+15551234567" -split
```

**Search for multiple calls and organize them by Call-ID**:
```bash
./pcapSearch capture.pcapng -ip 10.0.0.100 -split
```  -split
    	Split output into separate files by Call-ID
## Processing Modes

pcapSearch offers three processing modes, automatically selected based on file size:

1. **Standard Mode** (default for files < 500MB):
   - Processes the entire file in memory
   - Fastest for small to medium files
   - Highest memory usage

2. **Stream Mode** (for files between 500MB and 2GB):
   - Collects and sorts matches before writing to output
   - Balances memory usage and performance

3. **Chunk Mode** (for files > 2GB):
   - Processes the file in smaller chunks
   - Each chunk is processed, sorted, and saved temporarily
   - Chunks are merged in chronological order at the end
   - Minimal memory usage, can handle files of any size

## Technical Details

- Utilizes Berkeley Packet Filter (BPF) for efficient pre-filtering at the capture library level
- Implements a multi-worker processing model for parallel packet analysis
- Uses priority queue-based merging for preserving packet order in chunked processing
- Detects PCAPNG files by signature (0x0A0D0D0A) rather than relying only on file extension
- Preserves packet timestamps in all processing modes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
