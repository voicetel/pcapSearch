# pcapSearch Windows Installation Guide

This guide provides step-by-step instructions for installing and running pcapSearch on Windows systems.

## Prerequisites

Before you begin, make sure you have the following software installed:

1. **Go Programming Language**
2. **WinPcap or Npcap**
3. **MinGW or MSYS2 (for GCC)**
4. **Git** (optional, for cloning the repository)

## Installation Steps

### 1. Install Go

1. Download the Windows MSI installer from [https://golang.org/dl/](https://golang.org/dl/)
2. Run the installer and follow the prompts
3. Verify the installation by opening Command Prompt and typing:
   ```
   go version
   ```

### 2. Install Npcap (Recommended) or WinPcap

#### Option 1: Npcap (Recommended)
1. Download Npcap from [https://nmap.org/npcap/](https://nmap.org/npcap/)
2. During installation, select **"Install Npcap in WinPcap API-compatible Mode"**
3. Complete the installation

#### Option 2: WinPcap
1. Download WinPcap from [https://www.winpcap.org/](https://www.winpcap.org/)
2. Run the installer and follow the prompts

### 3. Install MinGW/MSYS2 (for GCC)

1. Download MSYS2 installer from [https://www.msys2.org/](https://www.msys2.org/)
2. Run the installer and follow the prompts
3. After installation, open the MSYS2 MINGW64 shell
4. Update the package database and core packages:
   ```
   pacman -Syu
   ```
   (You may need to close and reopen the shell after this)
5. Install GCC and Make:
   ```
   pacman -S mingw-w64-x86_64-gcc make
   ```
6. Add MinGW to your PATH environment variable:
   - Right-click on "This PC" or "My Computer"
   - Select "Properties"
   - Click on "Advanced system settings"
   - Click on "Environment Variables"
   - In the "System variables" section, select "Path" and click "Edit"
   - Add the path to your MinGW bin directory (typically `C:\msys64\mingw64\bin`)
   - Click "OK" on all dialogs

### 4. Get the pcapSearch Code

#### Option 1: Using Git
1. Install Git from [https://git-scm.com/download/win](https://git-scm.com/download/win)
2. Open Command Prompt and run:
   ```
   git clone https://github.com/yourusername/pcapSearch.git
   cd pcapSearch
   ```

#### Option 2: Download ZIP
1. Download the ZIP file of the repository
2. Extract the contents to a folder
3. Open Command Prompt and navigate to that folder

## Building pcapSearch

1. Open Command Prompt as Administrator
2. Navigate to the pcapSearch directory
3. Install required Go packages:
   ```
   go get github.com/google/gopacket
   go get github.com/google/gopacket/pcap
   go get github.com/google/gopacket/layers
   go get github.com/google/gopacket/pcapgo
   ```
4. Set environment variables to locate Npcap/WinPcap:
   
   For Npcap (64-bit):
   ```
   set CGO_CFLAGS=-I"C:\Program Files\Npcap\Include"
   set CGO_LDFLAGS=-L"C:\Program Files\Npcap\Lib\x64" -lwpcap
   ```
   
   For Npcap (32-bit):
   ```
   set CGO_CFLAGS=-I"C:\Program Files\Npcap\Include"
   set CGO_LDFLAGS=-L"C:\Program Files\Npcap\Lib" -lwpcap
   ```
   
   For WinPcap:
   ```
   set CGO_CFLAGS=-I"C:\WinPcap\Include"
   set CGO_LDFLAGS=-L"C:\WinPcap\Lib" -lwpcap
   ```

5. Enable CGO:
   ```
   set CGO_ENABLED=1
   ```

6. Build the application:
   ```
   go build -o pcapSearch.exe pcapSearch.go
   ```

## Running pcapSearch on Windows

The syntax for running pcapSearch on Windows is the same as on other platforms:

```
pcapSearch.exe [options] file.pcap|file.pcapng|file.pcap.gz
```

### Examples

**Search for calls from a specific phone number**:
```
pcapSearch.exe -src "+15551234567" C:\path\to\capture.pcap
```

**Split calls into separate files by Call-ID**:
```
pcapSearch.exe -ip 192.168.1.100 -split C:\path\to\capture.pcapng
```

**Process a large file with chunk mode**:
```
pcapSearch.exe -chunk -src "12345678" C:\path\to\large_capture.pcap
```

## Windows-Specific Tips

### 1. Path Handling

Windows paths use backslashes, which need to be escaped in command-line arguments:
```
pcapSearch.exe -o C:\\output\\result.pcap C:\\input\\capture.pcap
```

Alternatively, you can use forward slashes which work fine on Windows:
```
pcapSearch.exe -o C:/output/result.pcap C:/input/capture.pcap
```

### 2. Output Directory with `-split`

When using the `-split` option, pcapSearch creates a directory named `calls_TIMESTAMP`:
```
pcapSearch.exe -split -src "12345" capture.pcap
```

Creates a directory like: `calls_1683721245` with individual call files inside.

### 3. Command Prompt vs PowerShell

- **Command Prompt** uses `"` for quoting
- **PowerShell** can be confusing with quoting - if you have issues, try using single quotes `'` for filter strings

### 4. Performance Settings

- Use `-workers` to control CPU usage:
  ```
  pcapSearch.exe -workers 50% capture.pcap
  ```

- For large files, use auto-mode (default) or explicitly set `-chunk`:
  ```
  pcapSearch.exe -chunk capture.pcap
  ```

## Troubleshooting

### Common Errors

#### "libpcap.so/libwpcap.dll/wpcap.dll not found"
- Make sure Npcap or WinPcap is installed
- Verify the CGO environment variables point to the correct locations
- For Npcap, make sure you installed with WinPcap API-compatibility mode

#### Compiler Errors
- Ensure GCC is installed and in your PATH
- Verify that you have CGO_ENABLED=1
- Make sure the Include and Lib paths in CGO_CFLAGS and CGO_LDFLAGS are correct

#### Permission Issues
- Run Command Prompt as Administrator
- Make sure you have write permissions in the output directory

#### "File not found" Errors
- Make sure file paths are correctly escaped
- Try using absolute paths instead of relative paths

### Getting Help

If you continue to have issues, please:

1. Run in verbose mode to get more information:
   ```
   pcapSearch.exe -v capture.pcap
   ```

2. Check that your Npcap/WinPcap installation is working using a tool like Wireshark

3. Create an issue on the project repository with details about the error and your setup

## Creating Capture Files on Windows

If you need to create your own capture files:

### Using Wireshark
1. Download and install Wireshark from [https://www.wireshark.org/](https://www.wireshark.org/)
2. Select an interface and start capturing
3. Save the file as .pcap or .pcapng

### Using Npcap Command-Line Tools
If you installed Npcap, you can use WinDump (the Windows version of tcpdump):
```
"C:\Program Files\Npcap\windump.exe" -i 3 -w capture.pcap
```
(Replace `3` with your interface number, which you can see by running `windump -D`)
