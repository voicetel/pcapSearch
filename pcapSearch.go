package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Filter represents the SIP filter criteria
type Filter struct {
	SourceNumber string
	DestNumber   string
	User         string
	UserAgent    string
	IPAddress    string
	CallID       string
}

// PacketResult represents a matching packet
type PacketResult struct {
	Packet gopacket.Packet
}

func main() {
	// Create a custom flagset that doesn't require flags to be before arguments
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Define command line flags
	srcNumber := fs.String("src", "", "Filter by SRC Number")
	dstNumber := fs.String("dst", "", "Filter by DST Number")
	user := fs.String("usr", "", "Filter by User")
	userAgent := fs.String("ua", "", "Filter by User Agent")
	ipAddr := fs.String("ip", "", "Filter by IP Address")
	callID := fs.String("id", "", "Filter by Call ID")
	outputFile := fs.String("o", "", "Output PCAP file (default: timestamp.pcap)")

	// Custom usage message
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] file.pcap|file.pcap.gz\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported file formats: .pcap, .pcap.gz, .gz\n")
	}

	// First, find the pcap file from the arguments
	var pcapFile string
	var args []string

	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") &&
			(strings.HasSuffix(strings.ToLower(arg), ".pcap") ||
				strings.HasSuffix(strings.ToLower(arg), ".pcap.gz") ||
				strings.HasSuffix(strings.ToLower(arg), ".gz")) {
			pcapFile = arg
		} else {
			args = append(args, arg)
		}
	}

	// Parse the flags from the remaining arguments
	if err := fs.Parse(args); err != nil {
		fmt.Println("Error parsing flags:", err)
		fs.Usage()
		os.Exit(1)
	}

	// Check if a pcap file was found
	if pcapFile == "" {
		fmt.Println("Error: No PCAP file specified")
		fs.Usage()
		os.Exit(1)
	}

	// Verify the pcap file exists
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		fmt.Printf("Error: PCAP file %s does not exist\n", pcapFile)
		os.Exit(1)
	}

	// Create filter criteria
	filter := Filter{
		SourceNumber: *srcNumber,
		DestNumber:   *dstNumber,
		User:         *user,
		UserAgent:    *userAgent,
		IPAddress:    *ipAddr,
		CallID:       *callID,
	}

	/* Print filter info for debugging
	fmt.Println("Filter criteria:")
	fmt.Printf("  Source Number: '%s'\n", filter.SourceNumber)
	fmt.Printf("  Dest Number: '%s'\n", filter.DestNumber)
	fmt.Printf("  User: '%s'\n", filter.User)
	fmt.Printf("  User Agent: '%s'\n", filter.UserAgent)
	fmt.Printf("  IP Address: '%s'\n", filter.IPAddress)
	fmt.Printf("  Call ID: '%s'\n", filter.CallID)
	*/

	// Check if any filter was provided
	if filter.isEmpty() {
		fmt.Println("Error: No filter criteria specified")
		fs.Usage()
		os.Exit(1)
	}

	fmt.Printf("Processing PCAP file: %s\n", pcapFile)
	if strings.HasSuffix(strings.ToLower(pcapFile), ".gz") {
		fmt.Println("Detected compressed gzip file - will uncompress automatically")
	}

	// Process the PCAP file
	matchingPackets, err := processPCAP(pcapFile, filter)
	if err != nil {
		log.Fatalf("Error processing PCAP file: %v", err)
	}

	// Check if any matches were found
	if len(matchingPackets) == 0 {
		fmt.Println("Call(s) not found!")
		os.Exit(1)
	}

	// Write matching packets to a temporary PCAP file
	tempPCAP := fmt.Sprintf("%d.pcap", time.Now().Unix())
	if *outputFile != "" {
		tempPCAP = *outputFile
	}

	err = writePacketsToFile(tempPCAP, matchingPackets)
	if err != nil {
		log.Fatalf("Error writing output PCAP: %v", err)
	}

	fmt.Printf("Found %d matching packets. Output saved to %s\n", len(matchingPackets), tempPCAP)
}

// uncompressGzipFile takes a gzip file path and returns the path to a temporary
// uncompressed file. The caller is responsible for removing the temporary file.
func uncompressGzipFile(gzipFilePath string) (string, error) {
	// Open the gzip file
	gzipFile, err := os.Open(gzipFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open gzip file: %v", err)
	}
	defer gzipFile.Close()

	// Create a gzip reader
	gzipReader, err := gzip.NewReader(gzipFile)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzipReader.Close()

	// Create a temporary file to hold the uncompressed data
	// We'll use the original filename without the .gz extension if possible
	baseFilename := filepath.Base(gzipFilePath)
	if strings.HasSuffix(baseFilename, ".gz") {
		baseFilename = strings.TrimSuffix(baseFilename, ".gz")
	}

	tempFile, err := os.CreateTemp("", "uncompressed-"+baseFilename)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer tempFile.Close()

	// Copy the uncompressed data to the temporary file
	_, err = io.Copy(tempFile, gzipReader)
	if err != nil {
		// Clean up the temp file if we encounter an error
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to uncompress data: %v", err)
	}

	fmt.Printf("Successfully uncompressed %s to temporary file\n", gzipFilePath)
	return tempFile.Name(), nil
}
func (f Filter) isEmpty() bool {
	return f.SourceNumber == "" && f.DestNumber == "" && f.User == "" && f.UserAgent == "" && f.IPAddress == "" && f.CallID == ""
}

// processPCAP processes the PCAP file with the given filter
func processPCAP(filename string, filter Filter) ([]PacketResult, error) {
	var handle *pcap.Handle
	var err error

	// Check if the file is compressed with gzip
	isCompressed := strings.HasSuffix(strings.ToLower(filename), ".gz")

	if isCompressed {
		// Create a temporary file to hold the uncompressed data
		tempFile, err := uncompressGzipFile(filename)
		if err != nil {
			return nil, fmt.Errorf("error uncompressing gzip file: %v", err)
		}
		defer os.Remove(tempFile) // Clean up the temporary file when done

		// Open the uncompressed temporary pcap file
		handle, err = pcap.OpenOffline(tempFile)
	} else {
		// Open the regular pcap file
		handle, err = pcap.OpenOffline(filename)
	}

	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Set BPF filter for IP packets if an IP filter is provided
	if filter.IPAddress != "" {
		err = handle.SetBPFFilter(fmt.Sprintf("host %s", filter.IPAddress))
		if err != nil {
			return nil, fmt.Errorf("error setting BPF filter: %v", err)
		}
	}

	// Create channels for packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()
	resultChan := make(chan PacketResult)

	var wg sync.WaitGroup
	wg.Add(1)

	// Start worker goroutine to process packets
	go func() {
		defer wg.Done()
		for packet := range packetChan {
			matchFound := processPacket(packet, filter)
			if matchFound {
				resultChan <- PacketResult{
					Packet: packet,
				}
			}
		}
		close(resultChan)
	}()

	// Collect results
	var results []PacketResult
	for result := range resultChan {
		results = append(results, result)
	}

	wg.Wait()
	return results, nil
}

// processPacket processes a single packet and returns true if it matches the filter
func processPacket(packet gopacket.Packet, filter Filter) bool {
	// Check for SIP layer
	sipLayer := packet.Layer(layers.LayerTypeSIP)
	if sipLayer == nil {
		return false
	}

	sip, ok := sipLayer.(*layers.SIP)
	if !ok {
		return false
	}

	// Get all SIP headers from the raw message
	headerMap := extractSIPHeaders(sip)

	// Apply source number filter
	if filter.SourceNumber != "" {
		fromField := headerMap["From"]
		paiField := headerMap["P-Asserted-Identity"]

		if !strings.Contains(fromField, filter.SourceNumber) &&
			!strings.Contains(paiField, filter.SourceNumber) {
			return false
		}
	}

	// Apply destination number filter
	if filter.DestNumber != "" {
		toField := headerMap["To"]
		if !strings.Contains(toField, filter.DestNumber) {
			return false
		}
	}

	// Apply user filter
	if filter.User != "" {
		contactField := headerMap["Contact"]
		if !strings.Contains(contactField, filter.User) {
			return false
		}
	}

	// Apply User-Agent filter
	if filter.UserAgent != "" {
		uaField := headerMap["User-Agent"]
		if !strings.Contains(uaField, filter.UserAgent) {
			return false
		}
	}

	// Apply Call-ID filter
	if filter.CallID != "" {
		callIDField := headerMap["Call-ID"]
		if !strings.Contains(callIDField, filter.CallID) {
			return false
		}
	}

	// If all filters passed, it's a match
	return true
}

// extractSIPHeaders extracts all header values from the SIP message
func extractSIPHeaders(sip *layers.SIP) map[string]string {
	headers := make(map[string]string)

	// Extract headers from raw content
	rawMsg := string(sip.Contents)
	lines := strings.Split(rawMsg, "\r\n")

	// Skip the first line (request/status line)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break // End of headers
		}

		// Find the first colon
		colonPos := strings.Index(line, ":")
		if colonPos > 0 {
			headerName := line[:colonPos]
			headerValue := ""
			if colonPos+1 < len(line) {
				headerValue = strings.TrimSpace(line[colonPos+1:])
			}
			headers[headerName] = headerValue
		}
	}

	return headers
}

// writePacketsToFile writes the matching packets to a new PCAP file
func writePacketsToFile(filename string, packets []PacketResult) error {
	// Create a new pcap file
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Create a pcap writer
	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		return err
	}

	// Write each packet
	for _, result := range packets {
		err = writer.WritePacket(result.Packet.Metadata().CaptureInfo, result.Packet.Data())
		if err != nil {
			return err
		}
	}

	return nil
}
