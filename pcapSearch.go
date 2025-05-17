package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

// Constants for performance tuning
const (
	DefaultWorkers = 0 // 0 means use GOMAXPROCS
	BatchSize      = 1000
)

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
	workers := fs.Int("workers", DefaultWorkers, "Number of worker goroutines (0 = use all CPU cores)")
	streamOutput := fs.Bool("stream", false, "Stream output directly to file (reduces memory usage)")

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

	// Check if any filter was provided
	if filter.isEmpty() {
		fmt.Println("Error: No filter criteria specified")
		fs.Usage()
		os.Exit(1)
	}

	// Set the number of workers
	numWorkers := *workers
	if numWorkers <= 0 {
		numWorkers = runtime.GOMAXPROCS(0)
	}

	fmt.Printf("Processing PCAP file: %s with %d workers\n", pcapFile, numWorkers)
	if strings.HasSuffix(strings.ToLower(pcapFile), ".gz") {
		fmt.Println("Detected compressed gzip file - will uncompress automatically")
	}

	// Setting output file
	tempPCAP := fmt.Sprintf("%d.pcap", time.Now().Unix())
	if *outputFile != "" {
		tempPCAP = *outputFile
	}

	// Choose between memory-optimized streaming or in-memory processing
	var matchCount int
	var err error

	startTime := time.Now()

	if *streamOutput {
		// Stream output directly to file (memory efficient)
		matchCount, err = processPCAPStreaming(pcapFile, filter, tempPCAP, numWorkers)
	} else {
		// Process in memory (faster for smaller files)
		var matchingPackets []PacketResult
		matchingPackets, err = processPCAP(pcapFile, filter, numWorkers)
		if err == nil {
			matchCount = len(matchingPackets)
			if matchCount > 0 {
				err = writePacketsToFile(tempPCAP, matchingPackets)
			}
		}
	}

	processingTime := time.Since(startTime)

	if err != nil {
		log.Fatalf("Error processing PCAP file: %v", err)
	}

	// Check if any matches were found
	if matchCount == 0 {
		fmt.Println("Call(s) not found!")
		os.Exit(1)
	}

	fmt.Printf("Found %d matching packets in %v. Output saved to %s\n",
		matchCount, processingTime, tempPCAP)
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

// buildBPFFilter creates an optimized BPF filter based on available filter criteria
func buildBPFFilter(filter Filter) string {
	var filters []string

	// Filter by IP if specified
	if filter.IPAddress != "" {
		filters = append(filters, fmt.Sprintf("host %s", filter.IPAddress))
	}

	// Always filter for potential SIP traffic (common SIP ports)
	// SIP typically uses port 5060 for non-encrypted and 5061 for TLS
	filters = append(filters, "(port 5060 or port 5061)")

	// Combine all filters with AND
	return strings.Join(filters, " and ")
}

// processPCAP processes the PCAP file with the given filter using multiple workers
func processPCAP(filename string, filter Filter, numWorkers int) ([]PacketResult, error) {
	var handle *pcap.Handle
	var err error

	// Check if the file is compressed with gzip
	isCompressed := strings.HasSuffix(strings.ToLower(filename), ".gz")

	var pcapPath string
	if isCompressed {
		// Create a temporary file to hold the uncompressed data
		pcapPath, err = uncompressGzipFile(filename)
		if err != nil {
			return nil, fmt.Errorf("error uncompressing gzip file: %v", err)
		}
		defer os.Remove(pcapPath) // Clean up the temporary file when done
	} else {
		pcapPath = filename
	}

	// Open the pcap file
	handle, err = pcap.OpenOffline(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Set BPF filter to reduce the number of packets processed
	bpfFilter := buildBPFFilter(filter)
	if bpfFilter != "" {
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			fmt.Printf("Warning: could not set BPF filter '%s': %v\n", bpfFilter, err)
			// Continue without the filter rather than failing
		} else {
			fmt.Printf("Using BPF filter: %s\n", bpfFilter)
		}
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true // Enable lazy decoding for better performance
	packetSource.DecodeOptions.NoCopy = true

	// Create channels for parallel processing
	packetChan := make(chan gopacket.Packet, BatchSize)
	resultChan := make(chan PacketResult, BatchSize)
	doneChan := make(chan struct{})

	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			processPacketsWorker(packetChan, resultChan, filter)
		}(i)
	}

	// Start a goroutine to close the result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
		close(doneChan)
	}()

	// Start a goroutine to feed packets to workers
	go func() {
		for packet := range packetSource.Packets() {
			packetChan <- packet
		}
		close(packetChan)
	}()

	// Collect results
	var results []PacketResult
	for result := range resultChan {
		results = append(results, result)
	}

	<-doneChan // Wait for processing to complete
	return results, nil
}

// processPCAPStreaming processes the PCAP file and streams matches directly to output file
func processPCAPStreaming(filename string, filter Filter, outputFile string, numWorkers int) (int, error) {
	var handle *pcap.Handle
	var err error

	// Check if the file is compressed with gzip
	isCompressed := strings.HasSuffix(strings.ToLower(filename), ".gz")

	var pcapPath string
	if isCompressed {
		// Create a temporary file to hold the uncompressed data
		pcapPath, err = uncompressGzipFile(filename)
		if err != nil {
			return 0, fmt.Errorf("error uncompressing gzip file: %v", err)
		}
		defer os.Remove(pcapPath) // Clean up the temporary file when done
	} else {
		pcapPath = filename
	}

	// Open the pcap file
	handle, err = pcap.OpenOffline(pcapPath)
	if err != nil {
		return 0, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Set BPF filter to reduce the number of packets processed
	bpfFilter := buildBPFFilter(filter)
	if bpfFilter != "" {
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			fmt.Printf("Warning: could not set BPF filter '%s': %v\n", bpfFilter, err)
		} else {
			fmt.Printf("Using BPF filter: %s\n", bpfFilter)
		}
	}

	// Create output file
	f, err := os.Create(outputFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Create a pcap writer
	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		return 0, err
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Create channels for parallel processing
	type writerJob struct {
		ci   gopacket.CaptureInfo
		data []byte
	}

	packetChan := make(chan gopacket.Packet, BatchSize)
	matchChan := make(chan writerJob, BatchSize)
	doneChan := make(chan struct{})

	var matchCount atomic.Int32
	var wgWorkers, wgWriter sync.WaitGroup

	// Start the writer goroutine
	wgWriter.Add(1)
	go func() {
		defer wgWriter.Done()
		for job := range matchChan {
			if err := writer.WritePacket(job.ci, job.data); err != nil {
				fmt.Printf("Error writing packet: %v\n", err)
			}
		}
	}()

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wgWorkers.Add(1)
		go func(workerID int) {
			defer wgWorkers.Done()
			for packet := range packetChan {
				if matchFound := checkPacketMatch(packet, filter); matchFound {
					matchCount.Add(1)
					matchChan <- writerJob{
						ci:   packet.Metadata().CaptureInfo,
						data: packet.Data(),
					}
				}
			}
		}(i)
	}

	// Start a goroutine to close channels when all workers are done
	go func() {
		wgWorkers.Wait()
		close(matchChan)
		wgWriter.Wait()
		close(doneChan)
	}()

	// Feed packets to workers
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}
	close(packetChan)

	<-doneChan // Wait for processing to complete
	return int(matchCount.Load()), nil
}

// processPacketsWorker processes packets from a channel and sends matches to resultChan
func processPacketsWorker(packetChan <-chan gopacket.Packet, resultChan chan<- PacketResult, filter Filter) {
	for packet := range packetChan {
		if matchFound := checkPacketMatch(packet, filter); matchFound {
			resultChan <- PacketResult{
				Packet: packet,
			}
		}
	}
}

// checkPacketMatch checks if a packet matches the filter criteria
// This is an optimized version of the original processPacket function
func checkPacketMatch(packet gopacket.Packet, filter Filter) bool {
	// Check for SIP layer - early exit if not present
	sipLayer := packet.Layer(layers.LayerTypeSIP)
	if sipLayer == nil {
		return false
	}

	sip, ok := sipLayer.(*layers.SIP)
	if !ok {
		return false
	}

	// Quick check for Call-ID filter (most specific and efficient)
	if filter.CallID != "" {
		rawMsg := string(sip.Contents)
		if !strings.Contains(rawMsg, filter.CallID) {
			return false
		}
	}

	// Get all SIP headers from the raw message (only if we need them)
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

	// If we already checked Call-ID in the quick check and it passed, we don't need to check again

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
