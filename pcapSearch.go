package main

import (
	"compress/gzip"
	"container/heap"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// Constants for performance tuning
const (
	DefaultWorkers  = 0      // 0 means use GOMAXPROCS
	BatchSize       = 1000   // Size of channel buffers
	ChunkSize       = 100000 // Number of packets to process in each chunk
	MaxMemoryChunks = 4      // Maximum number of chunks to keep in memory

	// Size thresholds for automatic mode selection (in bytes)
	// Files larger than these sizes will use more efficient processing modes
	StreamModeThreshold = 500 * 1024 * 1024      // 500MB
	ChunkModeThreshold  = 2 * 1024 * 1024 * 1024 // 2GB
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
	chunkMode := fs.Bool("chunk", false, "Use chunked processing for very large files (lowest memory usage)")
	chunkSizeFlag := fs.Int("chunk-size", ChunkSize, "Number of packets per chunk in chunk mode")
	forceMode := fs.Bool("force-mode", false, "Force the specified mode instead of auto-selecting based on file size")
	autoMode := fs.Bool("auto", true, "Automatically select the best mode based on file size (default: true)")

	// Custom usage message
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s file.pcap [options]\n\n", os.Args[0])
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

	// Determine the appropriate processing mode based on file size if auto mode is enabled
	if *autoMode && !*forceMode {
		fileInfo, err := os.Stat(pcapFile)
		if err == nil {
			fileSize := fileInfo.Size()

			// If the file is compressed, estimate the uncompressed size (typical compression ratio for PCAP is ~3x)
			if strings.HasSuffix(strings.ToLower(pcapFile), ".gz") {
				estimatedUncompressedSize := fileSize * 3
				fileSize = estimatedUncompressedSize
			}

			// Auto-select the appropriate mode based on file size
			if fileSize > ChunkModeThreshold {
				*chunkMode = true
				*streamOutput = false
				fmt.Printf("Auto-selected: Chunk mode for large file (%.2f GB)\n", float64(fileSize)/(1024*1024*1024))
			} else if fileSize > StreamModeThreshold {
				*chunkMode = false
				*streamOutput = true
				fmt.Printf("Auto-selected: Stream mode for medium file (%.2f MB)\n", float64(fileSize)/(1024*1024))
			} else {
				*chunkMode = false
				*streamOutput = false
				fmt.Printf("Auto-selected: Standard mode for small file (%.2f MB)\n", float64(fileSize)/(1024*1024))
			}
		} else {
			fmt.Printf("Warning: Could not determine file size, using specified or default mode: %v\n", err)
		}
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

	// Choose between processing modes based on flags
	var matchCount int
	var err error

	startTime := time.Now()

	// Print which mode is being used
	if *chunkMode {
		fmt.Println("Using: Chunk mode (lowest memory usage, good for extremely large files)")
	} else if *streamOutput {
		fmt.Println("Using: Stream mode (balanced memory usage and performance)")
	} else {
		fmt.Println("Using: Standard mode (fastest for smaller files)")
	}

	if *chunkMode {
		// Chunked processing for very large files with minimal memory usage
		matchCount, err = processPCAPChunked(pcapFile, filter, tempPCAP, numWorkers, *chunkSizeFlag)
	} else if *streamOutput {
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

	// Sort the results chronologically by timestamp to maintain the original packet order
	sort.Slice(results, func(i, j int) bool {
		return results[i].Packet.Metadata().Timestamp.Before(results[j].Packet.Metadata().Timestamp)
	})

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

	// Create packet source and collect all matching packets first
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Create channels for parallel processing
	type matchResult struct {
		ci        gopacket.CaptureInfo
		data      []byte
		timestamp time.Time
	}

	packetChan := make(chan gopacket.Packet, BatchSize)
	doneChan := make(chan struct{})

	var matchMutex sync.Mutex
	var matchResults []matchResult
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var localMatches []matchResult

			for packet := range packetChan {
				if matchFound := checkPacketMatch(packet, filter); matchFound {
					localMatches = append(localMatches, matchResult{
						ci:        packet.Metadata().CaptureInfo,
						data:      packet.Data(),
						timestamp: packet.Metadata().Timestamp,
					})
				}
			}

			// Add all local matches to the global result list with lock protection
			matchMutex.Lock()
			matchResults = append(matchResults, localMatches...)
			matchMutex.Unlock()
		}(i)
	}

	// Start a goroutine to close channels when all workers are done
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	// Feed packets to workers
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}
	close(packetChan)

	<-doneChan // Wait for processing to complete

	// Sort the results chronologically by timestamp
	sort.Slice(matchResults, func(i, j int) bool {
		return matchResults[i].timestamp.Before(matchResults[j].timestamp)
	})

	// Write the sorted results to the file
	for _, match := range matchResults {
		if err := writer.WritePacket(match.ci, match.data); err != nil {
			fmt.Printf("Error writing packet: %v\n", err)
		}
	}

	return len(matchResults), nil
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

// processPCAPChunked processes a PCAP file in chunks to minimize memory usage
// while maintaining packet order
func processPCAPChunked(filename string, filter Filter, outputFile string, numWorkers int, chunkSize int) (int, error) {
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

	// First pass: count total packets in the file (for progress reporting)
	totalPackets, err := countPacketsInFile(pcapPath)
	if err != nil {
		fmt.Printf("Warning: Unable to determine total packet count: %v\n", err)
		totalPackets = 0 // Proceed without knowing the total
	}

	// Process the file in chunks
	var processedPackets, matchCount int
	var tempFiles []string
	var tempFileMutex sync.Mutex
	var chunkNumber int

	for {
		// Open the pcap file for this chunk
		handle, err = pcap.OpenOffline(pcapPath)
		if err != nil {
			return 0, fmt.Errorf("error opening pcap file: %v", err)
		}

		// Set BPF filter if applicable
		bpfFilter := buildBPFFilter(filter)
		if bpfFilter != "" {
			if err = handle.SetBPFFilter(bpfFilter); err != nil {
				fmt.Printf("Warning: could not set BPF filter '%s': %v\n", bpfFilter, err)
			} else {
				fmt.Printf("Using BPF filter: %s\n", bpfFilter)
			}
		}

		// Create packet source with lazy decoding
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions.Lazy = true
		packetSource.DecodeOptions.NoCopy = true
		packets := packetSource.Packets()

		// Skip packets we've already processed
		for i := 0; i < processedPackets; i++ {
			_, more := <-packets
			if !more {
				break
			}
		}

		// Process this chunk
		currentChunk := make([]PacketResult, 0, chunkSize)
		packetsInThisChunk := 0

		// Channels for worker communication
		packetChan := make(chan gopacket.Packet, BatchSize)
		resultChan := make(chan PacketResult, BatchSize)
		doneChan := make(chan struct{})

		var wg sync.WaitGroup

		// Start worker goroutines
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for packet := range packetChan {
					if matchFound := checkPacketMatch(packet, filter); matchFound {
						resultChan <- PacketResult{Packet: packet}
					}
				}
			}(i)
		}

		// Start collector goroutine
		go func() {
			for result := range resultChan {
				currentChunk = append(currentChunk, result)
			}
			close(doneChan)
		}()

		// Process packets until we reach the chunk size or run out
		for packet := range packets {
			packetsInThisChunk++
			processedPackets++

			packetChan <- packet

			// Report progress periodically
			if processedPackets%10000 == 0 && totalPackets > 0 {
				fmt.Printf("Progress: %d/%d packets (%.1f%%)\n",
					processedPackets, totalPackets, float64(processedPackets)/float64(totalPackets)*100)
			}

			if packetsInThisChunk >= chunkSize {
				break
			}
		}

		// Close channels and wait for workers to finish
		close(packetChan)
		wg.Wait()
		close(resultChan)
		<-doneChan

		handle.Close()

		// If we collected matches in this chunk, sort and save to temp file
		if len(currentChunk) > 0 {
			// Sort by timestamp
			sort.Slice(currentChunk, func(i, j int) bool {
				return currentChunk[i].Packet.Metadata().Timestamp.Before(currentChunk[j].Packet.Metadata().Timestamp)
			})

			// Create a temporary file for this chunk
			tempFile, err := createTempChunkFile(currentChunk)
			if err != nil {
				return 0, fmt.Errorf("error creating temp chunk file: %v", err)
			}

			tempFileMutex.Lock()
			tempFiles = append(tempFiles, tempFile)
			tempFileMutex.Unlock()

			matchCount += len(currentChunk)
			chunkNumber++
		}

		// If we've processed all packets or the source is empty, we're done
		if packetsInThisChunk < chunkSize {
			break
		}
	}

	// Clean up temp files when we're done
	defer func() {
		for _, file := range tempFiles {
			os.Remove(file)
		}
	}()

	// Merge all temporary files using a priority queue to maintain order
	err = mergeChunkFiles(tempFiles, writer)
	if err != nil {
		return 0, fmt.Errorf("error merging chunk files: %v", err)
	}

	return matchCount, nil
}

// countPacketsInFile counts the total number of packets in a pcap file
func countPacketsInFile(filename string) (int, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return 0, err
	}
	defer handle.Close()

	// Fast packet counting using BPF that matches everything
	err = handle.SetBPFFilter("ip or not ip") // Match all packets
	if err != nil {
		return 0, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	var count int
	for range packetSource.Packets() {
		count++
	}

	return count, nil
}

// createTempChunkFile creates a temporary PCAP file containing the given packets
func createTempChunkFile(packets []PacketResult) (string, error) {
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "pcapsearch-chunk-*.pcap")
	if err != nil {
		return "", err
	}
	tempFileName := tempFile.Name()

	// Create a pcap writer
	writer := pcapgo.NewWriter(tempFile)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFileName)
		return "", err
	}

	// Write all packets
	for _, result := range packets {
		err = writer.WritePacket(result.Packet.Metadata().CaptureInfo, result.Packet.Data())
		if err != nil {
			tempFile.Close()
			os.Remove(tempFileName)
			return "", err
		}
	}

	tempFile.Close()
	return tempFileName, nil
}

// Define a structure for our priority queue items
type PacketItem struct {
	ci        gopacket.CaptureInfo
	data      []byte
	timestamp time.Time
	index     int // Which reader this came from
}

// Implementation of a priority queue for merging sorted streams
type PriorityQueue []*PacketItem

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// We want the earliest timestamp at the top of the queue
	return pq[i].timestamp.Before(pq[j].timestamp)
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*PacketItem)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*pq = old[0 : n-1]
	return item
}

// mergeChunkFiles merges multiple sorted PCAP files into a single output file
// while maintaining packet order
func mergeChunkFiles(files []string, writer *pcapgo.Writer) error {
	if len(files) == 0 {
		return nil
	}

	fmt.Printf("Merging %d chunk files...\n", len(files))

	// Create readers for each file
	type chunkReader struct {
		handle   *pcap.Handle
		source   *gopacket.PacketSource
		packets  <-chan gopacket.Packet
		fileName string
	}

	readers := make([]*chunkReader, len(files))

	// Open all files first
	for i, file := range files {
		handle, err := pcap.OpenOffline(file)
		if err != nil {
			// Close already opened handles
			for j := 0; j < i; j++ {
				readers[j].handle.Close()
			}
			return fmt.Errorf("error opening chunk file %s: %v", file, err)
		}

		source := gopacket.NewPacketSource(handle, handle.LinkType())
		source.DecodeOptions.Lazy = true
		source.DecodeOptions.NoCopy = true

		readers[i] = &chunkReader{
			handle:   handle,
			source:   source,
			packets:  source.Packets(),
			fileName: file,
		}
	}

	// Make sure we close all readers when done
	defer func() {
		for _, reader := range readers {
			if reader.handle != nil {
				reader.handle.Close()
			}
		}
	}()

	// Initialize priority queue with the first packet from each file
	pq := make(PriorityQueue, 0, len(files))

	for i, reader := range readers {
		if packet, more := <-reader.packets; more {
			pq = append(pq, &PacketItem{
				ci:        packet.Metadata().CaptureInfo,
				data:      packet.Data(),
				timestamp: packet.Metadata().Timestamp,
				index:     i,
			})
		}
	}

	// Only need to heapify if we have more than one file
	if len(pq) > 1 {
		heap.Init(&pq)
	}

	// Merge the files by always taking the packet with the earliest timestamp
	for pq.Len() > 0 {
		// Get the earliest packet
		item := heap.Pop(&pq).(*PacketItem)

		// Write it to the output file
		err := writer.WritePacket(item.ci, item.data)
		if err != nil {
			return fmt.Errorf("error writing merged packet: %v", err)
		}

		// Get the next packet from the same file
		readerIndex := item.index
		if packet, more := <-readers[readerIndex].packets; more {
			// Add the next packet to the queue
			heap.Push(&pq, &PacketItem{
				ci:        packet.Metadata().CaptureInfo,
				data:      packet.Data(),
				timestamp: packet.Metadata().Timestamp,
				index:     readerIndex,
			})
		}
	}

	return nil
}
