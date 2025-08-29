package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/chunker"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"time"
)

// ================================================================================
// CHUNKING DEMONSTRATION PROGRAM
// This program shows how to chunk a steganographic image for DNS transport
// ================================================================================

func main() {
	// Command line flags
	inputFile := flag.String("input", "", "Input file to chunk (image or data)")
	outputDir := flag.String("output", "chunks", "Output directory for chunk files")
	encoding := flag.String("encoding", "base32", "Encoding type (hex or base32)")
	simulate := flag.Bool("simulate", false, "Simulate DNS records")
	reassemble := flag.Bool("reassemble", false, "Reassemble chunks from directory")
	verbose := flag.Bool("verbose", false, "Show detailed output")

	flag.Parse()

	fmt.Println("🧩 DNS CHUNKING SYSTEM DEMONSTRATION")

	if *reassemble {
		demonstrateReassembly(*outputDir, *verbose)
		return
	}

	if *inputFile == "" {
		// Create demo stego image if no input provided
		fmt.Println("\n📝 No input file specified, creating demo steganographic image...")
		*inputFile = createDemoStegoImage()
	}

	// Read input file
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("❌ Error reading file: %v\n", err)
		return
	}

	fmt.Printf("\n📁 Input file: %s\n", *inputFile)
	fmt.Printf("📊 File size: %d bytes\n", len(data))

	// Demonstrate chunking
	demonstrateChunking(data, *encoding, *outputDir, *simulate, *verbose)
}

func demonstrateChunking(data []byte, encoding, outputDir string, simulate, verbose bool) {

	fmt.Println("STEP 1: CHUNKING ANALYSIS")

	// Create chunker with configuration
	config := chunker.ChunkerConfig{
		Encoding:      encoding,
		DNSNamePrefix: "covert.example.com",
	}

	chk := chunker.NewChunker(config)

	// Perform chunking
	startTime := time.Now()
	msg, err := chk.ChunkMessage(data)
	if err != nil {
		fmt.Printf("❌ Chunking failed: %v\n", err)
		return
	}
	chunkTime := time.Since(startTime)

	// Display statistics
	fmt.Printf("\n📈 Chunking Statistics:\n")
	fmt.Printf("   Encoding method: %s\n", strings.ToUpper(encoding))
	fmt.Printf("   Chunks created: %d\n", len(msg.Chunks))
	fmt.Printf("   Processing time: %v\n", chunkTime)
	fmt.Printf("   Message ID: %s\n", hex.EncodeToString(msg.ID[:8]))

	// Calculate efficiency
	totalEncoded := 0
	for _, chunk := range msg.Chunks {
		totalEncoded += len(chunk.Encoded)
	}

	efficiency := float64(len(data)) / float64(totalEncoded) * 100
	fmt.Printf("\n📊 Efficiency Analysis:\n")
	fmt.Printf("   Original size: %d bytes\n", len(data))
	fmt.Printf("   Total encoded: %d bytes\n", totalEncoded)
	fmt.Printf("   Efficiency: %.1f%%\n", efficiency)
	fmt.Printf("   Expansion factor: %.2fx\n", float64(totalEncoded)/float64(len(data)))

	// DNS-specific calculations
	fmt.Printf("\n🌐 DNS Transport Estimates:\n")
	fmt.Printf("   DNS TXT records needed: %d\n", len(msg.Chunks))
	fmt.Printf("   @ 10 queries/sec: %.1f seconds\n", float64(len(msg.Chunks))/10)
	fmt.Printf("   @ 50 queries/sec: %.1f seconds\n", float64(len(msg.Chunks))/50)
	fmt.Printf("   @ 100 queries/sec: %.1f seconds\n", float64(len(msg.Chunks))/100)

	if verbose {

		fmt.Println("STEP 2: CHUNK DETAILS")

		// Show first few chunks
		numToShow := 3
		if len(msg.Chunks) < numToShow {
			numToShow = len(msg.Chunks)
		}

		for i := 0; i < numToShow; i++ {
			chunk := msg.Chunks[i]
			fmt.Printf("\n📦 Chunk %d/%d:\n", i+1, len(msg.Chunks))
			fmt.Printf("   Sequence: %d\n", chunk.Metadata.Sequence)
			fmt.Printf("   Payload size: %d bytes\n", len(chunk.Payload))
			fmt.Printf("   Encoded size: %d chars\n", len(chunk.Encoded))
			fmt.Printf("   Checksum: %08x\n", chunk.Metadata.Checksum)
			fmt.Printf("   DNS name: %s\n", chunk.RecordName)

			if i == 0 {
				// Show encoded preview
				preview := chunk.Encoded
				if len(preview) > 60 {
					preview = preview[:60] + "..."
				}
				fmt.Printf("   Encoded: %s\n", preview)
			}
		}

		if len(msg.Chunks) > numToShow {
			fmt.Printf("\n   ... and %d more chunks\n", len(msg.Chunks)-numToShow)
		}
	}

	// Save chunks to files
	if outputDir != "" {
		fmt.Println("STEP 3: SAVING CHUNKS")

		err = saveChunks(msg, outputDir)
		if err != nil {
			fmt.Printf("❌ Error saving chunks: %v\n", err)
			return
		}

		fmt.Printf("✅ Saved %d chunks to directory: %s/\n", len(msg.Chunks), outputDir)
	}

	// Simulate DNS records
	if simulate {

		fmt.Println("STEP 4: DNS SIMULATION")

		simulateDNSRecords(msg)
	}

	// Demonstrate reassembly

	fmt.Println("STEP 5: REASSEMBLY VERIFICATION")

	// Test immediate reassembly
	reassembled, err := chk.ReassembleMessage(msg.Chunks)
	if err != nil {
		fmt.Printf("❌ Reassembly failed: %v\n", err)
		return
	}

	if len(reassembled) == len(data) {
		fmt.Printf("✅ Reassembly successful: %d bytes recovered\n", len(reassembled))

		// Verify content
		match := true
		for i := range data {
			if data[i] != reassembled[i] {
				match = false
				break
			}
		}

		if match {
			fmt.Println("✅ Data integrity verified - perfect reconstruction!")
		} else {
			fmt.Println("⚠️  Data mismatch detected")
		}
	}

	fmt.Println("🎯 CHUNKING DEMONSTRATION COMPLETE")

	// Educational summary
	fmt.Println("\n📚 KEY LESSONS LEARNED:")
	fmt.Printf("1. Your %d-byte file required %d DNS TXT records\n", len(data), len(msg.Chunks))
	fmt.Printf("2. Each chunk carries %d bytes of metadata overhead\n", chunker.METADATA_OVERHEAD)
	fmt.Printf("3. %s encoding resulted in %.1fx expansion\n",
		strings.ToUpper(encoding), float64(totalEncoded)/float64(len(data)))
	fmt.Println("4. Chunks are self-contained and can arrive out of order")
	fmt.Println("5. Checksums ensure data integrity during transport")

	fmt.Println("\n💡 NEXT STEPS:")
	fmt.Println("   1. Upload these chunks to a DNS server as TXT records")
	fmt.Println("   2. Query the DNS server to retrieve chunks")
	fmt.Println("   3. Reassemble chunks to recover the original image")
	fmt.Println("   4. Decode the steganographic image to extract the message")
}

func saveChunks(msg *chunker.Message, outputDir string) error {
	// Create output directory
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return err
	}

	// Save manifest file
	manifestPath := fmt.Sprintf("%s/manifest.txt", outputDir)
	manifest, err := os.Create(manifestPath)
	if err != nil {
		return err
	}
	defer manifest.Close()

	fmt.Fprintf(manifest, "Message ID: %s\n", hex.EncodeToString(msg.ID[:]))
	fmt.Fprintf(manifest, "Total Chunks: %d\n", len(msg.Chunks))
	fmt.Fprintf(manifest, "Encoding: %s\n", msg.Encoding)
	fmt.Fprintf(manifest, "Created: %s\n", msg.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(manifest, "\n")

	// Save each chunk
	for i, chunk := range msg.Chunks {
		// Save as DNS zone file format
		filename := fmt.Sprintf("%s/chunk_%03d.txt", outputDir, i)
		file, err := os.Create(filename)
		if err != nil {
			return err
		}

		// Write DNS record format
		fmt.Fprintf(file, "; Chunk %d of %d\n", chunk.Metadata.Sequence+1, chunk.Metadata.TotalChunks)
		fmt.Fprintf(file, "; Message ID: %s\n", hex.EncodeToString(chunk.Metadata.MessageID[:8]))
		fmt.Fprintf(file, "; Checksum: %08x\n", chunk.Metadata.Checksum)
		fmt.Fprintf(file, "\n")
		fmt.Fprintf(file, "%s. 300 IN TXT \"%s\"\n", chunk.RecordName, chunk.Encoded)

		file.Close()

		// Add to manifest
		fmt.Fprintf(manifest, "Chunk %03d: %s\n", i, filename)
	}

	return nil
}

func simulateDNSRecords(msg *chunker.Message) {
	fmt.Println("\n🌐 Simulated DNS Zone File:")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("; DNS TXT Records for Message %s\n", hex.EncodeToString(msg.ID[:8]))
	fmt.Printf("; Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("; Total Records: %d\n\n", len(msg.Chunks))

	// Show first few records
	numToShow := 5
	if len(msg.Chunks) < numToShow {
		numToShow = len(msg.Chunks)
	}

	for i := 0; i < numToShow; i++ {
		chunk := msg.Chunks[i]

		// Format as DNS record
		recordData := chunk.Encoded
		if len(recordData) > 60 {
			recordData = recordData[:60] + "..."
		}

		fmt.Printf("%s. 300 IN TXT \"%s\"\n", chunk.RecordName, recordData)
	}

	if len(msg.Chunks) > numToShow {
		fmt.Printf("\n; ... and %d more records\n", len(msg.Chunks)-numToShow)
	}

	fmt.Println("\n📋 DNS Query Commands:")
	fmt.Printf("   dig @your-dns-server %s TXT\n", msg.Chunks[0].RecordName)
	fmt.Printf("   nslookup -type=TXT %s your-dns-server\n", msg.Chunks[0].RecordName)
}

func demonstrateReassembly(dir string, verbose bool) {
	fmt.Println("\n🔄 REASSEMBLY MODE")
	fmt.Println(strings.Repeat("-", 60))

	// Read chunks from directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("❌ Error reading directory: %v\n", err)
		return
	}

	// Create chunker for decoding
	chk := chunker.NewChunker(chunker.ChunkerConfig{
		Encoding: chunker.ENCODE_BASE32,
	})

	var chunks []chunker.Chunk

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "chunk_") && strings.HasSuffix(entry.Name(), ".txt") {
			filepath := fmt.Sprintf("%s/%s", dir, entry.Name())
			data, err := os.ReadFile(filepath)
			if err != nil {
				continue
			}

			// Parse DNS record format
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.Contains(line, "IN TXT") {
					// Extract the quoted content
					start := strings.Index(line, "\"")
					end := strings.LastIndex(line, "\"")
					if start >= 0 && end > start {
						encoded := line[start+1 : end]

						// Decode chunk
						chunk, err := chk.DecodeChunk(encoded)
						if err != nil {
							if verbose {
								fmt.Printf("⚠️  Failed to decode chunk from %s: %v\n", entry.Name(), err)
							}
							continue
						}

						chunks = append(chunks, *chunk)
						if verbose {
							fmt.Printf("✅ Loaded chunk %d from %s\n", chunk.Metadata.Sequence, entry.Name())
						}
					}
				}
			}
		}
	}

	fmt.Printf("\n📦 Loaded %d chunks from %s/\n", len(chunks), dir)

	if len(chunks) == 0 {
		fmt.Println("❌ No valid chunks found")
		return
	}

	// Attempt reassembly
	fmt.Println("\n🔧 Attempting reassembly...")

	reassembled, err := chk.ReassembleMessage(chunks)
	if err != nil {
		fmt.Printf("❌ Reassembly failed: %v\n", err)
		return
	}

	fmt.Printf("✅ Successfully reassembled %d bytes!\n", len(reassembled))

	// Save reassembled file
	outputFile := "reassembled_image.png"
	err = os.WriteFile(outputFile, reassembled, 0644)
	if err != nil {
		fmt.Printf("❌ Error saving file: %v\n", err)
		return
	}

	fmt.Printf("💾 Saved reassembled image: %s\n", outputFile)
	fmt.Println("\n🎉 Reassembly complete! You can now decode this image to extract the message.")
}

func createDemoStegoImage() string {
	// Create a simple demo image for testing
	fmt.Println("Creating 64x64 demo steganographic image...")

	// This would normally be your actual stego image
	// For demo purposes, we'll create a simple PNG
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))

	// Add some pattern (this would contain hidden data in real scenario)
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x * y) % 256),
				G: uint8((x + y) % 256),
				B: uint8((x - y) % 256),
				A: 255,
			})
		}
	}

	// Save to file
	filename := "demo_stego.png"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Created demo image: %s\n", filename)
	return filename
}
