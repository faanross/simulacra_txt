package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/chunker"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

// ================================================================================
// DNS UPLOAD CLIENT - Sender side of covert channel
// Uploads chunked steganographic images to DNS server
// ================================================================================

// UploadClient handles covert uploads to DNS server
type UploadClient struct {
	server      string        // DNS server address
	domain      string        // Target domain
	rateLimit   time.Duration // Delay between queries
	maxRetries  int           // Retry failed uploads
	stealthMode bool          // Add random delays and cover traffic
}

// NewUploadClient creates an upload client
func NewUploadClient(server, domain string) *UploadClient {
	return &UploadClient{
		server:      server,
		domain:      domain,
		rateLimit:   100 * time.Millisecond, // Default: 10 queries/sec
		maxRetries:  3,
		stealthMode: false,
	}
}

// UploadMessage uploads a complete message to DNS server via HTTP
func (uc *UploadClient) UploadMessage(msgID string, chunks []chunker.Chunk, manifest string) error {
	totalChunks := len(chunks)

	fmt.Printf("\n📤 UPLOADING MESSAGE: %s\n", msgID)
	fmt.Printf("   Chunks to upload: %d\n", totalChunks)
	fmt.Printf("   Server: %s\n", uc.server)

	// Prepare chunks map
	chunkMap := make(map[string]string)
	for i, chunk := range chunks {
		chunkName := fmt.Sprintf("c-%d-%s.data.%s", i, msgID, uc.domain)
		chunkMap[chunkName] = chunk.Encoded
	}

	// Add manifest
	manifestName := fmt.Sprintf("m-%s.data.%s", msgID, uc.domain)
	chunkMap[manifestName] = manifest

	// Create upload request
	uploadReq := struct {
		MessageID string            `json:"message_id"`
		Chunks    map[string]string `json:"chunks"`
		Manifest  string            `json:"manifest"`
	}{
		MessageID: msgID,
		Chunks:    chunkMap,
		Manifest:  manifest,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(uploadReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Extract host from DNS server address (remove port)
	serverHost := strings.Split(uc.server, ":")[0]
	httpURL := fmt.Sprintf("http://%s:8080/upload", serverHost)

	fmt.Printf("   Uploading to: %s\n", httpURL)

	// Send HTTP POST request
	resp, err := http.Post(httpURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("HTTP upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status: %s", resp.Status)
	}

	// Parse response
	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("\n✅ Upload successful!\n")
	fmt.Printf("   Message ID: %s\n", result["message_id"])
	fmt.Printf("   Chunks uploaded: %s\n", result["chunks"])

	return nil
}

// applyRateLimit adds delay between queries
func (uc *UploadClient) applyRateLimit() {
	if uc.stealthMode {
		// Add jitter: 50% to 150% of base rate
		jitter := uc.rateLimit/2 + time.Duration(rand.Int63n(int64(uc.rateLimit)))
		time.Sleep(jitter)
	} else {
		time.Sleep(uc.rateLimit)
	}
}

// generateCoverTraffic creates legitimate-looking DNS queries
func (uc *UploadClient) generateCoverTraffic() {
	// LESSON: Cover Traffic
	// Mix covert queries with legitimate ones to avoid detection

	coverDomains := []string{
		"www.google.com",
		"www.cloudflare.com",
		"cdn.jsdelivr.net",
		"api.github.com",
	}

	domain := coverDomains[rand.Intn(len(coverDomains))]

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	c.Exchange(m, uc.server) // Ignore response
}

// ProgressBar shows upload progress
type ProgressBar struct {
	total   int
	current int
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{total: total}
}

func (pb *ProgressBar) Update(current int) {
	pb.current = current

	// Calculate percentage
	percent := float64(pb.current) / float64(pb.total) * 100

	// Build progress bar
	barWidth := 30
	filled := int(float64(barWidth) * percent / 100)

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	fmt.Printf("\r   [%s] %d/%d (%.1f%%)", bar, pb.current, pb.total, percent)
}

func (pb *ProgressBar) Finish() {
	fmt.Println() // New line after progress bar
}

// LoadAndChunkImage prepares an image for upload
func LoadAndChunkImage(imagePath string) (string, []chunker.Chunk, string, error) {
	// Read image
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to read image: %w", err)
	}

	// Create chunker
	chk := chunker.NewChunker(chunker.ChunkerConfig{
		Encoding: chunker.ENCODE_BASE32,
	})

	// Chunk the image
	msg, err := chk.ChunkMessage(data)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to chunk: %w", err)
	}

	// Generate message ID
	msgID := fmt.Sprintf("%x", msg.ID[:8])

	// Create manifest
	manifest := fmt.Sprintf("%d:checksum:%d", len(msg.Chunks), time.Now().Unix())

	return msgID, msg.Chunks, manifest, nil
}

func main() {
	// Command line flags
	server := flag.String("server", "localhost:5353", "DNS server address")
	domain := flag.String("domain", "covert.example.com", "Target domain")
	input := flag.String("input", "", "Input image file")
	zoneFile := flag.String("zone", "", "Pre-generated zone file")
	rateLimit := flag.Int("rate", 10, "Queries per second")
	stealth := flag.Bool("stealth", false, "Enable stealth mode")
	flag.Parse()

	if *input == "" && *zoneFile == "" {
		log.Fatal("Please provide -input (image) or -zone (zone file)")
	}

	// Create upload client
	client := NewUploadClient(*server, *domain)
	client.stealthMode = *stealth

	// Calculate rate limit delay
	if *rateLimit > 0 {
		client.rateLimit = time.Second / time.Duration(*rateLimit)
	}

	fmt.Println("\n🚀 DNS COVERT CHANNEL UPLOADER")

	var msgID string
	var chunks []chunker.Chunk
	var manifest string
	var err error

	if *input != "" {
		// Load and chunk image
		fmt.Printf("📷 Loading image: %s\n", *input)
		msgID, chunks, manifest, err = LoadAndChunkImage(*input)
		if err != nil {
			log.Fatal(err)
		}

		fileInfo, _ := os.Stat(*input)
		fmt.Printf("   Size: %d bytes\n", fileInfo.Size())
		fmt.Printf("   Chunks: %d\n", len(chunks))
		fmt.Printf("   Message ID: %s\n", msgID)
	} else {
		// Load from zone file (TODO: implement zone file parser)
		log.Fatal("Zone file loading not yet implemented")
	}

	// Display configuration
	fmt.Printf("\n⚙️ Configuration:\n")
	fmt.Printf("   Server: %s\n", *server)
	fmt.Printf("   Domain: %s\n", *domain)
	fmt.Printf("   Rate limit: %d queries/sec\n", *rateLimit)
	fmt.Printf("   Stealth mode: %v\n", *stealth)

	if *stealth {
		fmt.Println("\n🥷 Stealth mode enabled:")
		fmt.Println("   - Random chunk order")
		fmt.Println("   - Timing jitter")
		fmt.Println("   - Cover traffic")
	}

	// Estimate upload time
	estimatedTime := time.Duration(len(chunks)+1) * client.rateLimit
	fmt.Printf("\n⏱️ Estimated upload time: %v\n", estimatedTime)

	// Start upload
	fmt.Printf("\nPress Enter to start upload...")
	fmt.Scanln()

	// Upload the message
	err = client.UploadMessage(msgID, chunks, manifest)
	if err != nil {
		log.Fatalf("Upload failed: %v", err)
	}

	fmt.Println("\n🎉 Upload complete!")
	fmt.Printf("Receiver should query for message: %s\n", msgID)
	fmt.Printf("\nExample receiver command:\n")
	fmt.Printf("  go run cmd/stego-receive/main.go -server %s -msg %s\n", *server, msgID)
}
