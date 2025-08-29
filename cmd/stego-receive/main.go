package main

import (
	"flag"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/chunker"
	"github.com/faanross/simulacra_txt/internal/decoder"
	"github.com/faanross/simulacra_txt/internal/scrypto"
	"github.com/miekg/dns"
	"image"
	"log"
	"os"
	"strings"
	"time"
)

// ================================================================================
// DNS RECEIVER CLIENT - Retrieves and decodes covert messages
// ================================================================================

// Receiver handles message retrieval from DNS
type Receiver struct {
	server       string
	domain       string
	pollInterval time.Duration
	maxRetries   int
}

// NewReceiver creates a receiver instance
func NewReceiver(server, domain string) *Receiver {
	return &Receiver{
		server:       server,
		domain:       domain,
		pollInterval: 5 * time.Second,
		maxRetries:   3,
	}
}

// RetrieveMessage fetches a complete message from DNS
func (r *Receiver) RetrieveMessage(msgID string) ([]byte, error) {
	fmt.Printf("\n📥 RETRIEVING MESSAGE: %s\n", msgID)
	fmt.Printf("   Server: %s\n", r.server)
	fmt.Printf("   Domain: %s\n", r.domain)

	// LESSON: Retrieval Strategy
	// 1. Fetch manifest first (tells us what to expect)
	// 2. Query for each chunk
	// 3. Handle missing/failed chunks
	// 4. Reassemble in correct order
	// 5. Decode from steganographic format

	// Step 1: Get manifest
	fmt.Printf("\n1️⃣ Fetching manifest...\n")
	manifest, totalChunks, err := r.fetchManifest(msgID)
	if err != nil {
		return nil, fmt.Errorf("manifest fetch failed: %w", err)
	}

	fmt.Printf("   ✅ Manifest retrieved\n")
	fmt.Printf("   Total chunks: %d\n", totalChunks)

	// Step 2: Fetch all chunks
	fmt.Printf("\n2️⃣ Fetching chunks...\n")
	chunks := make([]string, totalChunks)
	successful := 0
	failed := 0

	progressBar := NewProgressBar(totalChunks)

	for i := 0; i < totalChunks; i++ {
		chunkName := fmt.Sprintf("c-%d-%s.data.%s", i, msgID, r.domain)

		chunkData, err := r.fetchChunk(chunkName)
		if err != nil {
			// Retry logic
			retried := false
			for retry := 0; retry < r.maxRetries; retry++ {
				time.Sleep(time.Duration(retry+1) * time.Second)
				chunkData, err = r.fetchChunk(chunkName)
				if err == nil {
					retried = true
					break
				}
			}

			if !retried {
				fmt.Printf("\n   ❌ Failed chunk %d: %v\n", i, err)
				failed++
				continue
			}
		}

		chunks[i] = chunkData
		successful++
		progressBar.Update(successful)

		// Small delay to avoid hammering server
		time.Sleep(50 * time.Millisecond)
	}

	progressBar.Finish()

	// Check completeness
	if failed > 0 {
		return nil, fmt.Errorf("incomplete retrieval: %d/%d chunks missing", failed, totalChunks)
	}

	fmt.Printf("   ✅ All chunks retrieved\n")

	// Step 3: Reassemble
	fmt.Printf("\n3️⃣ Reassembling message...\n")

	reassembled, err := r.reassembleChunks(chunks, msgID, manifest)
	if err != nil {
		return nil, fmt.Errorf("reassembly failed: %w", err)
	}

	fmt.Printf("   ✅ Reassembled %d bytes\n", len(reassembled))

	return reassembled, nil
}

// fetchManifest retrieves the manifest record
func (r *Receiver) fetchManifest(msgID string) (string, int, error) {
	manifestName := fmt.Sprintf("m-%s.data.%s", msgID, r.domain)

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(manifestName), dns.TypeTXT)

	resp, _, err := c.Exchange(m, r.server)
	if err != nil {
		return "", 0, err
	}

	// Extract manifest data
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok && len(txt.Txt) > 0 {
			// Parse manifest: "total:checksum:timestamp"
			parts := strings.Split(txt.Txt[0], ":")
			if len(parts) >= 1 {
				var total int
				fmt.Sscanf(parts[0], "%d", &total)
				return txt.Txt[0], total, nil
			}
		}
	}

	return "", 0, fmt.Errorf("manifest not found")
}

// fetchChunk retrieves a single chunk
func (r *Receiver) fetchChunk(chunkName string) (string, error) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(chunkName), dns.TypeTXT)

	resp, _, err := c.Exchange(m, r.server)
	if err != nil {
		return "", err
	}

	// Extract chunk data
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok && len(txt.Txt) > 0 {
			return txt.Txt[0], nil
		}
	}

	return "", fmt.Errorf("chunk not found")
}

// reassembleChunks reconstructs the original data
func (r *Receiver) reassembleChunks(encodedChunks []string, msgID, manifest string) ([]byte, error) {
	// Convert DNS chunks back to chunker.Chunk format
	chk := chunker.NewChunker(chunker.ChunkerConfig{
		Encoding: chunker.ENCODE_BASE32,
	})

	chunks := make([]chunker.Chunk, 0, len(encodedChunks))

	for _, encoded := range encodedChunks {
		if encoded == "" {
			continue // Skip missing chunks
		}

		chunk, err := chk.DecodeChunk(encoded)
		if err != nil {
			return nil, fmt.Errorf("chunk decode failed: %w", err)
		}

		chunks = append(chunks, *chunk)
	}

	// Reassemble
	data, err := chk.ReassembleMessage(chunks)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// PollForNewMessages continuously checks for new messages
func (r *Receiver) PollForNewMessages(clientID string) {
	fmt.Printf("\n👁️ POLLING MODE\n")
	fmt.Printf("   Client ID: %s\n", clientID)
	fmt.Printf("   Poll interval: %v\n", r.pollInterval)
	fmt.Println("\nWaiting for messages... (Press Ctrl+C to stop)")

	// LESSON: Polling Patterns
	// - Fixed interval: Simple but predictable
	// - Exponential backoff: Reduces load when idle
	// - Jittered: Avoids synchronized polling

	consecutiveEmpty := 0

	for {
		// Query for new messages
		newMsgIDs, err := r.checkForNewMessages(clientID)
		if err != nil {
			log.Printf("Poll error: %v", err)
			time.Sleep(r.pollInterval)
			continue
		}

		if len(newMsgIDs) > 0 {
			fmt.Printf("\n🔔 New messages: %v\n", newMsgIDs)
			consecutiveEmpty = 0

			// Retrieve each message
			for _, msgID := range newMsgIDs {
				data, err := r.RetrieveMessage(msgID)
				if err != nil {
					log.Printf("Failed to retrieve %s: %v", msgID, err)
					continue
				}

				// Save retrieved message
				filename := fmt.Sprintf("received_%s.png", msgID)
				err = os.WriteFile(filename, data, 0644)
				if err != nil {
					log.Printf("Failed to save: %v", err)
					continue
				}

				fmt.Printf("💾 Saved to: %s\n", filename)

				// Acknowledge receipt
				r.acknowledgeMessage(msgID, clientID)
			}
		} else {
			consecutiveEmpty++

			// Exponential backoff when idle
			if consecutiveEmpty > 5 {
				time.Sleep(r.pollInterval * 2)
			} else {
				time.Sleep(r.pollInterval)
			}
		}
	}
}

// checkForNewMessages queries for unread messages
func (r *Receiver) checkForNewMessages(clientID string) ([]string, error) {
	queryName := fmt.Sprintf("consume.%s.%s", clientID, r.domain)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(queryName), dns.TypeTXT)

	resp, _, err := c.Exchange(m, r.server)
	if err != nil {
		return nil, err
	}

	// Parse response
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok && len(txt.Txt) > 0 {
			// Response format: "msgID1,msgID2,msgID3"
			if txt.Txt[0] != "" {
				return strings.Split(txt.Txt[0], ","), nil
			}
		}
	}

	return []string{}, nil
}

// acknowledgeMessage marks a message as consumed
func (r *Receiver) acknowledgeMessage(msgID, clientID string) {
	ackName := fmt.Sprintf("ack.%s.%s.%s", msgID, clientID, r.domain)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ackName), dns.TypeTXT)

	c.Exchange(m, r.server) // Fire and forget
}

// DecodeAndSave decodes the steganographic image
func DecodeAndSave(imagePath string, password []byte, outputPath string) error {
	// Open image
	file, err := os.Open(imagePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode image
	img, _, err := image.Decode(file)
	if err != nil {
		return err
	}

	// Create decoder
	stegDecoder := decoder.NewSecureStegoDecoder(img, password)

	// Extract and decrypt
	stegDecoder.ExtractBitStream()
	err = stegDecoder.ExtractSecurePayload()
	if err != nil {
		return err
	}

	result, err := stegDecoder.DecryptPayload()
	if err != nil {
		return err
	}

	// Save message
	err = os.WriteFile(outputPath, result.Message, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Decoded message saved to: %s\n", outputPath)
	return nil
}

// ProgressBar for visual feedback
type ProgressBar struct {
	total   int
	current int
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{total: total}
}

func (pb *ProgressBar) Update(current int) {
	pb.current = current
	percent := float64(pb.current) / float64(pb.total) * 100
	barWidth := 30
	filled := int(float64(barWidth) * percent / 100)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\r   [%s] %d/%d (%.1f%%)", bar, pb.current, pb.total, percent)
}

func (pb *ProgressBar) Finish() {
	fmt.Println()
}

func main() {
	// Command line flags
	server := flag.String("server", "localhost:5353", "DNS server")
	domain := flag.String("domain", "covert.example.com", "Domain")
	msgID := flag.String("msg", "", "Message ID to retrieve")
	poll := flag.Bool("poll", false, "Poll for new messages")
	clientID := flag.String("client", "receiver1", "Client ID for polling")
	decode := flag.Bool("decode", false, "Decode after retrieval")
	password := flag.String("password", "", "Password for decoding")
	output := flag.String("output", "", "Output directory")
	flag.Parse()

	fmt.Println("\n📡 DNS COVERT CHANNEL RECEIVER")

	receiver := NewReceiver(*server, *domain)

	if *poll {
		// Polling mode
		receiver.PollForNewMessages(*clientID)
	} else if *msgID != "" {
		// Retrieve specific message
		startTime := time.Now()

		data, err := receiver.RetrieveMessage(*msgID)
		if err != nil {
			log.Fatalf("Retrieval failed: %v", err)
		}

		// Save image
		imagePath := fmt.Sprintf("received_%s.png", *msgID)
		if *output != "" {
			imagePath = fmt.Sprintf("%s/received_%s.png", *output, *msgID)
		}

		err = os.WriteFile(imagePath, data, 0644)
		if err != nil {
			log.Fatalf("Failed to save: %v", err)
		}

		elapsed := time.Since(startTime)

		fmt.Printf("\n📊 RETRIEVAL SUMMARY:\n")
		fmt.Printf("   Message ID: %s\n", *msgID)
		fmt.Printf("   Size: %d bytes\n", len(data))
		fmt.Printf("   Time: %v\n", elapsed)
		fmt.Printf("   Rate: %.2f KB/s\n", float64(len(data))/1024/elapsed.Seconds())
		fmt.Printf("   Saved to: %s\n", imagePath)

		// Optionally decode
		if *decode {
			fmt.Printf("\n4️⃣ Decoding steganographic image...\n")

			var pass []byte
			if *password != "" {
				pass = []byte(*password)
			} else {
				pass, err = scrypto.GetSecurePassword("Enter password: ")
				if err != nil {
					log.Fatal(err)
				}
			}

			outputPath := fmt.Sprintf("decoded_%s.txt", *msgID)
			err = DecodeAndSave(imagePath, pass, outputPath)
			if err != nil {
				log.Printf("Decode failed: %v", err)
			}
		}

		fmt.Println("\n✅ RETRIEVAL COMPLETE!")
	} else {
		fmt.Println("Please specify -msg ID or -poll")
		flag.Usage()
	}
}
