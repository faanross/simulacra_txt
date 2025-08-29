package main

import (
	"encoding/json"
	"flag"
	"fmt"
	dnsserver "github.com/faanross/simulacra_txt/internal/dns-server"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

// DNSServerV2 integrates our storage backend
type DNSServerV2 struct {
	domain  string
	addr    string
	storage dnsserver.Storage
	queue   *dnsserver.QueueManager
}

// HTTP API for uploads
func (s *DNSServerV2) StartHTTPAPI(port string) {
	http.HandleFunc("/upload", s.handleHTTPUpload)
	http.HandleFunc("/status", s.handleStatus)

	log.Printf("📡 HTTP API starting on port %s", port)
	go http.ListenAndServe(":"+port, nil)
}

// handleHTTPUpload receives chunks via HTTP
func (s *DNSServerV2) handleHTTPUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MessageID string            `json:"message_id"`
		Chunks    map[string]string `json:"chunks"`
		Manifest  string            `json:"manifest"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Store the message
	err := s.queue.PublishMessage(req.MessageID, req.Chunks, req.Manifest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Uploaded message %s via HTTP (%d chunks)", req.MessageID, len(req.Chunks))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"message_id": req.MessageID,
		"chunks":     fmt.Sprintf("%d", len(req.Chunks)),
	})
}

// handleStatus returns server status
func (s *DNSServerV2) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.storage.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func NewDNSServerV2(domain, addr string, persistent bool) *DNSServerV2 {
	var storage dnsserver.Storage
	var err error

	if persistent {
		log.Println("📁 Using persistent storage (dns_data.json)")
		storage, err = dnsserver.NewFileStorage("dns_data.json")
		if err != nil {
			log.Fatalf("Failed to create file storage: %v", err)
		}
	} else {
		log.Println("💾 Using in-memory storage")
		storage = dnsserver.NewMemoryStorage()
	}

	return &DNSServerV2{
		domain:  domain,
		addr:    addr,
		storage: storage,
		queue:   dnsserver.NewQueueManager(storage),
	}
}

func (s *DNSServerV2) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		if question.Qtype == dns.TypeTXT {
			s.handleTXT(question, msg, r)
		}
	}

	w.WriteMsg(msg)
}

func (s *DNSServerV2) handleTXT(q dns.Question, msg *dns.Msg, r *dns.Msg) {
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// Extract client ID from query (for tracking)
	// In production, would extract from source IP or EDNS0
	clientID := "client-default"

	// Check if this is a consumption query (special prefix)
	if strings.Contains(qname, "consume.") {
		s.handleConsume(qname, msg, clientID)
		return
	}

	// Regular chunk query
	s.handleChunkQuery(qname, msg)
}

func (s *DNSServerV2) handleChunkQuery(qname string, msg *dns.Msg) {
	// Try to find the chunk
	parts := strings.Split(qname, ".")
	if len(parts) < 2 {
		return
	}

	// Extract potential message ID
	label := parts[0]
	var msgID string

	if strings.HasPrefix(label, "c-") || strings.HasPrefix(label, "m-") {
		// Extract message ID from chunk name
		idx := strings.LastIndex(label, "-")
		if idx > 0 {
			msgID = label[idx+1:]
		}
	}

	if msgID == "" {
		return
	}

	// Get message from storage
	message, err := s.storage.GetMessage(msgID)
	if err != nil {
		log.Printf("Message %s not found", msgID)
		return
	}

	// Return appropriate data
	var value string
	if strings.HasPrefix(label, "m-") {
		value = message.Manifest
	} else {
		// Find the specific chunk
		for chunkName, chunkData := range message.Chunks {
			if strings.Contains(chunkName, label) {
				value = chunkData
				break
			}
		}
	}

	if value != "" {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   qname + ".",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{value},
		}
		msg.Answer = append(msg.Answer, rr)
		log.Printf("Served: %s", qname)
	}
}

func (s *DNSServerV2) handleConsume(qname string, msg *dns.Msg, clientID string) {
	// Special query to get new messages
	// Format: consume.client123.covert.com

	messages, err := s.queue.ConsumeMessages(clientID)
	if err != nil {
		log.Printf("Consume failed for %s: %v", clientID, err)
		return
	}

	// Return list of new message IDs
	var ids []string
	for _, m := range messages {
		ids = append(ids, m.ID)
	}

	if len(ids) > 0 {
		value := strings.Join(ids, ",")
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   qname + ".",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60, // Short TTL for queue queries
			},
			Txt: []string{value},
		}
		msg.Answer = append(msg.Answer, rr)
		log.Printf("Client %s consumed %d messages", clientID, len(messages))
	}
}

func (s *DNSServerV2) LoadChunkedMessage(msgID string, zoneContent string) error {
	// Parse zone file and create message
	chunks := make(map[string]string)
	manifest := ""

	lines := strings.Split(zoneContent, "\n")
	for _, line := range lines {
		if strings.Contains(line, " IN TXT ") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				name := strings.TrimSuffix(parts[0], ".")

				// Extract value
				startQuote := strings.Index(line, `"`)
				endQuote := strings.LastIndex(line, `"`)
				if startQuote >= 0 && endQuote > startQuote {
					value := line[startQuote+1 : endQuote]

					if strings.Contains(name, "m-") {
						manifest = value
					} else if strings.Contains(name, "c-") {
						chunks[name] = value
					}
				}
			}
		}
	}

	if len(chunks) > 0 {
		return s.queue.PublishMessage(msgID, chunks, manifest)
	}

	return fmt.Errorf("no chunks found in zone file")
}

func (s *DNSServerV2) PrintStats() {
	stats := s.storage.GetStats()
	fmt.Printf("\n📊 Storage Statistics:\n")
	fmt.Printf("   Total messages: %d\n", stats.TotalMessages)
	fmt.Printf("   New (undelivered): %d\n", stats.NewMessages)
	fmt.Printf("   Delivered: %d\n", stats.Delivered)
	fmt.Printf("   Consumed: %d\n", stats.Consumed)
	fmt.Printf("   Total chunks: %d\n", stats.TotalChunks)

	messages, _ := s.storage.ListMessages()
	if len(messages) > 0 {
		fmt.Println("\n📬 Stored Messages:")
		for _, m := range messages {
			status := "unknown"
			switch m.State {
			case dnsserver.StateNew:
				status = "NEW"
			case dnsserver.StateDelivered:
				status = "DELIVERED"
			case dnsserver.StateConsumed:
				status = "CONSUMED"
			}
			fmt.Printf("   %s: %d chunks, status=%s\n", m.ID, m.TotalChunks, status)
		}
	}
}

func main() {
	domain := flag.String("domain", "covert.example.com", "Domain to serve")
	addr := flag.String("addr", ":5353", "Listen address")
	persistent := flag.Bool("persistent", false, "Use persistent storage")
	zoneFile := flag.String("zone", "", "Zone file to load")
	cleanInterval := flag.Duration("clean", 1*time.Hour, "Cleanup interval for old messages")
	flag.Parse()

	// Create server with storage backend
	server := NewDNSServerV2(*domain, *addr, *persistent)
	server.StartHTTPAPI("8080")

	// Load zone file if provided
	if *zoneFile != "" {
		content, err := os.ReadFile(*zoneFile)
		if err != nil {
			log.Fatalf("Failed to read zone file: %v", err)
		}

		// Extract message ID from zone file
		msgID := fmt.Sprintf("msg%d", time.Now().Unix())
		if err := server.LoadChunkedMessage(msgID, string(content)); err != nil {
			log.Printf("Failed to load zone file: %v", err)
		} else {
			log.Printf("✅ Loaded message %s from zone file", msgID)
		}
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(*cleanInterval)
		for range ticker.C {
			removed := server.storage.CleanExpired(*cleanInterval)
			if removed > 0 {
				log.Printf("🧹 Cleaned %d expired messages", removed)
			}
		}
	}()

	// Print initial stats
	server.PrintStats()

	// Handle shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		fmt.Println("\n🛑 Shutting down...")
		server.PrintStats()

		// Save if using persistent storage
		if fs, ok := server.storage.(*dnsserver.FileStorage); ok {
			if err := fs.Save(); err != nil {
				log.Printf("Failed to save state: %v", err)
			} else {
				log.Println("💾 State saved to disk")
			}
		}

		os.Exit(0)
	}()

	// Setup DNS handler
	dns.HandleFunc(server.domain, server.handleDNSRequest)
	dns.HandleFunc(".", server.handleDNSRequest)

	// Start server
	fmt.Printf("\n🌐 DNS Server V2 starting on %s\n", *addr)
	fmt.Printf("📍 Domain: %s\n", *domain)
	fmt.Printf("💾 Storage: ")
	if *persistent {
		fmt.Println("Persistent (dns_data.json)")
	} else {
		fmt.Println("In-memory")
	}
	fmt.Printf("🧹 Cleanup: Every %v\n", *cleanInterval)
	fmt.Println("\n✅ Server ready!")

	dnsServer := &dns.Server{
		Addr: *addr,
		Net:  "udp",
	}
	log.Fatal(dnsServer.ListenAndServe())
}
