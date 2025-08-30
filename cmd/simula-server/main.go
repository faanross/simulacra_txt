package main

import (
	"encoding/json"
	"fmt"
	dnsserver "github.com/faanross/simulacra_txt/internal/dns-server"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var totalDuration int = 26

// SimulationServer wraps DNS server for 24-hour simulation
type SimulationServer struct {
	domain    string
	dnsAddr   string
	httpPort  string
	storage   dnsserver.Storage
	queue     *dnsserver.QueueManager
	startTime time.Time
	logFile   *os.File
}

// NewSimulationServer creates the simulation server
func NewSimulationServer() *SimulationServer {
	// Create log file for trace analysis
	logFile, err := os.Create(fmt.Sprintf("simulation_server_%s.log",
		time.Now().Format("20060102_150405")))
	if err != nil {
		log.Fatal("Failed to create log file:", err)
	}

	// Use persistent storage so state survives if we need to restart
	storage, err := dnsserver.NewFileStorage("simulation_state.json")
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	return &SimulationServer{
		domain:    "covert.example.com",
		dnsAddr:   ":5555",
		httpPort:  "8080",
		storage:   storage,
		queue:     dnsserver.NewQueueManager(storage),
		startTime: time.Now(),
		logFile:   logFile,
	}
}

// Start begins the simulation server
func (s *SimulationServer) Start() {
	s.log("SIMULATION", fmt.Sprintf("Server starting for %d-hour simulation", totalDuration))
	s.log("CONFIG", fmt.Sprintf("DNS: %s, HTTP: %s, Domain: %s",
		s.dnsAddr, s.httpPort, s.domain))

	// Start HTTP API
	s.startHTTPAPI()

	// Start DNS server in background
	go s.startDNSServer()

	// Print status every 5 minutes
	go s.statusReporter()

	// Run for X hours
	duration := time.Duration(totalDuration) * time.Hour
	s.log("SIMULATION", fmt.Sprintf("Will run for %v", duration))

	timer := time.NewTimer(duration)
	<-timer.C

	s.shutdown()
}

// startHTTPAPI starts the HTTP endpoints
func (s *SimulationServer) startHTTPAPI() {
	// Upload endpoint (Host A uses this)
	http.HandleFunc("/upload", s.handleUpload)

	// Discovery endpoint (Host C uses this)
	http.HandleFunc("/messages", s.handleGetMessages)

	// Consume endpoint (Host C uses this)
	http.HandleFunc("/consume", s.handleConsume)

	// Status endpoint (for monitoring)
	http.HandleFunc("/status", s.handleStatus)

	go func() {
		s.log("HTTP", fmt.Sprintf("API starting on port %s", s.httpPort))
		if err := http.ListenAndServe(":"+s.httpPort, nil); err != nil {
			s.log("ERROR", fmt.Sprintf("HTTP server failed: %v", err))
		}
	}()
}

// handleUpload processes message uploads from Host A
func (s *SimulationServer) handleUpload(w http.ResponseWriter, r *http.Request) {
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
		s.log("ERROR", fmt.Sprintf("Upload decode failed: %v", err))
		return
	}

	// Process chunks
	processedChunks := make(map[string]string)
	for chunkName, chunkData := range req.Chunks {
		parts := strings.Split(chunkName, ".")
		if len(parts) > 0 {
			processedChunks[parts[0]] = chunkData
		}
	}

	// Store the message
	err := s.queue.PublishMessage(req.MessageID, processedChunks, req.Manifest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.log("ERROR", fmt.Sprintf("Failed to store message %s: %v", req.MessageID, err))
		return
	}

	s.log("UPLOAD", fmt.Sprintf("Message %s uploaded (%d chunks)", req.MessageID, len(req.Chunks)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"message_id": req.MessageID,
	})
}

// handleGetMessages allows Host C to discover new messages
func (s *SimulationServer) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		clientID = "default-client"
	}

	messages, err := s.storage.GetNewMessages(clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.log("ERROR", fmt.Sprintf("Failed to get messages for %s: %v", clientID, err))
		return
	}

	var messageIDs []string
	for _, msg := range messages {
		messageIDs = append(messageIDs, msg.ID)
		s.storage.MarkAsDelivered(msg.ID, clientID)
	}

	if len(messageIDs) > 0 {
		s.log("DISCOVERY", fmt.Sprintf("Client %s discovered %d messages: %v",
			clientID, len(messageIDs), messageIDs))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": messageIDs,
		"count":    len(messageIDs),
	})
}

// handleConsume marks a message as processed
func (s *SimulationServer) handleConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MessageID string `json:"message_id"`
		ClientID  string `json:"client_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := s.storage.MarkAsConsumed(req.MessageID, req.ClientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.log("ERROR", fmt.Sprintf("Failed to mark %s as consumed: %v", req.MessageID, err))
		return
	}

	s.log("CONSUME", fmt.Sprintf("Message %s consumed by %s", req.MessageID, req.ClientID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "consumed"})
}

// handleStatus returns server statistics
func (s *SimulationServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.storage.GetStats()
	uptime := time.Since(s.startTime)

	response := map[string]interface{}{
		"uptime_seconds":  uptime.Seconds(),
		"uptime_readable": uptime.String(),
		"stats":           stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// startDNSServer handles DNS queries for chunk retrieval
func (s *SimulationServer) startDNSServer() {
	dns.HandleFunc(s.domain, s.handleDNSRequest)
	dns.HandleFunc(".", s.handleDNSRequest)

	server := &dns.Server{
		Addr: s.dnsAddr,
		Net:  "udp",
	}

	s.log("DNS", fmt.Sprintf("Server starting on %s", s.dnsAddr))
	if err := server.ListenAndServe(); err != nil {
		s.log("ERROR", fmt.Sprintf("DNS server failed: %v", err))
	}
}

// handleDNSRequest processes DNS TXT queries
func (s *SimulationServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		if question.Qtype == dns.TypeTXT {
			s.handleTXTQuery(question, msg)
		}
	}

	w.WriteMsg(msg)
}

// handleTXTQuery returns chunk data via DNS
func (s *SimulationServer) handleTXTQuery(q dns.Question, msg *dns.Msg) {
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	parts := strings.Split(qname, ".")

	if len(parts) < 2 {
		msg.Rcode = dns.RcodeNameError
		return
	}

	label := parts[0]
	var msgID string

	// Extract message ID from query
	if strings.HasPrefix(label, "c-") || strings.HasPrefix(label, "m-") {
		idx := strings.LastIndex(label, "-")
		if idx > 0 {
			msgID = label[idx+1:]
		}
	}

	if msgID == "" {
		msg.Rcode = dns.RcodeNameError
		return
	}

	// Get message from storage
	message, err := s.storage.GetMessage(msgID)
	if err != nil {
		msg.Rcode = dns.RcodeNameError
		return
	}

	// Return appropriate data
	var value string
	if strings.HasPrefix(label, "m-") {
		value = message.Manifest
		s.log("DNS_QUERY", fmt.Sprintf("Manifest for %s", msgID))
	} else {
		if chunkData, exists := message.Chunks[label]; exists {
			value = chunkData
			s.log("DNS_QUERY", fmt.Sprintf("Chunk %s", label))
		}
	}

	if value != "" {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{value},
		}
		msg.Answer = append(msg.Answer, rr)
		msg.Rcode = dns.RcodeSuccess
	} else {
		msg.Rcode = dns.RcodeNameError
	}
}

// statusReporter prints statistics periodically
func (s *SimulationServer) statusReporter() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		stats := s.storage.GetStats()
		uptime := time.Since(s.startTime)

		s.log("STATUS", fmt.Sprintf(
			"Uptime: %v | Messages: %d (New: %d, Delivered: %d, Consumed: %d) | Chunks: %d",
			uptime.Round(time.Second),
			stats.TotalMessages,
			stats.NewMessages,
			stats.Delivered,
			stats.Consumed,
			stats.TotalChunks,
		))
	}
}

// log writes timestamped log entries
func (s *SimulationServer) log(category, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logEntry := fmt.Sprintf("[%s] [%s] %s\n", timestamp, category, message)

	// Write to file
	s.logFile.WriteString(logEntry)

	// Also print to console
	fmt.Print(logEntry)
}

// shutdown gracefully stops the server
func (s *SimulationServer) shutdown() {
	s.log("SIMULATION", "24-hour simulation complete, shutting down")

	// Final statistics
	stats := s.storage.GetStats()
	s.log("FINAL", fmt.Sprintf(
		"Total Messages: %d | Consumed: %d | Chunks: %d",
		stats.TotalMessages,
		stats.Consumed,
		stats.TotalChunks,
	))

	// Save final state
	if fs, ok := s.storage.(*dnsserver.FileStorage); ok {
		if err := fs.Save(); err != nil {
			s.log("ERROR", fmt.Sprintf("Failed to save final state: %v", err))
		} else {
			s.log("SHUTDOWN", "State saved to simulation_state.json")
		}
	}

	s.logFile.Close()
	os.Exit(0)
}

func main() {
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Printf("SIMULACRA TXT - %d HOUR SIMULATION SERVER\n", totalDuration)
	fmt.Println("=" + strings.Repeat("=", 60))

	server := NewSimulationServer()
	server.Start()
}
