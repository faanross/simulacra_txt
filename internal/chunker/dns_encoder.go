package chunker

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// DNSEncoder handles DNS-specific encoding requirements
type DNSEncoder struct {
	domain     string
	subdomain  string
	timePrefix bool // Add timestamp to prevent caching
}

// NewDNSEncoder creates an encoder for DNS transport
func NewDNSEncoder(domain string) *DNSEncoder {
	return &DNSEncoder{
		domain:     domain,
		subdomain:  "data",
		timePrefix: true,
	}
}

// DNSManifest describes a complete message for DNS transport
type DNSManifest struct {
	MessageID   string    `json:"id"`
	TotalChunks int       `json:"total"`
	Timestamp   time.Time `json:"timestamp"`
	Checksum    string    `json:"checksum"`
	ChunkIDs    []string  `json:"chunks"`
	Domain      string    `json:"domain"`
}

// EncodeToDNS converts chunks into DNS TXT records
func (de *DNSEncoder) EncodeToDNS(msg *Message) (*DNSManifest, []DNSRecord, error) {
	// LESSON: DNS names have strict rules:
	// - Max 63 chars per label
	// - Only a-z, 0-9, and hyphen
	// - No leading/trailing hyphens
	// - Case insensitive

	manifest := &DNSManifest{
		MessageID:   de.sanitizeForDNS(hex.EncodeToString(msg.ID[:8])),
		TotalChunks: len(msg.Chunks),
		Timestamp:   msg.CreatedAt,
		Domain:      de.domain,
		ChunkIDs:    make([]string, 0, len(msg.Chunks)),
	}

	records := make([]DNSRecord, 0, len(msg.Chunks)+1)

	// Create manifest record
	// LESSON: The manifest helps receivers know what to expect
	manifestRecord := de.createManifestRecord(manifest)
	records = append(records, manifestRecord)

	// Process each chunk
	for i, chunk := range msg.Chunks {
		record, err := de.createChunkRecord(chunk, i, manifest.MessageID)
		if err != nil {
			return nil, nil, fmt.Errorf("chunk %d encoding failed: %w", i, err)
		}

		records = append(records, record)
		manifest.ChunkIDs = append(manifest.ChunkIDs, record.Name)
	}

	// Calculate overall checksum
	manifest.Checksum = de.calculateManifestChecksum(msg.Data)

	return manifest, records, nil
}

// DNSRecord represents a DNS TXT record
type DNSRecord struct {
	Name  string // Full DNS name (e.g., chunk-0-abc123.data.example.com)
	Type  string // Always "TXT" for our use
	TTL   int    // Time to live in seconds
	Value string // The encoded chunk data
}

// createChunkRecord creates a DNS TXT record for a chunk
func (de *DNSEncoder) createChunkRecord(chunk Chunk, index int, msgID string) (DNSRecord, error) {
	// LESSON: DNS Label Format Strategy
	// We encode metadata in the DNS name itself for quick filtering
	// Format: c-{seq}-{msgid}.{subdomain}.{domain}
	// Example: c-0-abc123.data.covert.com

	// Create DNS-safe label
	label := fmt.Sprintf("c-%d-%s", index, msgID)

	// Add optional timestamp prefix to prevent caching
	if de.timePrefix {
		// Use minutes since epoch for cache busting
		minutes := time.Now().Unix() / 60
		label = fmt.Sprintf("t%d-%s", minutes, label)
	}

	// Validate label length (63 char limit)
	if len(label) > 63 {
		// Truncate message ID if needed
		maxMsgIDLen := 63 - len(fmt.Sprintf("c-%d-", index))
		if de.timePrefix {
			maxMsgIDLen -= 12 // Account for timestamp
		}
		msgID = msgID[:maxMsgIDLen]
		label = fmt.Sprintf("c-%d-%s", index, msgID)
	}

	// Build full DNS name
	fullName := fmt.Sprintf("%s.%s.%s", label, de.subdomain, de.domain)

	// LESSON: TXT Record Value Encoding
	// Must handle special characters that DNS doesn't like
	encodedValue := de.escapeTXTValue(chunk.Encoded)

	return DNSRecord{
		Name:  fullName,
		Type:  "TXT",
		TTL:   300, // 5 minutes - balance between caching and freshness
		Value: encodedValue,
	}, nil
}

// createManifestRecord creates a special record that describes the message
func (de *DNSEncoder) createManifestRecord(manifest *DNSManifest) DNSRecord {
	// LESSON: Manifest Record
	// Special record that tells receivers:
	// - How many chunks to expect
	// - Message identifier
	// - Verification checksum

	// Use special prefix for manifest
	label := fmt.Sprintf("m-%s", manifest.MessageID)
	fullName := fmt.Sprintf("%s.%s.%s", label, de.subdomain, de.domain)

	// Encode manifest data
	// Format: TOTAL:CHECKSUM:TIMESTAMP
	value := fmt.Sprintf("%d:%s:%d",
		manifest.TotalChunks,
		"pending", // Checksum calculated after all chunks
		manifest.Timestamp.Unix())

	return DNSRecord{
		Name:  fullName,
		Type:  "TXT",
		TTL:   300,
		Value: value,
	}
}

// sanitizeForDNS makes a string DNS-label safe
func (de *DNSEncoder) sanitizeForDNS(input string) string {
	// LESSON: DNS Label Rules (RFC 1035)
	// - Only alphanumeric and hyphens
	// - No leading/trailing hyphens
	// - Max 63 characters
	// - Case insensitive (we use lowercase)

	// Convert to lowercase
	input = strings.ToLower(input)

	// Replace invalid characters with hyphens
	reg := regexp.MustCompile(`[^a-z0-9-]`)
	sanitized := reg.ReplaceAllString(input, "-")

	// Remove leading/trailing hyphens
	sanitized = strings.Trim(sanitized, "-")

	// Collapse multiple hyphens
	reg = regexp.MustCompile(`-+`)
	sanitized = reg.ReplaceAllString(sanitized, "-")

	// Enforce length limit
	if len(sanitized) > 63 {
		sanitized = sanitized[:63]
	}

	// Ensure it starts with alphanumeric
	if len(sanitized) > 0 && !isAlphanumeric(sanitized[0]) {
		sanitized = "x" + sanitized[1:]
	}

	return sanitized
}

// escapeTXTValue escapes special characters in TXT record values
func (de *DNSEncoder) escapeTXTValue(value string) string {
	// LESSON: TXT Record Special Characters
	// Some characters need escaping in TXT records:
	// - Quotes (") → \"
	// - Backslash (\) → \\
	// - Non-printable → \DDD (decimal)

	var escaped strings.Builder

	for _, ch := range value {
		switch ch {
		case '"':
			escaped.WriteString(`\"`)
		case '\\':
			escaped.WriteString(`\\`)
		case '\n', '\r', '\t':
			// Escape whitespace characters
			escaped.WriteString(fmt.Sprintf("\\%03d", ch))
		default:
			if ch < 32 || ch > 126 {
				// Escape non-printable
				escaped.WriteString(fmt.Sprintf("\\%03d", ch))
			} else {
				escaped.WriteRune(ch)
			}
		}
	}

	return escaped.String()
}

// ParseFromDNS reconstructs chunks from DNS records
func (de *DNSEncoder) ParseFromDNS(records []DNSRecord) ([]Chunk, *DNSManifest, error) {
	var manifest *DNSManifest
	chunks := make([]Chunk, 0)

	// LESSON: Parsing Strategy
	// 1. Find manifest record first
	// 2. Validate expected vs received chunks
	// 3. Decode chunk data

	for _, record := range records {
		if strings.Contains(record.Name, ".m-") {
			// This is a manifest record
			manifest = de.parseManifestRecord(record)
			continue
		}

		if strings.Contains(record.Name, ".c-") {
			// This is a chunk record
			chunk, err := de.parseChunkRecord(record)
			if err != nil {
				// Log but continue - DNS might have garbage
				fmt.Printf("Warning: failed to parse %s: %v\n", record.Name, err)
				continue
			}
			chunks = append(chunks, *chunk)
		}
	}

	if manifest != nil && len(chunks) != manifest.TotalChunks {
		fmt.Printf("Warning: expected %d chunks, got %d\n",
			manifest.TotalChunks, len(chunks))
	}

	return chunks, manifest, nil
}

// parseChunkRecord extracts a chunk from a DNS record
func (de *DNSEncoder) parseChunkRecord(record DNSRecord) (*Chunk, error) {
	// Extract sequence number from name
	// Format: c-{seq}-{msgid} or t{time}-c-{seq}-{msgid}

	parts := strings.Split(record.Name, ".")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid record name: %s", record.Name)
	}

	label := parts[0]

	// Remove timestamp prefix if present
	if strings.HasPrefix(label, "t") {
		idx := strings.Index(label, "-c-")
		if idx > 0 {
			label = label[idx+1:]
		}
	}

	// Parse sequence number
	var seq int
	if strings.HasPrefix(label, "c-") {
		fmt.Sscanf(label, "c-%d-", &seq)
	}

	// Unescape TXT value
	unescaped := de.unescapeTXTValue(record.Value)

	// Decode the chunk (auto-detect encoding)
	chunker := NewChunker(ChunkerConfig{})
	return chunker.DecodeChunk(unescaped)
}

// parseManifestRecord extracts manifest from DNS record
func (de *DNSEncoder) parseManifestRecord(record DNSRecord) *DNSManifest {
	// Parse manifest value
	// Format: TOTAL:CHECKSUM:TIMESTAMP

	parts := strings.Split(record.Value, ":")
	if len(parts) < 3 {
		return nil
	}

	var total int
	var timestamp int64
	fmt.Sscanf(parts[0], "%d", &total)
	fmt.Sscanf(parts[2], "%d", &timestamp)

	// Extract message ID from name
	nameParts := strings.Split(record.Name, ".")
	label := nameParts[0]
	msgID := strings.TrimPrefix(label, "m-")

	return &DNSManifest{
		MessageID:   msgID,
		TotalChunks: total,
		Checksum:    parts[1],
		Timestamp:   time.Unix(timestamp, 0),
		Domain:      de.domain,
	}
}

// unescapeTXTValue reverses TXT record escaping
func (de *DNSEncoder) unescapeTXTValue(value string) string {
	// Reverse the escaping process
	result := strings.ReplaceAll(value, `\"`, `"`)
	result = strings.ReplaceAll(result, `\\`, `\`)
	// Note: \DDD sequences would need more complex parsing
	return result
}

// calculateManifestChecksum creates a checksum for the entire message
func (de *DNSEncoder) calculateManifestChecksum(data []byte) string {
	// Simple checksum for verification
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
		sum = (sum << 1) | (sum >> 31)
	}
	return fmt.Sprintf("%08x", sum)
}

// isAlphanumeric checks if a byte is a-z, 0-9
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// GenerateZoneFile creates a BIND-compatible zone file
func (de *DNSEncoder) GenerateZoneFile(records []DNSRecord) string {
	var zone strings.Builder

	zone.WriteString("; DNS Covert Channel Zone File\n")
	zone.WriteString(fmt.Sprintf("; Generated: %s\n", time.Now().Format(time.RFC3339)))
	zone.WriteString(fmt.Sprintf("; Records: %d\n\n", len(records)))

	for _, record := range records {
		// Format: name TTL IN TXT "value"
		zone.WriteString(fmt.Sprintf("%s. %d IN %s \"%s\"\n",
			record.Name, record.TTL, record.Type, record.Value))
	}

	return zone.String()
}
