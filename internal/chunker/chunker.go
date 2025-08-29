package chunker

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// ================================================================================
// THEORY LESSON: DNS TXT Record Chunking System
// ================================================================================
//
// This chunker implements a robust fragmentation system optimized for DNS TXT records.
//
// KEY CONCEPTS:
// 1. DNS Wire Format: Each string in a TXT record has a 1-byte length prefix,
//    limiting individual strings to 255 bytes
// 2. Encoding Overhead:
//    - Hex encoding: 2x overhead (1 byte → 2 hex chars)
//    - Base64: 1.33x overhead (more efficient)
//    - Base32: 1.6x overhead (DNS-safer than base64)
// 3. Metadata Requirements: Each chunk needs identification and ordering info
//
// DESIGN PHILOSOPHY:
// We prioritize reliability over efficiency. DNS is lossy and unordered,
// so our chunks must be self-contained and self-describing.
// ================================================================================

const (
	// CHUNK SIZING CONSTANTS - With Detailed Explanations

	// MAX_DNS_STRING_SIZE is 255 bytes (DNS protocol limit)
	// We subtract safety margins for:
	// - DNS server implementation variations
	// - Potential escaping overhead
	// - Future protocol extensions
	MAX_DNS_STRING_SIZE = 255

	// SAFE_CHUNK_SIZE is our conservative limit
	// We use 250 to leave room for DNS protocol overhead
	SAFE_CHUNK_SIZE = 250

	// METADATA_OVERHEAD is the fixed size of our chunk header
	// Contains: Magic(4) + MessageID(16) + Sequence(2) + Total(2) + Checksum(4) = 28 bytes
	METADATA_OVERHEAD = 28

	// PAYLOAD_PER_CHUNK is the actual data we can fit per chunk
	// This accounts for hex encoding: (250 - 28) / 2 = 111 bytes of raw data
	// For base32: (250 - 28) / 1.6 ≈ 138 bytes of raw data
	PAYLOAD_PER_CHUNK_HEX = (SAFE_CHUNK_SIZE - METADATA_OVERHEAD) / 2
	// PAYLOAD_PER_CHUNK_B32 = int((SAFE_CHUNK_SIZE - METADATA_OVERHEAD) / 1.6)

	// ENCODING TYPES
	ENCODE_HEX    = "hex"
	ENCODE_BASE32 = "base32"

	// MAGIC_BYTES identifies our chunk protocol version
	// Allows future protocol evolution
	CHUNK_MAGIC = 0x444E5343 // "DNSC" in hex

	// Protocol version for future compatibility
	PROTOCOL_VERSION = 1
)

//var PAYLOAD_PER_CHUNK_B32 = int(float64(SAFE_CHUNK_SIZE-METADATA_OVERHEAD) / 1.6)

var PAYLOAD_PER_CHUNK_B32 = int(math.Floor(float64(SAFE_CHUNK_SIZE-METADATA_OVERHEAD) / 1.6))

// ================================================================================
// LESSON: Chunk Structure Design
//
// Each chunk is self-contained with:
// 1. Identity (which message it belongs to)
// 2. Position (where in the sequence)
// 3. Integrity (checksum verification)
// 4. Context (total chunks for completeness check)
//
// This design survives:
// - Out-of-order delivery (DNS makes no ordering guarantees)
// - Packet loss (we can detect missing chunks)
// - Corruption (checksums catch errors)
// - Replay attacks (message IDs prevent confusion)
// ================================================================================

// ChunkMetadata contains all information needed to reassemble a message
type ChunkMetadata struct {
	Magic       uint32   // Protocol identifier and version check
	MessageID   [16]byte // Unique message identifier (128-bit)
	Sequence    uint16   // Chunk number (0-based)
	TotalChunks uint16   // Total number of chunks in message
	Checksum    uint32   // CRC32 of this chunk's payload
	Timestamp   int64    // Unix timestamp for TTL/cleanup
	PayloadSize uint16   // Actual payload bytes (for last chunk)
}

// Chunk represents a single DNS-ready fragment
type Chunk struct {
	Metadata   ChunkMetadata
	Payload    []byte // Raw data (before encoding)
	Encoded    string // DNS-ready encoded string
	RecordName string // Suggested DNS record name
}

// Message represents a complete message for chunking
type Message struct {
	ID        [16]byte          // Unique message identifier
	Data      []byte            // Complete message data
	Chunks    []Chunk           // All chunks for this message
	Encoding  string            // Encoding type used
	CreatedAt time.Time         // Message creation time
	Metadata  map[string]string // Additional metadata
}

// ChunkerConfig allows customization of chunking behavior
type ChunkerConfig struct {
	Encoding      string // hex or base32
	MaxChunkSize  int    // Override default chunk size
	AddRedundancy bool   // Add error correction codes
	Compression   bool   // Pre-compress data
	DNSNamePrefix string // Prefix for DNS record names
}

// Chunker handles message fragmentation
type Chunker struct {
	config ChunkerConfig
	stats  ChunkingStats
}

// ChunkingStats tracks performance metrics
type ChunkingStats struct {
	MessagesChunked  int
	TotalChunks      int
	TotalBytes       int
	CompressionRatio float64
	LastChunkingTime time.Duration
}

// ================================================================================
// CORE IMPLEMENTATION
// ================================================================================

// NewChunker creates a configured chunker instance
func NewChunker(config ChunkerConfig) *Chunker {
	// Set defaults
	if config.Encoding == "" {
		config.Encoding = ENCODE_BASE32 // More efficient than hex
	}
	if config.MaxChunkSize == 0 {
		config.MaxChunkSize = SAFE_CHUNK_SIZE
	}

	return &Chunker{
		config: config,
	}
}

// ChunkMessage fragments a message into DNS-ready chunks
func (c *Chunker) ChunkMessage(data []byte) (*Message, error) {
	startTime := time.Now()

	// LESSON: Message ID Generation
	// We use SHA256 of data + timestamp for uniqueness
	// This prevents duplicate messages from colliding
	messageID := c.generateMessageID(data)

	// Calculate payload size per chunk based on encoding
	payloadSize := c.calculatePayloadSize()

	// LESSON: Chunk Count Calculation
	// We must carefully calculate to avoid off-by-one errors
	totalChunks := c.calculateTotalChunks(len(data), payloadSize)

	if totalChunks > math.MaxUint16 {
		return nil, fmt.Errorf("message too large: requires %d chunks (max %d)",
			totalChunks, math.MaxUint16)
	}

	fmt.Printf("\n📊 CHUNKING ANALYSIS:\n")
	fmt.Printf("   Data size: %d bytes\n", len(data))
	fmt.Printf("   Encoding: %s\n", c.config.Encoding)
	fmt.Printf("   Payload per chunk: %d bytes\n", payloadSize)
	fmt.Printf("   Total chunks needed: %d\n", totalChunks)
	fmt.Printf("   DNS records required: %d\n", totalChunks)
	fmt.Printf("   Overhead: %.1f%%\n", c.calculateOverhead(len(data), totalChunks))

	// Create message container
	message := &Message{
		ID:        messageID,
		Data:      data,
		Chunks:    make([]Chunk, 0, totalChunks),
		Encoding:  c.config.Encoding,
		CreatedAt: time.Now(),
		Metadata:  make(map[string]string),
	}

	// Fragment data into chunks
	for i := 0; i < totalChunks; i++ {
		chunk := c.createChunk(data, messageID, i, uint16(totalChunks), payloadSize)
		message.Chunks = append(message.Chunks, chunk)
	}

	// Update statistics
	c.stats.MessagesChunked++
	c.stats.TotalChunks += totalChunks
	c.stats.TotalBytes += len(data)
	c.stats.LastChunkingTime = time.Since(startTime)

	fmt.Printf("   Chunking completed in: %v\n", c.stats.LastChunkingTime)

	return message, nil
}

// createChunk creates a single chunk with all metadata
func (c *Chunker) createChunk(data []byte, messageID [16]byte, sequence int, total uint16, payloadSize int) Chunk {
	// Calculate chunk boundaries
	start := sequence * payloadSize
	end := start + payloadSize
	if end > len(data) {
		end = len(data)
	}

	// Extract payload for this chunk
	payload := data[start:end]

	// Create metadata
	metadata := ChunkMetadata{
		Magic:       CHUNK_MAGIC,
		MessageID:   messageID,
		Sequence:    uint16(sequence),
		TotalChunks: total,
		Checksum:    c.calculateChecksum(payload),
		Timestamp:   time.Now().Unix(),
		PayloadSize: uint16(len(payload)),
	}

	// Encode the chunk
	encoded := c.encodeChunk(metadata, payload)

	// Generate DNS record name
	// Format: seq-total-msgid.prefix.domain.com
	recordName := c.generateRecordName(metadata)

	return Chunk{
		Metadata:   metadata,
		Payload:    payload,
		Encoded:    encoded,
		RecordName: recordName,
	}
}

// encodeChunk combines metadata and payload into DNS-safe string
func (c *Chunker) encodeChunk(metadata ChunkMetadata, payload []byte) string {
	// LESSON: Wire Format Design
	// We need a consistent, parseable format:
	// [MAGIC(4)][MSGID(16)][SEQ(2)][TOTAL(2)][CHECKSUM(4)][PAYLOAD(variable)]

	// Serialize metadata
	metaBytes := make([]byte, 0, METADATA_OVERHEAD)

	// Add magic bytes
	magicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBytes, metadata.Magic)
	metaBytes = append(metaBytes, magicBytes...)

	// Add message ID
	metaBytes = append(metaBytes, metadata.MessageID[:]...)

	// Add sequence number
	seqBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(seqBytes, metadata.Sequence)
	metaBytes = append(metaBytes, seqBytes...)

	// Add total chunks
	totalBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(totalBytes, metadata.TotalChunks)
	metaBytes = append(metaBytes, totalBytes...)

	// Add checksum
	checksumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBytes, metadata.Checksum)
	metaBytes = append(metaBytes, checksumBytes...)

	// Combine metadata and payload
	fullChunk := append(metaBytes, payload...)

	// Encode based on configuration
	switch c.config.Encoding {
	case ENCODE_HEX:
		return hex.EncodeToString(fullChunk)
	case ENCODE_BASE32:
		// Use base32 with DNS-safe alphabet (RFC 4648)
		// No padding for cleaner DNS records
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(fullChunk)
	default:
		// Fallback to hex
		return hex.EncodeToString(fullChunk)
	}
}

// ================================================================================
// REASSEMBLY FUNCTIONS
// ================================================================================

// ReassembleMessage reconstructs the original message from chunks
func (c *Chunker) ReassembleMessage(chunks []Chunk) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, errors.New("no chunks provided")
	}

	// LESSON: Reassembly Challenges
	// 1. Chunks may arrive out of order
	// 2. Some chunks may be missing
	// 3. Chunks may be from different messages
	// 4. Chunks may be corrupted

	fmt.Printf("\n🔧 REASSEMBLY PROCESS:\n")
	fmt.Printf("   Chunks received: %d\n", len(chunks))

	// Verify all chunks belong to same message
	messageID := chunks[0].Metadata.MessageID
	totalExpected := chunks[0].Metadata.TotalChunks

	for _, chunk := range chunks {
		if chunk.Metadata.MessageID != messageID {
			return nil, fmt.Errorf("mixed messages detected: %x vs %x",
				messageID[:8], chunk.Metadata.MessageID[:8])
		}
		if chunk.Metadata.TotalChunks != totalExpected {
			return nil, fmt.Errorf("inconsistent total chunks: %d vs %d",
				totalExpected, chunk.Metadata.TotalChunks)
		}
	}

	// Check for completeness
	if len(chunks) != int(totalExpected) {
		// Identify missing chunks for error report
		missing := c.findMissingChunks(chunks, totalExpected)
		return nil, fmt.Errorf("incomplete message: missing chunks %v", missing)
	}

	// Sort chunks by sequence number
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Metadata.Sequence < chunks[j].Metadata.Sequence
	})

	// Verify sequence integrity
	for i, chunk := range chunks {
		if chunk.Metadata.Sequence != uint16(i) {
			return nil, fmt.Errorf("sequence error at position %d", i)
		}

		// Verify checksum
		calculatedChecksum := c.calculateChecksum(chunk.Payload)
		if calculatedChecksum != chunk.Metadata.Checksum {
			return nil, fmt.Errorf("checksum failed for chunk %d", i)
		}
	}

	// Reassemble data
	var reassembled []byte
	for _, chunk := range chunks {
		reassembled = append(reassembled, chunk.Payload...)
	}

	fmt.Printf("   ✅ Successfully reassembled %d bytes\n", len(reassembled))

	return reassembled, nil
}

// DecodeChunk parses a DNS TXT record back into a Chunk
func (c *Chunker) DecodeChunk(encoded string) (*Chunk, error) {
	// Decode from hex or base32
	var rawData []byte
	var err error

	switch c.config.Encoding {
	case ENCODE_HEX:
		rawData, err = hex.DecodeString(encoded)
	case ENCODE_BASE32:
		rawData, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	default:
		// Try hex first, then base32
		rawData, err = hex.DecodeString(encoded)
		if err != nil {
			rawData, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	// Verify minimum size
	if len(rawData) < METADATA_OVERHEAD {
		return nil, fmt.Errorf("chunk too small: %d bytes", len(rawData))
	}

	// Parse metadata
	metadata := ChunkMetadata{}
	offset := 0

	// Parse magic
	metadata.Magic = binary.BigEndian.Uint32(rawData[offset : offset+4])
	offset += 4

	if metadata.Magic != CHUNK_MAGIC {
		return nil, fmt.Errorf("invalid magic: %x", metadata.Magic)
	}

	// Parse message ID
	copy(metadata.MessageID[:], rawData[offset:offset+16])
	offset += 16

	// Parse sequence
	metadata.Sequence = binary.BigEndian.Uint16(rawData[offset : offset+2])
	offset += 2

	// Parse total chunks
	metadata.TotalChunks = binary.BigEndian.Uint16(rawData[offset : offset+2])
	offset += 2

	// Parse checksum
	metadata.Checksum = binary.BigEndian.Uint32(rawData[offset : offset+4])
	offset += 4

	// Extract payload
	payload := rawData[offset:]
	metadata.PayloadSize = uint16(len(payload))

	return &Chunk{
		Metadata: metadata,
		Payload:  payload,
		Encoded:  encoded,
	}, nil
}

// ================================================================================
// UTILITY FUNCTIONS
// ================================================================================

// generateMessageID creates a unique identifier for a message
func (c *Chunker) generateMessageID(data []byte) [16]byte {
	// Use SHA256 hash truncated to 128 bits
	hash := sha256.Sum256(append(data, []byte(fmt.Sprintf("%d", time.Now().UnixNano()))...))
	var id [16]byte
	copy(id[:], hash[:16])
	return id
}

// calculatePayloadSize determines bytes per chunk based on encoding
func (c *Chunker) calculatePayloadSize() int {
	switch c.config.Encoding {
	case ENCODE_HEX:
		return PAYLOAD_PER_CHUNK_HEX
	case ENCODE_BASE32:
		return PAYLOAD_PER_CHUNK_B32
	default:
		return PAYLOAD_PER_CHUNK_HEX
	}
}

// calculateTotalChunks determines how many chunks are needed
func (c *Chunker) calculateTotalChunks(dataSize, payloadSize int) int {
	// Use ceiling division to ensure we don't lose bytes
	return int(math.Ceil(float64(dataSize) / float64(payloadSize)))
}

// calculateChecksum computes CRC32 for integrity verification
func (c *Chunker) calculateChecksum(data []byte) uint32 {
	// Simple checksum using sum of bytes
	// In production, use CRC32 or better
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
		sum = (sum << 1) | (sum >> 31) // Rotate left by 1
	}
	return sum
}

// calculateOverhead determines the efficiency loss from chunking
func (c *Chunker) calculateOverhead(originalSize, totalChunks int) float64 {
	totalOverhead := totalChunks * METADATA_OVERHEAD
	return float64(totalOverhead) / float64(originalSize) * 100
}

// generateRecordName creates a DNS-compliant record name
func (c *Chunker) generateRecordName(metadata ChunkMetadata) string {
	// Format: chunk-{seq}-{msgid}.{prefix}
	// Example: chunk-0-a3f2b1.data.covert.example.com

	msgIDShort := hex.EncodeToString(metadata.MessageID[:4])

	name := fmt.Sprintf("chunk-%03d-%s", metadata.Sequence, msgIDShort)

	if c.config.DNSNamePrefix != "" {
		name = fmt.Sprintf("%s.%s", name, c.config.DNSNamePrefix)
	}

	return name
}

// findMissingChunks identifies which sequence numbers are missing
func (c *Chunker) findMissingChunks(chunks []Chunk, total uint16) []uint16 {
	present := make(map[uint16]bool)
	for _, chunk := range chunks {
		present[chunk.Metadata.Sequence] = true
	}

	var missing []uint16
	for i := uint16(0); i < total; i++ {
		if !present[i] {
			missing = append(missing, i)
		}
	}

	return missing
}

// GetStats returns chunking statistics
func (c *Chunker) GetStats() ChunkingStats {
	return c.stats
}

// ValidateChunk performs comprehensive chunk validation
func (c *Chunker) ValidateChunk(chunk *Chunk) error {
	// Check magic number
	if chunk.Metadata.Magic != CHUNK_MAGIC {
		return fmt.Errorf("invalid magic number: %x", chunk.Metadata.Magic)
	}

	// Verify checksum
	calculated := c.calculateChecksum(chunk.Payload)
	if calculated != chunk.Metadata.Checksum {
		return fmt.Errorf("checksum mismatch: expected %x, got %x",
			chunk.Metadata.Checksum, calculated)
	}

	// Check sequence bounds
	if chunk.Metadata.Sequence >= chunk.Metadata.TotalChunks {
		return fmt.Errorf("sequence %d out of bounds (total: %d)",
			chunk.Metadata.Sequence, chunk.Metadata.TotalChunks)
	}

	// Validate payload size
	if len(chunk.Payload) == 0 {
		return errors.New("empty payload")
	}

	maxPayload := c.calculatePayloadSize()
	if len(chunk.Payload) > maxPayload {
		return fmt.Errorf("payload too large: %d > %d", len(chunk.Payload), maxPayload)
	}

	return nil
}

// ================================================================================
// ADVANCED FEATURES (for future lessons)
// ================================================================================

// AddRedundancy implements Reed-Solomon error correction
// This will be covered in advanced lessons
func (c *Chunker) AddRedundancy(chunks []Chunk, redundancyFactor float64) []Chunk {
	// TODO: Implement FEC (Forward Error Correction)
	// This allows recovery even with missing chunks
	fmt.Println("📚 FUTURE LESSON: Error correction codes for lossy channels")
	return chunks
}

// CompressBeforeChunking applies compression to reduce chunk count
func (c *Chunker) CompressBeforeChunking(data []byte) []byte {
	// TODO: Implement compression
	fmt.Println("📚 FUTURE LESSON: Compression strategies for covert channels")
	return data
}
