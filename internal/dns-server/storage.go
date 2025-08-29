package dnsserver

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ================================================================================
// STORAGE BACKEND FOR DNS COVERT CHANNEL
// Handles message storage with queue semantics and persistence
// ================================================================================

// LESSON: Storage Design Decisions
// 1. In-Memory: Fast but volatile - good for active messages
// 2. Persistent: Survives restarts - good for reliability
// 3. Hybrid: Memory cache + disk backup - best of both

// Message represents a complete covert channel message
type Message struct {
	ID          string            `json:"id"`           // Unique message identifier
	Chunks      map[string]string `json:"chunks"`       // chunk_name -> chunk_data
	TotalChunks int               `json:"total_chunks"` // Expected chunk count
	Manifest    string            `json:"manifest"`     // Manifest record data
	CreatedAt   time.Time         `json:"created_at"`
	State       MessageState      `json:"state"`     // NEW, DELIVERED, CONSUMED
	Consumers   []ConsumerRecord  `json:"consumers"` // Who has fetched this
}

// MessageState tracks lifecycle
type MessageState int

const (
	StateNew       MessageState = iota // Just uploaded, never fetched
	StateDelivered                     // Fetched at least once
	StateConsumed                      // Marked as consumed/processed
	StateExpired                       // TTL exceeded
)

// ConsumerRecord tracks who fetched what
type ConsumerRecord struct {
	ClientIP      string    `json:"client_ip"`
	FetchedAt     time.Time `json:"fetched_at"`
	ChunksFetched []string  `json:"chunks_fetched"`
}

// Storage is our main storage interface
type Storage interface {
	// Basic operations
	StoreMessage(msg *Message) error
	GetMessage(id string) (*Message, error)
	GetChunk(msgID, chunkName string) (string, error)

	// Queue semantics (for covert channel)
	GetNewMessages(clientID string) ([]*Message, error)
	MarkAsDelivered(msgID, clientID string) error
	MarkAsConsumed(msgID, clientID string) error

	// Management
	ListMessages() ([]*Message, error)
	CleanExpired(ttl time.Duration) int
	GetStats() StorageStats
}

// StorageStats provides metrics
type StorageStats struct {
	TotalMessages int
	NewMessages   int
	Delivered     int
	Consumed      int
	TotalChunks   int
	MemoryUsage   int64
}

// ================================================================================
// IN-MEMORY STORAGE IMPLEMENTATION
// ================================================================================

// MemoryStorage keeps everything in RAM
type MemoryStorage struct {
	messages map[string]*Message // msgID -> Message
	chunks   map[string]string   // full_chunk_name -> data
	index    map[string][]string // clientID -> []msgID (for tracking)
	mu       sync.RWMutex
	stats    StorageStats
}

// NewMemoryStorage creates in-memory storage
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		messages: make(map[string]*Message),
		chunks:   make(map[string]string),
		index:    make(map[string][]string),
	}
}

// StoreMessage adds a new message
func (ms *MemoryStorage) StoreMessage(msg *Message) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// LESSON: Atomic Operations
	// We need to ensure all chunks are stored together
	// This is the "A" in ACID - Atomicity

	// Check if message already exists
	if _, exists := ms.messages[msg.ID]; exists {
		return fmt.Errorf("message %s already exists", msg.ID)
	}

	// Store message metadata
	msg.State = StateNew
	msg.CreatedAt = time.Now()
	ms.messages[msg.ID] = msg

	// Store individual chunks for fast lookup
	for chunkName, chunkData := range msg.Chunks {
		ms.chunks[chunkName] = chunkData
	}

	// Update stats
	ms.stats.TotalMessages++
	ms.stats.NewMessages++
	ms.stats.TotalChunks += len(msg.Chunks)

	return nil
}

// GetMessage retrieves a message by ID
func (ms *MemoryStorage) GetMessage(id string) (*Message, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	msg, exists := ms.messages[id]
	if !exists {
		return nil, fmt.Errorf("message %s not found", id)
	}

	return msg, nil
}

// GetChunk retrieves a specific chunk
func (ms *MemoryStorage) GetChunk(msgID, chunkName string) (string, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	// LESSON: Efficient Lookups
	// Direct chunk access avoids iterating through message

	data, exists := ms.chunks[chunkName]
	if !exists {
		return "", fmt.Errorf("chunk %s not found", chunkName)
	}

	return data, nil
}

// GetNewMessages returns undelivered messages for a client
func (ms *MemoryStorage) GetNewMessages(clientID string) ([]*Message, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	// LESSON: Message Queue Pattern
	// Each client tracks what they've seen
	// This implements "at-least-once" delivery

	var newMessages []*Message

	// Get list of messages client has seen
	seenMsgIDs := make(map[string]bool)
	if msgIDs, exists := ms.index[clientID]; exists {
		for _, id := range msgIDs {
			seenMsgIDs[id] = true
		}
	}

	// Find messages client hasn't seen
	for id, msg := range ms.messages {
		if !seenMsgIDs[id] && msg.State == StateNew {
			newMessages = append(newMessages, msg)
		}
	}

	return newMessages, nil
}

// MarkAsDelivered marks message as delivered to a client
func (ms *MemoryStorage) MarkAsDelivered(msgID, clientID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	msg, exists := ms.messages[msgID]
	if !exists {
		return fmt.Errorf("message %s not found", msgID)
	}

	// Update message state
	if msg.State == StateNew {
		msg.State = StateDelivered
		ms.stats.NewMessages--
		ms.stats.Delivered++
	}

	// Record consumer
	msg.Consumers = append(msg.Consumers, ConsumerRecord{
		ClientIP:  clientID,
		FetchedAt: time.Now(),
	})

	// Update index
	ms.index[clientID] = append(ms.index[clientID], msgID)

	return nil
}

// MarkAsConsumed marks message as fully processed
func (ms *MemoryStorage) MarkAsConsumed(msgID, clientID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	msg, exists := ms.messages[msgID]
	if !exists {
		return fmt.Errorf("message %s not found", msgID)
	}

	// Update state
	if msg.State != StateConsumed {
		msg.State = StateConsumed
		ms.stats.Consumed++
	}

	return nil
}

// ListMessages returns all messages
func (ms *MemoryStorage) ListMessages() ([]*Message, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var messages []*Message
	for _, msg := range ms.messages {
		messages = append(messages, msg)
	}

	return messages, nil
}

// CleanExpired removes old messages
func (ms *MemoryStorage) CleanExpired(ttl time.Duration) int {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// LESSON: Garbage Collection
	// Prevents unbounded memory growth

	cutoff := time.Now().Add(-ttl)
	removed := 0

	for id, msg := range ms.messages {
		if msg.CreatedAt.Before(cutoff) {
			// Remove chunks
			for chunkName := range msg.Chunks {
				delete(ms.chunks, chunkName)
			}

			// Remove message
			delete(ms.messages, id)
			removed++

			// Update stats
			ms.stats.TotalMessages--
			ms.stats.TotalChunks -= len(msg.Chunks)
		}
	}

	return removed
}

// GetStats returns storage statistics
func (ms *MemoryStorage) GetStats() StorageStats {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	return ms.stats
}

// ================================================================================
// PERSISTENT STORAGE IMPLEMENTATION
// ================================================================================

// FileStorage adds persistence to memory storage
type FileStorage struct {
	*MemoryStorage
	dataFile string
	mu       sync.Mutex
}

// NewFileStorage creates persistent storage
func NewFileStorage(dataFile string) (*FileStorage, error) {
	fs := &FileStorage{
		MemoryStorage: NewMemoryStorage(),
		dataFile:      dataFile,
	}

	// Load existing data
	if err := fs.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return fs, nil
}

// StoreMessage adds message and persists to disk
func (fs *FileStorage) StoreMessage(msg *Message) error {
	// Store in memory first
	if err := fs.MemoryStorage.StoreMessage(msg); err != nil {
		return err
	}

	// Persist to disk
	return fs.Save()
}

// Save writes current state to disk
func (fs *FileStorage) Save() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// LESSON: Persistence Strategy
	// Simple: JSON file (good for small datasets)
	// Better: SQLite or BoltDB (for larger datasets)
	// Best: Dedicated database (for production)

	data := struct {
		Messages map[string]*Message `json:"messages"`
		Index    map[string][]string `json:"index"`
		Stats    StorageStats        `json:"stats"`
	}{
		Messages: fs.messages,
		Index:    fs.index,
		Stats:    fs.stats,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Atomic write (write to temp, then rename)
	tempFile := fs.dataFile + ".tmp"
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, fs.dataFile); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// Load reads state from disk
func (fs *FileStorage) Load() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	jsonData, err := os.ReadFile(fs.dataFile)
	if err != nil {
		return err
	}

	var data struct {
		Messages map[string]*Message `json:"messages"`
		Index    map[string][]string `json:"index"`
		Stats    StorageStats        `json:"stats"`
	}

	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	fs.messages = data.Messages
	fs.index = data.Index
	fs.stats = data.Stats

	// Rebuild chunks index
	fs.chunks = make(map[string]string)
	for _, msg := range fs.messages {
		for chunkName, chunkData := range msg.Chunks {
			fs.chunks[chunkName] = chunkData
		}
	}

	return nil
}

// ================================================================================
// QUEUE MANAGER - Coordinates message flow
// ================================================================================

// QueueManager adds queue semantics on top of storage
type QueueManager struct {
	storage Storage
	mu      sync.Mutex
}

// NewQueueManager creates a queue manager
func NewQueueManager(storage Storage) *QueueManager {
	return &QueueManager{
		storage: storage,
	}
}

// PublishMessage adds a new message to the queue
func (qm *QueueManager) PublishMessage(id string, chunks map[string]string, manifest string) error {
	msg := &Message{
		ID:          id,
		Chunks:      chunks,
		TotalChunks: len(chunks),
		Manifest:    manifest,
		CreatedAt:   time.Now(),
		State:       StateNew,
	}

	return qm.storage.StoreMessage(msg)
}

// ConsumeMessages gets new messages for a client
func (qm *QueueManager) ConsumeMessages(clientID string) ([]*Message, error) {
	// LESSON: Consumer Pattern
	// 1. Get new messages
	// 2. Mark as delivered
	// 3. Client processes
	// 4. Client acknowledges (mark consumed)

	messages, err := qm.storage.GetNewMessages(clientID)
	if err != nil {
		return nil, err
	}

	// Mark all as delivered
	for _, msg := range messages {
		qm.storage.MarkAsDelivered(msg.ID, clientID)
	}

	return messages, nil
}

// AcknowledgeMessage marks a message as consumed
func (qm *QueueManager) AcknowledgeMessage(msgID, clientID string) error {
	return qm.storage.MarkAsConsumed(msgID, clientID)
}

// GetMessageStatus returns current state of a message
func (qm *QueueManager) GetMessageStatus(msgID string) (string, error) {
	msg, err := qm.storage.GetMessage(msgID)
	if err != nil {
		return "", err
	}

	status := "unknown"
	switch msg.State {
	case StateNew:
		status = "new"
	case StateDelivered:
		status = fmt.Sprintf("delivered to %d clients", len(msg.Consumers))
	case StateConsumed:
		status = "consumed"
	case StateExpired:
		status = "expired"
	}

	return status, nil
}
