package decoder

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/spec"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"strings"
)

// DecryptPayload decrypts the extracted payload
func (ssd *SecureStegoDecoder) DecryptPayload() (*ExtractedMessage, error) {
	fmt.Printf("\n🔓 Decryption process:\n")

	// Parse secure payload structure
	if len(ssd.securePayload) < spec.SALT_SIZE+spec.NONCE_SIZE+spec.TAG_SIZE {
		return nil, fmt.Errorf("payload too small for decryption")
	}

	offset := 0

	// Extract salt
	salt := ssd.securePayload[offset : offset+spec.SALT_SIZE]
	offset += spec.SALT_SIZE
	fmt.Printf("   Salt: %X...\n", salt[:8])

	// Extract nonce
	nonce := ssd.securePayload[offset : offset+spec.NONCE_SIZE]
	offset += spec.NONCE_SIZE
	fmt.Printf("   Nonce: %X...\n", nonce[:6])

	// Remaining is encrypted data + auth tag
	ciphertext := ssd.securePayload[offset:]
	if len(ciphertext) < spec.TAG_SIZE {
		return nil, fmt.Errorf("insufficient data for auth tag")
	}

	fmt.Printf("   Ciphertext size: %d bytes\n", len(ciphertext))

	// Derive key from password
	fmt.Printf("\n🔑 Key derivation:\n")
	fmt.Printf("   Using PBKDF2 with %d iterations...\n", spec.PBKDF2_ITERS)
	key := pbkdf2.Key(ssd.password, salt, spec.PBKDF2_ITERS, spec.KEY_SIZE, sha256.New)

	fingerprint := fmt.Sprintf("%X", key[:4])
	fmt.Printf("   Key fingerprint: %s...\n", fingerprint)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	// Decrypt and authenticate
	fmt.Printf("\n🔐 Attempting decryption...\n")
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			return nil, fmt.Errorf("❌ AUTHENTICATION FAILED - Wrong password or corrupted data")
		}
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	fmt.Printf("   ✅ Authentication successful!\n")
	fmt.Printf("   Decrypted size: %d bytes\n", len(plaintext))

	// Verify magic header
	if len(plaintext) < 4 {
		return nil, fmt.Errorf("decrypted data too small")
	}

	magic := binary.BigEndian.Uint32(plaintext[:4])
	if magic != spec.MAGIC_HEADER {
		return nil, fmt.Errorf("invalid magic header: %X (expected %X)", magic, spec.MAGIC_HEADER)
	}

	fmt.Printf("   ✅ Magic header verified\n")

	// Extract actual message (skip magic header)
	messageData := plaintext[4:]

	// Try to decompress
	wasCompressed := false
	finalMessage := messageData

	// Check if data might be compressed (gzip magic: 1f8b)
	if len(messageData) >= 2 && messageData[0] == 0x1f && messageData[1] == 0x8b {
		fmt.Printf("\n📦 Detected compression, decompressing...\n")
		reader, err := gzip.NewReader(bytes.NewReader(messageData))
		if err == nil {
			decompressed, err := io.ReadAll(reader)
			reader.Close()
			if err == nil {
				wasCompressed = true
				finalMessage = decompressed
				fmt.Printf("   Decompressed: %d → %d bytes\n", len(messageData), len(decompressed))
			}
		}
	}

	return &ExtractedMessage{
		Message:       finalMessage,
		WasCompressed: wasCompressed,
		EncryptedSize: len(ciphertext),
		DecryptedSize: len(finalMessage),
		Authenticated: true,
	}, nil
}

// ExtractedMessage contains decrypted message and metadata
type ExtractedMessage struct {
	Message       []byte
	WasCompressed bool
	EncryptedSize int
	DecryptedSize int
	Authenticated bool
}
