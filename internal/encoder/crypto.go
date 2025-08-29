package encoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/scrypto"
	"github.com/faanross/simulacra_txt/internal/spec"
	"io"
	mrand "math/rand"
)

// EncryptMessage performs AES-256-GCM encryption
func (sse *SecureStegoEncoder) EncryptMessage() (*scrypto.SecureMessage, error) {
	fmt.Printf("\n🔐 Encryption Process:\n")

	// Step 1: Optionally compress
	dataToEncrypt := sse.message
	if sse.useCompression {
		compressed, err := CompressData(sse.message)
		if err != nil {
			return nil, fmt.Errorf("compression failed: %w", err)
		}
		dataToEncrypt = compressed
	}

	// Step 2: Generate random salt
	salt := make([]byte, spec.SALT_SIZE)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}

	// Step 3: Derive key from password
	key := scrypto.DeriveKey(sse.password, salt)

	// Step 4: Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	// Step 5: Generate nonce
	nonce := make([]byte, spec.NONCE_SIZE)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// Step 6: Add magic header to verify decryption
	payload := make([]byte, 4+len(dataToEncrypt))
	binary.BigEndian.PutUint32(payload[:4], spec.MAGIC_HEADER)
	copy(payload[4:], dataToEncrypt)

	// Step 7: Encrypt with authentication
	ciphertext := gcm.Seal(nil, nonce, payload, nil)

	// The Seal function appends the auth tag to the ciphertext
	// Split them for clarity
	encryptedData := ciphertext[:len(ciphertext)-spec.TAG_SIZE]
	authTag := ciphertext[len(ciphertext)-spec.TAG_SIZE:]

	fmt.Printf("   Original size: %d bytes\n", len(sse.message))
	fmt.Printf("   Encrypted size: %d bytes\n", len(encryptedData))
	fmt.Printf("   Auth tag: %X...\n", authTag[:4])

	return &scrypto.SecureMessage{
		Salt:           salt,
		Nonce:          nonce,
		EncryptedData:  encryptedData,
		AuthTag:        authTag,
		CompressedSize: len(dataToEncrypt),
		OriginalSize:   len(sse.message),
	}, nil
}

// PrepareSecurePayload creates the final payload for embedding
func (sse *SecureStegoEncoder) PrepareSecurePayload() error {
	// Encrypt the message
	secMsg, err := sse.EncryptMessage()
	if err != nil {
		return err
	}

	// Create payload structure:
	// [TotalLength(4)][Salt(32)][Nonce(12)][EncryptedData][AuthTag(16)]

	totalSize := spec.SALT_SIZE + spec.NONCE_SIZE + len(secMsg.EncryptedData) + spec.TAG_SIZE
	payload := make([]byte, 4+totalSize)

	// Write total length
	binary.BigEndian.PutUint32(payload[:4], uint32(totalSize))

	// Write components
	offset := 4
	copy(payload[offset:], secMsg.Salt)
	offset += spec.SALT_SIZE

	copy(payload[offset:], secMsg.Nonce)
	offset += spec.NONCE_SIZE

	copy(payload[offset:], secMsg.EncryptedData)
	offset += len(secMsg.EncryptedData)

	copy(payload[offset:], secMsg.AuthTag)

	// Add random padding to hide exact message length
	// This provides additional security against length analysis
	paddingSize := mrand.Intn(256) + 128 // 128-384 bytes of random padding
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	sse.securePayload = append(payload, padding...)

	fmt.Printf("\n📦 Secure Payload Structure:\n")
	fmt.Printf("   Header: 4 bytes\n")
	fmt.Printf("   Salt: %d bytes\n", spec.SALT_SIZE)
	fmt.Printf("   Nonce: %d bytes\n", spec.NONCE_SIZE)
	fmt.Printf("   Encrypted: %d bytes\n", len(secMsg.EncryptedData))
	fmt.Printf("   Auth Tag: %d bytes\n", spec.TAG_SIZE)
	fmt.Printf("   Random Padding: %d bytes\n", paddingSize)
	fmt.Printf("   Total: %d bytes\n", len(sse.securePayload))

	return nil
}
