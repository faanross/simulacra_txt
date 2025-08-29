package scrypto

import (
	"crypto/sha256"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/decoder"
	"github.com/faanross/simulacra_txt/internal/spec"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
	"image"
	"strings"
	"syscall"
)

// SecureMessage contains all cryptographic components
type SecureMessage struct {
	Salt           []byte
	Nonce          []byte
	EncryptedData  []byte
	AuthTag        []byte
	CompressedSize int
	OriginalSize   int
}

// DeriveKey generates encryption key from password using PBKDF2
func DeriveKey(password, salt []byte) []byte {
	fmt.Printf("\n🔑 Key Derivation:\n")
	fmt.Printf("   Algorithm: PBKDF2-SHA256\n")
	fmt.Printf("   Iterations: %d\n", spec.PBKDF2_ITERS)
	fmt.Printf("   Salt length: %d bytes\n", len(salt))

	key := pbkdf2.Key(password, salt, spec.PBKDF2_ITERS, spec.KEY_SIZE, sha256.New)

	// Display key fingerprint (first 4 bytes as hex)
	fingerprint := fmt.Sprintf("%X", key[:4])
	fmt.Printf("   Key fingerprint: %s...\n", fingerprint)

	return key
}

// GetSecurePassword prompts for password with hidden input
func GetSecurePassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // New line after password

	if err != nil {
		return nil, fmt.Errorf("password read failed: %w", err)
	}

	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	return password, nil
}

// TryMultiplePasswords attempts decryption with multiple passwords
func TryMultiplePasswords(img image.Image, passwords []string) {
	fmt.Printf("\n🔑 Trying %d passwords:\n", len(passwords))

	for i, pass := range passwords {
		fmt.Printf("\n   Attempt %d/%d: ", i+1, len(passwords))

		stegDecoder := decoder.NewSecureStegoDecoder(img, []byte(pass))
		stegDecoder.ExtractBitStream()

		err := stegDecoder.ExtractSecurePayload()
		if err != nil {
			fmt.Printf("❌ Failed (extraction)\n")
			continue
		}

		result, err := stegDecoder.DecryptPayload()
		if err != nil {
			if strings.Contains(err.Error(), "AUTHENTICATION FAILED") {
				fmt.Printf("❌ Wrong password\n")
			} else {
				fmt.Printf("❌ Failed: %v\n", err)
			}
			continue
		}

		fmt.Printf("✅ SUCCESS!\n")
		fmt.Printf("\n📝 Decrypted message preview:\n")
		preview := string(result.Message)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		fmt.Printf("%s\n", preview)
		return
	}

	fmt.Printf("\n❌ All passwords failed\n")
}
