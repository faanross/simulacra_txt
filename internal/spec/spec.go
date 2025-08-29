package spec

// Steganography constants
const (
	DEFAULT_WIDTH = 64 // Default image width (px)
	HEADER_BITS   = 32 // Bits for storing message length
	HEADER_SIZE   = 4
	BITS_PER_BYTE = 8 // Standard byte size
	CHANNELS      = 3 // RGB channels
)

// Security constants
const (
	SALT_SIZE    = 32     // Salt for PBKDF2
	NONCE_SIZE   = 12     // GCM nonce size
	KEY_SIZE     = 32     // AES-256 key size
	TAG_SIZE     = 16     // GCM authentication tag
	PBKDF2_ITERS = 100000 // PBKDF2 iterations (adjustable for security/speed)

	// Magic bytes to verify successful decryption (optional)
	MAGIC_HEADER = 0xDEADBEEF
)
