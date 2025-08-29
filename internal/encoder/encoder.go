package encoder

import (
	"crypto/rand"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/spec"
	"image"
	"image/color"
)

// SecureStegoEncoder handles encrypted steganography
type SecureStegoEncoder struct {
	width          int
	height         int
	password       []byte
	message        []byte
	securePayload  []byte
	useCompression bool
	addDecoy       bool
}

// NewSecureStegoEncoder creates an encoder with encryption
func NewSecureStegoEncoder(message []byte, password []byte, width int, compress bool) *SecureStegoEncoder {
	return &SecureStegoEncoder{
		width:          width,
		password:       password,
		message:        message,
		useCompression: compress,
	}
}

// EmbedBit modifies the LSB of a color value to store a bit
func EmbedBit(colorValue uint8, bit bool) uint8 {
	if bit {
		// Set LSB to 1: use bitwise OR with 1
		return colorValue | 1
	} else {
		// Set LSB to 0: use bitwise AND with 254 (11111110)
		return colorValue & 0xFE
	}
}

// CreateStegoImage generates the image with encrypted embedded data
func (sse *SecureStegoEncoder) CreateStegoImage() (*image.RGBA, error) {
	// Prepare encrypted payload
	err := sse.PrepareSecurePayload()
	if err != nil {
		return nil, err
	}

	// Calculate dimensions
	sse.CalculateImageDimensions()

	// Convert payload to bits
	bits := make([]bool, len(sse.securePayload)*spec.BITS_PER_BYTE)
	for i, b := range sse.securePayload {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (b & (1 << (7 - j))) != 0
		}
	}

	// Create image
	img := image.NewRGBA(image.Rect(0, 0, sse.width, sse.height))

	fmt.Printf("\n🎨 Embedding Encrypted Data:\n")

	// Use cryptographically secure random base colors
	// This makes the image appear more random and harder to detect
	bitIndex := 0
	for y := 0; y < sse.height; y++ {
		for x := 0; x < sse.width; x++ {
			// Generate cryptographically random base colors
			var baseColors [3]byte
			rand.Read(baseColors[:])

			// Embed bits in LSBs
			if bitIndex < len(bits) {
				if bits[bitIndex] {
					baseColors[0] |= 1
				} else {
					baseColors[0] &= 0xFE
				}
				bitIndex++
			}

			if bitIndex < len(bits) {
				if bits[bitIndex] {
					baseColors[1] |= 1
				} else {
					baseColors[1] &= 0xFE
				}
				bitIndex++
			}

			if bitIndex < len(bits) {
				if bits[bitIndex] {
					baseColors[2] |= 1
				} else {
					baseColors[2] &= 0xFE
				}
				bitIndex++
			}

			img.Set(x, y, color.RGBA{
				R: baseColors[0],
				G: baseColors[1],
				B: baseColors[2],
				A: 255,
			})
		}
	}

	fmt.Printf("   Bits embedded: %d\n", min(bitIndex, len(bits)))
	fmt.Printf("   Security level: AES-256-GCM + PBKDF2\n")

	return img, nil
}
