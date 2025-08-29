package decoder

import (
	"encoding/binary"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/spec"
	"image"
)

// SecureStegoDecoder handles decryption and extraction
type SecureStegoDecoder struct {
	img           image.Image
	width         int
	height        int
	password      []byte
	bits          []bool
	securePayload []byte
}

// NewSecureStegoDecoder creates a decoder instance
func NewSecureStegoDecoder(img image.Image, password []byte) *SecureStegoDecoder {
	bounds := img.Bounds()
	return &SecureStegoDecoder{
		img:      img,
		width:    bounds.Max.X - bounds.Min.X,
		height:   bounds.Max.Y - bounds.Min.Y,
		password: password,
	}
}

// ExtractBitStream extracts all LSBs from the image
func (ssd *SecureStegoDecoder) ExtractBitStream() {
	maxBits := ssd.width * ssd.height * spec.CHANNELS
	ssd.bits = make([]bool, 0, maxBits)

	fmt.Printf("\n🔍 Extracting encrypted data from image (%dx%d):\n", ssd.width, ssd.height)

	pixelsRead := 0

	for y := 0; y < ssd.height; y++ {
		for x := 0; x < ssd.width; x++ {
			r, g, b, _ := ssd.img.At(x, y).RGBA()

			// Extract LSBs
			ssd.bits = append(ssd.bits,
				(uint8(r>>8)&1) == 1,
				(uint8(g>>8)&1) == 1,
				(uint8(b>>8)&1) == 1,
			)

			pixelsRead++
			if pixelsRead%10000 == 0 {
				fmt.Printf("   Processed %d pixels...\n", pixelsRead)
			}
		}
	}

	fmt.Printf("   Total bits extracted: %d\n", len(ssd.bits))
}

// ExtractSecurePayload reconstructs the encrypted payload from bits
func (ssd *SecureStegoDecoder) ExtractSecurePayload() error {
	if len(ssd.bits) < spec.HEADER_SIZE*spec.BITS_PER_BYTE {
		return fmt.Errorf("insufficient bits for header")
	}

	// Extract payload length from first 32 bits
	lengthBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			if ssd.bits[i*8+j] {
				b |= 1 << (7 - j)
			}
		}
		lengthBytes[i] = b
	}

	payloadLength := binary.BigEndian.Uint32(lengthBytes)
	fmt.Printf("\n📦 Extracting secure payload:\n")
	fmt.Printf("   Payload length: %d bytes\n", payloadLength)

	// Validate payload length
	maxBytes := (len(ssd.bits) - spec.HEADER_SIZE*spec.BITS_PER_BYTE) / spec.BITS_PER_BYTE
	if int(payloadLength) > maxBytes {
		return fmt.Errorf("payload length %d exceeds available %d bytes", payloadLength, maxBytes)
	}

	// Sanity check
	expectedMinSize := spec.SALT_SIZE + spec.NONCE_SIZE + spec.TAG_SIZE + 4 // Min encrypted size
	if payloadLength < uint32(expectedMinSize) {
		return fmt.Errorf("payload too small to contain encrypted data: %d < %d",
			payloadLength, expectedMinSize)
	}

	// Extract payload bytes
	ssd.securePayload = make([]byte, payloadLength)
	bitOffset := spec.HEADER_SIZE * spec.BITS_PER_BYTE

	for i := 0; i < int(payloadLength); i++ {
		var b byte
		for j := 0; j < 8; j++ {
			bitIndex := bitOffset + i*8 + j
			if bitIndex >= len(ssd.bits) {
				return fmt.Errorf("unexpected end of bit stream")
			}
			if ssd.bits[bitIndex] {
				b |= 1 << (7 - j)
			}
		}
		ssd.securePayload[i] = b

		// Show progress for large payloads
		if i > 0 && i%1000 == 0 {
			fmt.Printf("   Extracted %d/%d bytes...\n", i, payloadLength)
		}
	}

	fmt.Printf("   Successfully extracted %d bytes\n", len(ssd.securePayload))
	return nil
}
