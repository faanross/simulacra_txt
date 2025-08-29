package encoder

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/spec"
	"image"
	"math"
)

// CalculateImageDimensions determines required image size
func (sse *SecureStegoEncoder) CalculateImageDimensions() {
	totalBits := len(sse.securePayload) * spec.BITS_PER_BYTE
	pixelsNeeded := int(math.Ceil(float64(totalBits) / float64(spec.CHANNELS)))
	sse.height = int(math.Ceil(float64(pixelsNeeded) / float64(sse.width)))

	fmt.Printf("\n📊 Steganography Parameters:\n")
	fmt.Printf("   Payload size: %d bytes\n", len(sse.securePayload))
	fmt.Printf("   Bits needed: %d\n", totalBits)
	fmt.Printf("   Image dimensions: %dx%d\n", sse.width, sse.height)
	fmt.Printf("   Total capacity: %d bits\n", sse.width*sse.height*spec.CHANNELS)
	fmt.Printf("   Utilization: %.1f%%\n",
		float64(totalBits)*100/float64(sse.width*sse.height*spec.CHANNELS))
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CompressData uses gzip to compress the message
func CompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	_, err := writer.Write(data)
	if err != nil {
		return nil, fmt.Errorf("compression write failed: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("compression close failed: %w", err)
	}

	compressed := buf.Bytes()

	// Only use compression if it actually reduces size
	if len(compressed) < len(data) {
		compressionRatio := float64(len(compressed)) / float64(len(data)) * 100
		fmt.Printf("   Compression: %d → %d bytes (%.1f%%)\n",
			len(data), len(compressed), compressionRatio)
		return compressed, nil
	}

	fmt.Printf("   Compression: Not beneficial for this data\n")
	return data, nil
}

// AnalyzeImageSecurity provides security metrics
func AnalyzeImageSecurity(img *image.RGBA) {
	fmt.Printf("\n🔒 Security Analysis:\n")

	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	// Calculate LSB entropy
	lsbBits := make([]byte, 0, width*height*3/8)
	bitBuffer := byte(0)
	bitCount := 0

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			// Collect LSBs
			bits := []bool{
				(uint8(r>>8) & 1) == 1,
				(uint8(g>>8) & 1) == 1,
				(uint8(b>>8) & 1) == 1,
			}

			for _, bit := range bits {
				if bit {
					bitBuffer |= (1 << (7 - bitCount))
				}
				bitCount++

				if bitCount == 8 {
					lsbBits = append(lsbBits, bitBuffer)
					bitBuffer = 0
					bitCount = 0
				}
			}
		}
	}

	// Calculate entropy
	frequency := make(map[byte]int)
	for _, b := range lsbBits {
		frequency[b]++
	}

	entropy := 0.0
	total := float64(len(lsbBits))
	for _, count := range frequency {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	fmt.Printf("   LSB Entropy: %.4f bits (max: 8.0)\n", entropy)
	fmt.Printf("   Randomness: %.1f%%\n", entropy/8.0*100)

	// Check for patterns
	zerosCount := 0
	onesCount := 0
	for y := 0; y < min(10, height); y++ {
		for x := 0; x < min(10, width); x++ {
			r, _, _, _ := img.At(x, y).RGBA()
			if (uint8(r>>8) & 1) == 0 {
				zerosCount++
			} else {
				onesCount++
			}
		}
	}

	distribution := float64(zerosCount) / float64(zerosCount+onesCount) * 100
	fmt.Printf("   Sample LSB Distribution: %.1f%% zeros, %.1f%% ones\n",
		distribution, 100-distribution)

	if entropy > 7.9 {
		fmt.Printf("   ✅ High entropy - statistically indistinguishable from random\n")
	} else if entropy > 7.5 {
		fmt.Printf("   ⚠️  Good entropy - difficult to detect\n")
	} else {
		fmt.Printf("   ❌ Low entropy - may be detectable\n")
	}
}
