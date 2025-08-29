package decoder

import (
	"fmt"
	"image"
)

// AnalyzeSecurity performs security analysis on the image
func AnalyzeSecurity(img image.Image) {
	fmt.Printf("\n🔒 Security Analysis:\n")

	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	// Analyze LSB distribution
	zeros := 0
	ones := 0

	sampleSize := min(width*height, 10000) // Sample first 10k pixels
	pixelCount := 0

	for y := 0; y < height && pixelCount < sampleSize; y++ {
		for x := 0; x < width && pixelCount < sampleSize; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			// Count LSBs
			if (uint8(r>>8) & 1) == 0 {
				zeros++
			} else {
				ones++
			}
			if (uint8(g>>8) & 1) == 0 {
				zeros++
			} else {
				ones++
			}
			if (uint8(b>>8) & 1) == 0 {
				zeros++
			} else {
				ones++
			}

			pixelCount++
		}
	}

	total := float64(zeros + ones)
	zeroRatio := float64(zeros) / total * 100

	fmt.Printf("   LSB Distribution (sample):\n")
	fmt.Printf("     0s: %.1f%%\n", zeroRatio)
	fmt.Printf("     1s: %.1f%%\n", 100-zeroRatio)

	// Check randomness
	if zeroRatio > 45 && zeroRatio < 55 {
		fmt.Printf("   🔐 Appears to contain encrypted/random data\n")
	} else {
		fmt.Printf("   📸 Appears to be a natural image\n")
	}

	// Color distribution analysis
	fmt.Printf("\n   Color Channel Analysis:\n")
	var rSum, gSum, bSum int64
	for y := 0; y < min(100, height); y++ {
		for x := 0; x < min(100, width); x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			rSum += int64(r >> 8)
			gSum += int64(g >> 8)
			bSum += int64(b >> 8)
		}
	}

	samples := min(100, width) * min(100, height)
	fmt.Printf("     Red avg: %d\n", rSum/int64(samples))
	fmt.Printf("     Green avg: %d\n", gSum/int64(samples))
	fmt.Printf("     Blue avg: %d\n", bSum/int64(samples))

	// Check if all channels are similar (typical of encrypted stego)
	avgDiff := abs(rSum-gSum) + abs(gSum-bSum) + abs(bSum-rSum)
	if avgDiff < int64(samples)*30 {
		fmt.Printf("   ⚠️  Uniform color distribution detected\n")
	}
}

// min returns minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// abs returns absolute value
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
