package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/encoder"
	"github.com/faanross/simulacra_txt/internal/scrypto"
	"github.com/faanross/simulacra_txt/internal/spec"
	"image/png"
	"log"
	"os"
	"strings"
)

func main() {
	// Command line arguments
	inputFile := flag.String("input", "", "Path to input text file")
	outputFile := flag.String("output", "secure_stego.png", "Output PNG file")
	width := flag.Int("width", spec.DEFAULT_WIDTH, "Image width")
	compress := flag.Bool("compress", true, "Enable compression")
	password := flag.String("password", "", "Password (prompt if not provided)")
	analyze := flag.Bool("analyze", false, "Show security analysis")

	flag.Parse()

	// Validate input
	if *inputFile == "" {
		log.Fatal("❌ Please provide input file with -input flag")
	}

	fmt.Println("\n🔐 Secure Steganography Encoder")
	fmt.Println("=" + strings.Repeat("=", 40))

	// Read input file
	message, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("❌ Error reading file: %v", err)
	}

	fmt.Printf("\n📄 Input file: %s (%d bytes)\n", *inputFile, len(message))

	// Get password
	var pass []byte
	if *password != "" {
		pass = []byte(*password)
		if len(pass) < 8 {
			log.Fatal("❌ Password must be at least 8 characters")
		}
	} else {
		pass, err = scrypto.GetSecurePassword("\n🔑 Enter password (min 8 chars): ")
		if err != nil {
			log.Fatalf("❌ Password error: %v", err)
		}

		// Confirm password
		confirm, err := scrypto.GetSecurePassword("🔑 Confirm password: ")
		if err != nil {
			log.Fatalf("❌ Password error: %v", err)
		}

		if !bytes.Equal(pass, confirm) {
			log.Fatal("❌ Passwords do not match")
		}
	}

	// Create secure encoder
	stegoEncoder := encoder.NewSecureStegoEncoder(message, pass, *width, *compress)

	// Generate secure stego image
	img, err := stegoEncoder.CreateStegoImage()
	if err != nil {
		log.Fatalf("❌ Encoding failed: %v", err)
	}

	// Security analysis
	if *analyze {
		encoder.AnalyzeImageSecurity(img)
	}

	// Save image
	file, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("❌ Cannot create output file: %v", err)
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		log.Fatalf("❌ PNG encoding failed: %v", err)
	}

	fmt.Printf("\n✅ Secure steganography complete!\n")
	fmt.Printf("   Output: %s\n", *outputFile)
	fmt.Printf("   Security: AES-256-GCM + PBKDF2-%d\n", spec.PBKDF2_ITERS)
	fmt.Printf("\n🔓 To decode: Use the secure decoder with the same password\n")
}
