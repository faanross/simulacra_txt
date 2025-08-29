package main

import (
	"flag"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/decoder"
	"github.com/faanross/simulacra_txt/internal/scrypto"
	"image"
	_ "image/png"
	"log"
	"os"
	"strings"
)

func main() {
	// Command line arguments
	inputFile := flag.String("input", "", "Path to stego image")
	outputFile := flag.String("output", "", "Save extracted message to file")
	password := flag.String("password", "", "Password (prompt if not provided)")
	analyze := flag.Bool("analyze", false, "Perform security analysis only")
	tryList := flag.String("trylist", "", "Comma-separated passwords to try")
	verbose := flag.Bool("verbose", false, "Show full extracted message")

	flag.Parse()

	// Validate input
	if *inputFile == "" {
		log.Fatal("❌ Please provide input image with -input flag")
	}

	fmt.Println("\n🔓 Secure Steganography Decoder")
	fmt.Println("=" + strings.Repeat("=", 40))

	// Open image
	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("❌ Error opening file: %v", err)
	}
	defer file.Close()

	// Decode image
	img, format, err := image.Decode(file)
	if err != nil {
		log.Fatalf("❌ Error decoding image: %v", err)
	}

	bounds := img.Bounds()
	fmt.Printf("\n📷 Image loaded:\n")
	fmt.Printf("   File: %s\n", *inputFile)
	fmt.Printf("   Format: %s\n", format)
	fmt.Printf("   Dimensions: %dx%d\n",
		bounds.Max.X-bounds.Min.X,
		bounds.Max.Y-bounds.Min.Y)

	// Security analysis mode
	if *analyze {
		decoder.AnalyzeSecurity(img)
		return
	}

	// Try multiple passwords mode
	if *tryList != "" {
		passwords := strings.Split(*tryList, ",")
		scrypto.TryMultiplePasswords(img, passwords)
		return
	}

	// Get password
	var pass []byte
	if *password != "" {
		pass = []byte(*password)
	} else {
		pass, err = scrypto.GetSecurePassword("\n🔑 Enter password: ")
		if err != nil {
			log.Fatalf("❌ Password error: %v", err)
		}
	}

	// Create decoder
	stegDecoder := decoder.NewSecureStegoDecoder(img, pass)

	// Extract bit stream
	stegDecoder.ExtractBitStream()

	// Extract secure payload
	err = stegDecoder.ExtractSecurePayload()
	if err != nil {
		log.Fatalf("❌ Extraction failed: %v", err)
	}

	// Decrypt payload
	result, err := stegDecoder.DecryptPayload()
	if err != nil {
		log.Fatalf("❌ Decryption failed: %v", err)
	}

	// Display results
	fmt.Printf("\n✅ MESSAGE SUCCESSFULLY DECRYPTED\n")
	fmt.Println("=" + strings.Repeat("=", 40))

	fmt.Printf("\n📊 Extraction Statistics:\n")
	fmt.Printf("   Encrypted size: %d bytes\n", result.EncryptedSize)
	fmt.Printf("   Decrypted size: %d bytes\n", result.DecryptedSize)
	fmt.Printf("   Compression: %v\n", result.WasCompressed)
	fmt.Printf("   Authentication: %v\n", result.Authenticated)

	// Display message
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📝 DECRYPTED MESSAGE:")
	fmt.Println(strings.Repeat("=", 60))

	message := string(result.Message)
	if *verbose || len(message) <= 500 {
		fmt.Println(message)
	} else {
		// Show preview for long messages
		fmt.Printf("%s\n... [%d more characters] ...\n%s\n",
			message[:200],
			len(message)-400,
			message[len(message)-200:])
		fmt.Printf("\n(Use -verbose flag to see full message)\n")
	}

	fmt.Println(strings.Repeat("=", 60))

	// Save to file if requested
	if *outputFile != "" {
		err = os.WriteFile(*outputFile, result.Message, 0644)
		if err != nil {
			log.Fatalf("❌ Error saving output: %v", err)
		}
		fmt.Printf("\n💾 Message saved to: %s\n", *outputFile)
	}

	fmt.Println("\n✅ Secure decoding complete!")
}
