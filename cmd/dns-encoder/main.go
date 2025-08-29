package main

import (
	"flag"
	"fmt"
	"github.com/faanross/simulacra_txt/internal/chunker"
	"os"
)

func main() {
	input := flag.String("input", "", "Input image file")
	domain := flag.String("domain", "covert.example.com", "DNS domain")
	output := flag.String("output", "zone.txt", "Output zone file")
	flag.Parse()

	if *input == "" {
		fmt.Println("Usage: dns-encoder-demo -input <image.png>")
		return
	}

	// Read image
	data, err := os.ReadFile(*input)
	if err != nil {
		panic(err)
	}

	fmt.Printf("📷 Image: %s (%d bytes)\n", *input, len(data))

	// Chunk it
	chk := chunker.NewChunker(chunker.ChunkerConfig{
		Encoding: chunker.ENCODE_BASE32,
	})
	msg, err := chk.ChunkMessage(data)
	if err != nil {
		panic(err)
	}

	fmt.Printf("🧩 Chunks: %d\n", len(msg.Chunks))

	// Encode for DNS
	encoder := chunker.NewDNSEncoder(*domain)
	manifest, records, err := encoder.EncodeToDNS(msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("🌐 DNS Records: %d\n", len(records))
	fmt.Printf("📋 Message ID: %s\n", manifest.MessageID)

	// Show example records
	fmt.Println("\nExample DNS records:")
	for i := 0; i < 3 && i < len(records); i++ {
		r := records[i]
		value := r.Value
		if len(value) > 50 {
			value = value[:50] + "..."
		}
		fmt.Printf("  %s TXT \"%s\"\n", r.Name, value)
	}

	// Generate zone file
	zoneFile := encoder.GenerateZoneFile(records)
	err = os.WriteFile(*output, []byte(zoneFile), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n✅ Zone file saved to: %s\n", *output)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Upload zone file to DNS server")
	fmt.Println("2. Query DNS server from receiver")
	fmt.Println("3. Reassemble and decode")
}
