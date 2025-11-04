//go:build performance_tool

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// TestDataGenerator creates realistic test data for performance testing
type TestDataGenerator struct {
	outputDir string
	patterns  *TestPatterns
}

// TestPatterns contains realistic patterns found in malware and legitimate files
type TestPatterns struct {
	PEHeaders     [][]byte
	ELFHeaders    [][]byte
	MachoHeaders  [][]byte
	ScriptHeaders [][]byte
	Encodings     [][]byte
	Network       [][]byte
	Suspicious    [][]byte
	Legitimate    [][]byte
}

// FileType represents different file types for testing
type FileType int

const (
	PEFile FileType = iota
	ELFFile
	MachoFile
	PDFFile
	JPEGFile
	PNGFile
	ScriptFile
	OfficeFile
	EncryptedFile
	PackedFile
)

// DataGenerationConfig defines how to generate test data
type DataGenerationConfig struct {
	FileType   FileType
	Size       int64
	Entropy    float64  // 0.0 = ordered, 1.0 = random
	Includes   []string // What patterns to include
	Corruption float64  // Data corruption level (0.0-1.0)
	Metadata   map[string]string
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator(outputDir string) *TestDataGenerator {
	return &TestDataGenerator{
		outputDir: outputDir,
		patterns:  initTestPatterns(),
	}
}

func initTestPatterns() *TestPatterns {
	return &TestPatterns{
		PEHeaders: [][]byte{
			[]byte("MZ"),               // DOS header
			[]byte("\x50\x45\x00\x00"), // PE header
			[]byte(".text"),            // Section names
			[]byte(".data"),
			[]byte(".rdata"),
		},
		ELFHeaders: [][]byte{
			[]byte("\x7FELF"),          // ELF magic
			[]byte("\x02\x00\x01\x00"), // 64-bit LSB
			[]byte("\x01\x00\x03\x00"), // 32-bit LSB
			[]byte(".text"),            // Section names
			[]byte(".data"),
		},
		MachoHeaders: [][]byte{
			[]byte("\xFE\xED\xFA\xCE"), // Mach-O 32-bit
			[]byte("\xFE\xED\xFA\xCF"), // Mach-O 64-bit
			[]byte("\xCF\xFA\xED\xFE"), // Mach-O little endian
			[]byte("__TEXT"),
			[]byte("__data"),
		},
		ScriptHeaders: [][]byte{
			[]byte("#!/bin/bash"),
			[]byte("#!/usr/bin/env python"),
			[]byte("<?php"),
			[]byte("<script"),
			[]byte("#!/usr/bin/perl"),
		},
		Encodings: [][]byte{
			[]byte("-----BEGIN CERTIFICATE-----"),
			[]byte("-----END CERTIFICATE-----"),
			[]byte("import base64"),
			[]byte("b'"),
			[]byte("0x"),
		},
		Network: [][]byte{
			[]byte("http://"),
			[]byte("https://"),
			[]byte("ftp://"),
			[]byte("User-Agent:"),
			[]byte("Host:"),
			[]byte("Cookie:"),
			[]byte("Authorization:"),
		},
		Suspicious: [][]byte{
			[]byte("CreateRemoteThread"),
			[]byte("WriteProcessMemory"),
			[]byte("VirtualAlloc"),
			[]byte("SetWindowsHookEx"),
			[]byte("keylogger"),
			[]byte("backdoor"),
			[]byte("trojan"),
			[]byte("malware"),
			[]byte("rootkit"),
			[]byte("cryptocurrency"),
			[]byte("bitcoin"),
			[]byte("ransomware"),
		},
		Legitimate: [][]byte{
			[]byte("Microsoft"),
			[]byte("Google"),
			[]byte("Apple"),
			[]byte("Mozilla"),
			[]byte("OpenSSL"),
			[]byte("GNU"),
			[]byte("Apache"),
			[]byte("nginx"),
		},
	}
}

// GenerateTestDataset creates a comprehensive test dataset
func (tdg *TestDataGenerator) GenerateTestDataset() error {
	if err := os.MkdirAll(tdg.outputDir, 0755); err != nil {
		return err
	}

	fmt.Printf("Generating test dataset in %s...\n", tdg.outputDir)

	// Generate files of different sizes
	sizes := []struct {
		category string
		sizes    []int64
		count    int
	}{
		{"small", []int64{1024, 4096, 8192}, 20},          // 1KB-8KB
		{"medium", []int64{65536, 262144, 524288}, 15},    // 64KB-512KB
		{"large", []int64{1048576, 2097152, 5242880}, 10}, // 1MB-5MB
	}

	// Generate different file types
	fileTypes := []FileType{
		PEFile, ELFFile, MachoFile, PDFFile, JPEGFile,
		PNGFile, ScriptFile, OfficeFile, EncryptedFile, PackedFile,
	}

	for _, sizeCategory := range sizes {
		for _, size := range sizeCategory.sizes {
			for i := 0; i < sizeCategory.count; i++ {
				ft := fileTypes[i%len(fileTypes)]
				filename := fmt.Sprintf("%s_%s_%d_%d.dat",
					sizeCategory.category, ft.String(), size, i)

				entropy := 0.3 + (float64(i%5) * 0.15) // Vary entropy
				config := DataGenerationConfig{
					FileType: ft,
					Size:     size,
					Entropy:  entropy,
					Includes: []string{"suspicious", "legitimate"},
					Metadata: map[string]string{
						"size":     fmt.Sprintf("%d", size),
						"type":     ft.String(),
						"entropy":  fmt.Sprintf("%.2f", entropy),
						"category": sizeCategory.category,
					},
				}

				if err := tdg.generateFile(filename, config); err != nil {
					return err
				}
			}
		}
	}

	// Generate specialized datasets
	tdg.generateMaliciousDataset()
	tdg.generateLegitimateDataset()
	tdg.generatePackeredDataset()
	tdg.generateNetworkDataset()

	fmt.Printf("Test dataset generation completed\n")
	return nil
}

func (tdg *TestDataGenerator) generateFile(filename string, config DataGenerationConfig) error {
	filepath := filepath.Join(tdg.outputDir, filename)
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Generate file content based on type
	var content []byte
	switch config.FileType {
	case PEFile:
		content = tdg.generatePEFile(config)
	case ELFFile:
		content = tdg.generateELFFile(config)
	case MachoFile:
		content = tdg.generateMachOFile(config)
	case PDFFile:
		content = tdg.generatePDFFile(config)
	case JPEGFile:
		content = tdg.generateJPEGFile(config)
	case PNGFile:
		content = tdg.generatePNGFile(config)
	case ScriptFile:
		content = tdg.generateScriptFile(config)
	case OfficeFile:
		content = tdg.generateOfficeFile(config)
	case EncryptedFile:
		content = tdg.generateEncryptedFile(config)
	case PackedFile:
		content = tdg.generatePackedFile(config)
	default:
		content = tdg.generateGenericFile(config)
	}

	// Apply entropy adjustment
	content = tdg.applyEntropy(content, config.Entropy)

	// Apply corruption if specified
	if config.Corruption > 0 {
		content = tdg.applyCorruption(content, config.Corruption)
	}

	// Write to file
	if _, err := file.Write(content); err != nil {
		return err
	}

	return nil
}

func (tdg *TestDataGenerator) generatePEFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// DOS header
	buf.Write(tdg.patterns.PEHeaders[0]) // "MZ"
	buf.Write(make([]byte, 58))          // DOS stub

	// PE header pointer at offset 0x3C
	_ = buf.Len()
	buf.Write([]byte{0x3C, 0x00, 0x00, 0x00})

	// Align to 0x200
	for buf.Len() < 512 {
		buf.WriteByte(0)
	}

	// PE header
	buf.Write(tdg.patterns.PEHeaders[1]) // PE signature
	buf.Write([]byte{0x4C, 0x01})        // i386
	buf.Write([]byte{0x03, 0x00})        // Number of sections

	// Section headers
	sections := []string{".text", ".data", ".rdata"}
	for _, section := range sections {
		buf.WriteString(section)
		buf.Write(make([]byte, 16-len(section))) // Pad to 16 bytes
	}

	// Include suspicious patterns
	for _, include := range config.Includes {
		if include == "suspicious" {
			buf.Write(tdg.getRandomPattern(tdg.patterns.Suspicious))
		}
	}

	// Fill remaining space
	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateELFFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// ELF header
	buf.Write(tdg.patterns.ELFHeaders[0]) // ELF magic
	buf.Write(tdg.patterns.ELFHeaders[1]) // 64-bit LSB
	buf.Write(make([]byte, 8))            // Rest of header

	// Section headers
	sections := []string{".text", ".data", ".bss"}
	for _, section := range sections {
		buf.WriteString(section)
		buf.WriteByte(0)
	}

	// Include network patterns
	for _, include := range config.Includes {
		if include == "network" {
			buf.Write(tdg.getRandomPattern(tdg.patterns.Network))
		}
	}

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateMachOFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// Mach-O header
	buf.Write(tdg.patterns.MachoHeaders[2])   // Mach-O little endian
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // CPU type

	// Load commands
	buf.Write([]byte{0x19, 0x00, 0x00, 0x00}) // LC_SEGMENT_64
	buf.WriteString("__TEXT")
	buf.Write(make([]byte, 16-len("__TEXT")))

	// Section content
	sections := []string{"__text", "__data", "__const"}
	for _, section := range sections {
		buf.WriteString(section)
		buf.Write(make([]byte, 16-len(section)))
	}

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generatePDFFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// PDF header
	buf.WriteString("%PDF-1.7\n")
	buf.WriteString("%\xC3\xA4\xC3\xBC\xC3\xB6\n") // Binary comment

	// PDF objects
	for i := 1; i <= 5; i++ {
		buf.WriteString(fmt.Sprintf("%d 0 obj\n<< /Type /Catalog /Pages %d 0 R >>\nendobj\n", i, i+1))
	}

	// Include script content if suspicious
	for _, include := range config.Includes {
		if include == "suspicious" {
			buf.WriteString("<< /Type /Action /S /JavaScript /JS (")
			buf.Write(tdg.getRandomPattern(tdg.patterns.Suspicious))
			buf.WriteString(") >>\n")
		}
	}

	// Cross-reference table
	buf.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for i := 1; i <= 5; i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", i*100))
	}

	// Trailer
	buf.WriteString("trailer\n<< /Size 6 /Root 1 0 R >>\n")
	buf.WriteString("startxref\n")
	buf.WriteString(fmt.Sprintf("%d\n", buf.Len()))
	buf.WriteString("%%EOF\n")

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateJPEGFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// JPEG header
	buf.Write([]byte{0xFF, 0xD8, 0xFF, 0xE0}) // SOI + APP0 marker
	buf.Write([]byte{0x00, 0x10})             // Length
	buf.WriteString("JFIF")                   // Identifier
	buf.Write([]byte{0x00, 0x01, 0x01, 0x00}) // Version info

	// Add metadata with potential suspicious content
	for _, include := range config.Includes {
		if include == "suspicious" {
			// Exif comment with suspicious content
			buf.Write([]byte{0xFF, 0xFE}) // COM marker
			comment := tdg.getRandomPattern(tdg.patterns.Suspicious)
			buf.Write([]byte{byte(len(comment) + 2), 0x00}) // Length
			buf.Write(comment)
		}
	}

	// JPEG image data
	for buf.Len() < int(config.Size)-100 {
		buf.Write([]byte{0xFF, 0xD8}) // Start of scan
		buf.Write(make([]byte, 1000)) // Image data
	}

	// End of image
	buf.Write([]byte{0xFF, 0xD9})

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generatePNGFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// PNG signature
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	// IHDR chunk
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], uint32(min(int(config.Size), 1024))) // Width
	binary.BigEndian.PutUint32(ihdr[4:8], uint32(min(int(config.Size), 768)))  // Height
	ihdr[8] = 8                                                                // Bit depth
	ihdr[9] = 6                                                                // Color type (RGBA)
	ihdr[10] = 0                                                               // Compression
	ihdr[11] = 0                                                               // Filter
	ihdr[12] = 0                                                               // Interlace

	tdg.writePNGChunk(&buf, "IHDR", ihdr)

	// Include text chunks with suspicious content
	for _, include := range config.Includes {
		if include == "suspicious" {
			textData := tdg.getRandomPattern(tdg.patterns.Suspicious)
			tdg.writePNGChunk(&buf, "tEXt", textData)
		}
	}

	// IDAT chunk (image data)
	imageData := make([]byte, min(int(config.Size)-100, 10000))
	rand.Read(imageData)
	tdg.writePNGChunk(&buf, "IDAT", imageData)

	// IEND chunk
	tdg.writePNGChunk(&buf, "IEND", []byte{})

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateScriptFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// Script header
	header := tdg.getRandomPattern(tdg.patterns.ScriptHeaders)
	buf.Write(header)
	buf.WriteByte('\n')

	// Include various script patterns
	scriptContent := []string{
		"import os, sys, subprocess",
		"from base64 import b64decode",
		"import urllib.request",
		"import json, hashlib",
	}

	for _, line := range scriptContent {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	// Add suspicious function calls
	for _, include := range config.Includes {
		if include == "suspicious" {
			buf.WriteString("exec(")
			buf.Write(tdg.getRandomPattern(tdg.patterns.Encodings))
			buf.WriteString(")\n")
		}
	}

	// Add network connections
	for _, include := range config.Includes {
		if include == "network" {
			buf.WriteString("urllib.request.urlopen(")
			buf.Write(tdg.getRandomPattern(tdg.patterns.Network))
			buf.WriteString(")\n")
		}
	}

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateOfficeFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// ZIP-based Office file structure
	buf.WriteString("PK\x03\x04") // Local file header

	// Include VBA macros if suspicious
	for _, include := range config.Includes {
		if include == "suspicious" {
			// VBA macro content
			vba := fmt.Sprintf("Sub Auto_Open()\n")
			vba += "Shell(" + string(tdg.getRandomPattern(tdg.patterns.Suspicious)) + ")\n"
			vba += "End Sub\n"
			buf.Write([]byte(vba))
		}
	}

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateEncryptedFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// Generate random encrypted-looking data
	data := make([]byte, config.Size)
	rand.Read(data)

	// Add encryption headers
	buf.Write([]byte("-----BEGIN ENCRYPTED DATA-----\n"))
	buf.Write(data[:min(len(data), 1000)])
	buf.WriteString("\n-----END ENCRYPTED DATA-----\n")

	// Fill with more encrypted patterns
	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generatePackedFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// Packed file signature
	buf.Write([]byte("UPX"))    // UPX packer signature
	buf.Write(make([]byte, 20)) // Packer info

	// Add unpacking stub (NOP sled followed by actual code)
	nopSled := make([]byte, 100)
	for i := range nopSled {
		nopSled[i] = 0x90 // NOP
	}
	buf.Write(nopSled)

	// Include packed content
	for _, include := range config.Includes {
		if include == "suspicious" {
			buf.Write(tdg.getRandomPattern(tdg.patterns.Suspicious))
		}
	}

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) generateGenericFile(config DataGenerationConfig) []byte {
	var buf bytes.Buffer

	// Generic content with mixed patterns
	for _, include := range config.Includes {
		switch include {
		case "suspicious":
			buf.Write(tdg.getRandomPattern(tdg.patterns.Suspicious))
		case "legitimate":
			buf.Write(tdg.getRandomPattern(tdg.patterns.Legitimate))
		case "network":
			buf.Write(tdg.getRandomPattern(tdg.patterns.Network))
		}
	}

	tdg.fillContent(&buf, int(config.Size)-buf.Len(), config)

	return buf.Bytes()
}

func (tdg *TestDataGenerator) fillContent(buf *bytes.Buffer, remaining int, config DataGenerationConfig) {
	if remaining <= 0 {
		return
	}

	// Fill with entropy-appropriate content
	data := make([]byte, remaining)

	if config.Entropy < 0.3 {
		// Low entropy - repeating patterns
		pattern := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
		for i := 0; i < remaining; i++ {
			data[i] = pattern[i%len(pattern)]
		}
	} else if config.Entropy < 0.7 {
		// Medium entropy - mixed patterns
		for i := 0; i < remaining; i++ {
			if i%100 == 0 {
				// Insert a pattern every 100 bytes
				data[i] = byte(i % 256)
			} else {
				data[i] = byte((i*31 + 17) % 256)
			}
		}
	} else {
		// High entropy - random data
		rand.Read(data)
	}

	buf.Write(data)
}

func (tdg *TestDataGenerator) applyEntropy(data []byte, targetEntropy float64) []byte {
	if targetEntropy == 1.0 {
		return data
	}

	// Calculate current entropy
	currentEntropy := tdg.calculateEntropy(data)
	if math.Abs(currentEntropy-targetEntropy) < 0.1 {
		return data
	}

	// Adjust by introducing patterns or randomness
	result := make([]byte, len(data))
	copy(result, data)

	if targetEntropy < currentEntropy {
		// Reduce entropy by adding patterns
		patternLength := int((1.0 - targetEntropy) * 100)
		pattern := make([]byte, patternLength)
		for i := 0; i < patternLength; i++ {
			pattern[i] = byte('A' + i%26)
		}

		for i := 0; i < len(result); i += patternLength {
			if i+patternLength <= len(result) {
				copy(result[i:], pattern)
			}
		}
	} else {
		// Increase entropy by adding randomness
		for i := range result {
			if i%10 == 0 { // Change every 10th byte
				result[i] ^= byte(i % 256)
			}
		}
	}

	return result
}

func (tdg *TestDataGenerator) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy / 8.0 // Normalize to 0-1 range
}

func (tdg *TestDataGenerator) applyCorruption(data []byte, level float64) []byte {
	if level == 0 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	corruptionCount := int(float64(len(data)) * level)
	for i := 0; i < corruptionCount; i++ {
		pos := int(float64(len(data)) * (float64(i) / float64(corruptionCount)))
		if pos < len(result) {
			result[pos] ^= byte(i % 256)
		}
	}

	return result
}

func (tdg *TestDataGenerator) getRandomPattern(patterns [][]byte) []byte {
	if len(patterns) == 0 {
		return []byte{}
	}
	return patterns[len(patterns)%len(patterns)]
}

func (tdg *TestDataGenerator) writePNGChunk(buf *bytes.Buffer, chunkType string, data []byte) {
	length := uint32(len(data))
	binary.Write(buf, binary.BigEndian, length)
	buf.WriteString(chunkType)
	buf.Write(data)

	// Calculate CRC
	crc := tdg.calculateCRC(append([]byte(chunkType), data...))
	binary.Write(buf, binary.BigEndian, crc)
}

func (tdg *TestDataGenerator) calculateCRC(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = crc ^ uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func (tdg *TestDataGenerator) generateMaliciousDataset() error {
	dir := filepath.Join(tdg.outputDir, "malicious")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	fmt.Printf("Generating malicious dataset...\n")

	maliciousConfigs := []DataGenerationConfig{
		{
			FileType: PEFile,
			Size:     1024 * 1024,
			Entropy:  0.8,
			Includes: []string{"suspicious", "network"},
		},
		{
			FileType: ScriptFile,
			Size:     100 * 1024,
			Entropy:  0.6,
			Includes: []string{"suspicious", "encodings"},
		},
		{
			FileType: PackedFile,
			Size:     2 * 1024 * 1024,
			Entropy:  0.9,
			Includes: []string{"suspicious"},
		},
	}

	for i, config := range maliciousConfigs {
		filename := filepath.Join(dir, fmt.Sprintf("malware_%d.dat", i))
		if err := tdg.generateFile(filename, config); err != nil {
			return err
		}
	}

	return nil
}

func (tdg *TestDataGenerator) generateLegitimateDataset() error {
	dir := filepath.Join(tdg.outputDir, "legitimate")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	fmt.Printf("Generating legitimate dataset...\n")

	legitimateConfigs := []DataGenerationConfig{
		{
			FileType: JPEGFile,
			Size:     500 * 1024,
			Entropy:  0.3,
			Includes: []string{"legitimate"},
		},
		{
			FileType: PDFFile,
			Size:     200 * 1024,
			Entropy:  0.4,
			Includes: []string{"legitimate"},
		},
		{
			FileType: PNGFile,
			Size:     100 * 1024,
			Entropy:  0.2,
			Includes: []string{"legitimate"},
		},
	}

	for i, config := range legitimateConfigs {
		filename := filepath.Join(dir, fmt.Sprintf("legitimate_%d.dat", i))
		if err := tdg.generateFile(filename, config); err != nil {
			return err
		}
	}

	return nil
}

func (tdg *TestDataGenerator) generatePackeredDataset() error {
	dir := filepath.Join(tdg.outputDir, "packed")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	fmt.Printf("Generate packed dataset...\n")

	packedConfigs := []DataGenerationConfig{
		{
			FileType: PackedFile,
			Size:     3 * 1024 * 1024,
			Entropy:  0.95,
			Includes: []string{"suspicious"},
		},
		{
			FileType: EncryptedFile,
			Size:     1024 * 1024,
			Entropy:  0.98,
			Includes: []string{"suspicious", "encodings"},
		},
	}

	for i, config := range packedConfigs {
		filename := filepath.Join(dir, fmt.Sprintf("packed_%d.dat", i))
		if err := tdg.generateFile(filename, config); err != nil {
			return err
		}
	}

	return nil
}

func (tdg *TestDataGenerator) generateNetworkDataset() error {
	dir := filepath.Join(tdg.outputDir, "network")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	fmt.Printf("Generating network dataset...\n")

	networkConfigs := []DataGenerationConfig{
		{
			FileType: ScriptFile,
			Size:     50 * 1024,
			Entropy:  0.5,
			Includes: []string{"network", "suspicious"},
		},
		{
			FileType: PDFFile,
			Size:     100 * 1024,
			Entropy:  0.6,
			Includes: []string{"network"},
		},
	}

	for i, config := range networkConfigs {
		filename := filepath.Join(dir, fmt.Sprintf("network_%d.dat", i))
		if err := tdg.generateFile(filename, config); err != nil {
			return err
		}
	}

	return nil
}

// String method for FileType
func (ft FileType) String() string {
	switch ft {
	case PEFile:
		return "pe"
	case ELFFile:
		return "elf"
	case MachoFile:
		return "macho"
	case PDFFile:
		return "pdf"
	case JPEGFile:
		return "jpeg"
	case PNGFile:
		return "png"
	case ScriptFile:
		return "script"
	case OfficeFile:
		return "office"
	case EncryptedFile:
		return "encrypted"
	case PackedFile:
		return "packed"
	default:
		return "unknown"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
