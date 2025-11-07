package main

import (
	"fmt"
	"os"
)

// writeFileWithErrCheck writes data to a file and exits on error
func writeFileWithErrCheck(filename string, data []byte) {
	if err := writeFileWithErrCheck(filename, data); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file %s: %v\n", filename, err)
		os.Exit(1)
	}
}

func main() {
	dir := "testdata/performance"
	if err := os.MkdirAll(dir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory %s: %v\n", dir, err)
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "large":
			generateLargePerformanceFiles(dir)
			return
		case "samples":
			generateSampleFiles(dir)
			return
		case "all":
			// Generate everything
		default:
			fmt.Println("Usage: go run generate_test_data.go [all|large|samples]")
			fmt.Println("  all     - Generate all test data (default)")
			fmt.Println("  large   - Generate only large performance files")
			fmt.Println("  samples - Generate only malware sample files")
			return
		}
	}

	// Generate all test data
	generateSampleFiles(dir)
	generateLargePerformanceFiles(dir)

	fmt.Println("Test data generated successfully!")
}

// generateSampleFiles generates malware sample files for testing
func generateSampleFiles(dir string) {
	// Generate various types of test files representing real-world scenarios
	generatePEFile(dir + "/pe_malware_sample.bin")
	generateELFFile(dir + "/elf_backdoor_sample.bin")
	generateWebShellFile(dir + "/webshell_sample.php")
	generateRansomwareFile(dir + "/ransomware_sample.exe")
	generateBankerFile(dir + "/banker_sample.dll")
	generateDDOSFile(dir + "/ddos_bot_sample.exe")
	generateMinerFile(dir + "/miner_sample.exe")
	generateAPTSample(dir + "/apt_surveillance_sample.exe")

	// Generate clean files for false positive testing
	generateCleanPE(dir + "/clean_program.exe")
	generateCleanDocument(dir + "/clean_document.pdf")
	generateCleanScript(dir + "/clean_script.js")
}

// generateLargePerformanceFiles generates large files for performance testing
func generateLargePerformanceFiles(dir string) {
	// Generate large files for performance testing
	generateLargeFile(dir+"/large_binary.exe", 10*1024*1024)    // 10MB
	generateLargeFile(dir+"/large_log.txt", 5*1024*1024)        // 5MB
	generateLargeFile(dir+"/large_test_50mb.bin", 50*1024*1024) // 50MB
}

func generatePEFile(filename string) {
	data := make([]byte, 10240)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A})                 // MZ
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})   // PE header offset
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00}) // PE

	// Add suspicious strings
	suspiciousStrings := []string{
		"CreateRemoteThread",
		"WriteProcessMemory",
		"malware",
		"UPX1.0",
		"VirtualAllocEx",
		"SetWindowsHookEx",
	}

	offset := 500
	for _, str := range suspiciousStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 10
		}
	}

	// Fill rest with random-like data
	for i := 1000; i < len(data); i++ {
		data[i] = byte(i % 256)
	}

	writeFileWithErrCheck(filename, data)
}

func generateELFFile(filename string) {
	data := make([]byte, 8192)

	// ELF header
	copy(data[0:4], []byte{0x7F, 0x45, 0x4C, 0x46}) // ELF
	data[4] = 0x01                                  // 32-bit
	data[5] = 0x01                                  // little endian
	data[6] = 0x01                                  // ELF version

	// Add backdoor strings
	backdoorStrings := []string{
		"backdoor",
		"socket",
		"connect",
		"bind",
		"malicious.tk",
		"command.control.com",
		"shell.php",
	}

	offset := 500
	for _, str := range backdoorStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 15
		}
	}

	// Fill rest
	for i := 1000; i < len(data); i++ {
		data[i] = byte(i % 256)
	}

	writeFileWithErrCheck(filename, data)
}

func generateWebShellFile(filename string) {
	content := `<?php
// Webshell sample for performance testing
eval($_POST['cmd']);
system($_GET['exec']);
shell_exec($_REQUEST['command']);
WScript.Shell.Exec($_POST['run']);
base64_decode($_POST['payload']);
passthru($_GET['cmd']);
// Common webshell patterns
backdoor_function();
webshell_interface();
c2_server_comms();
file_manager_tool();
database_connector();
?>`
	writeFileWithErrCheck(filename, []byte(content))
}

func generateRansomwareFile(filename string) {
	data := make([]byte, 15360)

	// PE header for executable
	copy(data[0:2], []byte{0x4D, 0x5A})
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00})

	// Ransomware indicators
	ransomwareStrings := []string{
		"Your files are encrypted",
		"Send 1 Bitcoin to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"contact us at tor://recoverfiles.onion",
		"CryptEncrypt",
		"CryptCreateHash",
		"file.locked",
		"document.encrypted",
		"payment.instructions.txt",
	}

	offset := 1000
	for _, str := range ransomwareStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 20
		}
	}

	writeFileWithErrCheck(filename, data)
}

func generateBankerFile(filename string) {
	data := make([]byte, 12288)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A})
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00})

	// Banking trojan strings
	bankerStrings := []string{
		"paypal.com",
		"chase.com",
		"bankofamerica.com",
		"wellsfargo.com",
		"GetAsyncKeyState",
		"form grabbing",
		"password input",
		"credit card number",
		"ssn social security",
		"InternetExplorer.Application",
		"browser automation",
	}

	offset := 800
	for _, str := range bankerStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 25
		}
	}

	writeFileWithErrCheck(filename, data)
}

func generateDDOSFile(filename string) {
	data := make([]byte, 9216)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A})
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00})

	// DDoS bot strings
	ddosStrings := []string{
		"DDoS attack tool",
		"botnet client",
		"flood attack",
		"POST / HTTP/1.1",
		"SYN flood",
		"UDP flood",
		"ICMP flood",
		"c2.server.com",
		"cmd.botnet.net",
		"dns amplification",
		"ntp amplification",
		"memcached amplification",
	}

	offset := 600
	for _, str := range ddosStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 30
		}
	}

	writeFileWithErrCheck(filename, data)
}

func generateMinerFile(filename string) {
	data := make([]byte, 20480)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A})
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00})

	// Miner strings
	minerStrings := []string{
		"stratum+tcp://",
		"mining.pool.com",
		"SHA-256 algorithm",
		"Scrypt algorithm",
		"Ethash algorithm",
		"RandomX algorithm",
		"bitcoin mining",
		"ethereum mining",
		"monero mining",
		"cryptocurrency",
		"CPU 100% usage",
		"xmrig",
		"cpuminer",
		"ccminer",
	}

	offset := 1200
	for _, str := range minerStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 40
		}
	}

	writeFileWithErrCheck(filename, data)
}

func generateAPTSample(filename string) {
	data := make([]byte, 25600)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A})
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00})

	// APT surveillance strings
	aptStrings := []string{
		"keylogger",
		"screenshot capture",
		"webcam access",
		"microphone recording",
		"data exfiltration",
		"steal information",
		"leak data",
		"autorun registry",
		"startup persistence",
		"runonce registry key",
		"http://c2.server.com/api",
		"https://control.center.net/c2",
		"rootkit technology",
		"hidden process",
		"invisible service",
	}

	offset := 1500
	for _, str := range aptStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 50
		}
	}

	writeFileWithErrCheck(filename, data)
}

func generateCleanPE(filename string) {
	data := make([]byte, 8192)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A})
	copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00})
	copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00})

	// Clean strings
	cleanStrings := []string{
		"Hello World",
		"Normal application",
		"Windows program",
		"legitimate software",
		"user interface",
		"file operations",
		"memory management",
	}

	offset := 1000
	for _, str := range cleanStrings {
		if offset+len(str) < len(data) {
			copy(data[offset:], []byte(str))
			offset += len(str) + 20
		}
	}

	writeFileWithErrCheck(filename, data)
}

func generateCleanDocument(filename string) {
	content := `This is a clean PDF document for testing purposes.
It contains legitimate content without any malicious indicators.
Normal business documents, reports, and communications.
File size and performance testing.
Clean text content for baseline measurements.
No suspicious patterns or indicators present.`
	writeFileWithErrCheck(filename, []byte(content))
}

func generateCleanScript(filename string) {
	content := `// Clean JavaScript file for testing
console.log("Hello World");
function calculateSum(a, b) {
    return a + b;
}
var result = calculateSum(5, 10);
console.log("Result: " + result);
// Normal JavaScript operations
document.getElementById("output").innerHTML = result;`
	writeFileWithErrCheck(filename, []byte(content))
}

func generateLargeFile(filename string, size int) {
	data := make([]byte, size)

	// Create realistic large file content
	patterns := [][]byte{
		[]byte("MZ"),                 // PE header
		{0x7F, 0x45, 0x4C, 0x46},     // ELF header
		[]byte("malware"),            // Suspicious string
		[]byte("virus"),              // Another suspicious string
		[]byte("trojan"),             // More suspicious content
		[]byte("CreateRemoteThread"), // API call
		[]byte("WriteProcessMemory"), // API call
		[]byte("VirtualAllocEx"),     // API call
	}

	// Fill file with patterns mixed with random data
	patternIndex := 0
	for i := 0; i < size; i++ {
		if i%4096 == 0 && patternIndex < len(patterns) {
			pattern := patterns[patternIndex]
			if i+len(pattern) < size {
				copy(data[i:], pattern)
				i += len(pattern) - 1
			}
			patternIndex++
		} else {
			data[i] = byte(i % 256)
		}
	}

	writeFileWithErrCheck(filename, data)
}
