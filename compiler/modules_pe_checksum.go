package compiler

import (
	"encoding/binary"
	"math"
)

const peChecksumChunkSize = 64 * 1024

// peCalculateChecksum implements libyara's pe.calculate_checksum() with
// explicit full-input semantics. Stored pe.checksum is header metadata and may
// be stale or zero; calculate_checksum sums full contiguous file bytes via
// peFullScanData and returns undefined on bounded reader prefixes, segmented
// blocks, or host-data overrides.
func (i *Interpreter) peCalculateChecksum() ModuleValue {
	if i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	if _, supplied := i.moduleData["pe"]; supplied {
		return ModuleValue{}
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return ModuleValue{}
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	if image.calculatedChecksumSet {
		return image.calculatedChecksum
	}
	data, ok := peFullScanData(image.context)
	if !ok {
		image.calculatedChecksumSet = true
		image.calculatedChecksum = ModuleValue{}
		return ModuleValue{}
	}
	sum, _, complete := peCalculateChecksumBytes(data, image.file.DOSHeader.AddressOfNewEXEHeader, done)
	if !complete {
		return ModuleValue{}
	}
	result := IntegerValue(sum)
	image.calculatedChecksumSet = true
	image.calculatedChecksum = result
	return result
}

// peCalculateChecksumBytes sums 32-bit little-endian words in bounded 64 KiB
// chunks with end-around carry folding, excluding the aligned OptionalHeader
// CheckSum field (matching libyara's 4-byte-aligned pointer comparison),
// appending any trailing partial word and total byte length.
// It returns the checksum, the byte count examined, and false if canceled.
func peCalculateChecksumBytes(data []byte, eLfanew uint32, done <-chan struct{}) (checksum, examined int64, complete bool) {
	checksumOffset := uint64(eLfanew) + 88
	// Intentionally skip only when checksumOffset is 4-byte aligned: libyara
	// iterates uint32_t* words and checks (p != checksum_addr), so unaligned
	// e_lfanew values do not skip the CheckSum field (verified by
	// TestLibyaraPECalculateChecksum/pe32_unaligned_lfanew).
	skipAlignedChecksum := checksumOffset%4 == 0 && checksumOffset+4 <= uint64(len(data))
	alignedLen := len(data) &^ 3

	var sum uint64
	for chunkStart := 0; chunkStart < alignedLen; chunkStart += peChecksumChunkSize {
		if scanCanceled(done) {
			return 0, int64(chunkStart), false
		}
		chunkEnd := min(chunkStart+peChecksumChunkSize, alignedLen)
		var chunkSum uint64
		off := chunkStart
		for ; off+16 <= chunkEnd; off += 16 {
			chunkSum += uint64(binary.LittleEndian.Uint32(data[off:off+4])) +
				uint64(binary.LittleEndian.Uint32(data[off+4:off+8])) +
				uint64(binary.LittleEndian.Uint32(data[off+8:off+12])) +
				uint64(binary.LittleEndian.Uint32(data[off+12:off+16]))
		}
		for ; off < chunkEnd; off += 4 {
			chunkSum += uint64(binary.LittleEndian.Uint32(data[off : off+4]))
		}
		if skipAlignedChecksum && checksumOffset >= uint64(chunkStart) && checksumOffset < uint64(chunkEnd) {
			chunkSum -= uint64(binary.LittleEndian.Uint32(data[checksumOffset : checksumOffset+4]))
		}
		sum += chunkSum
		sum = (sum & 0xffffffff) + (sum >> 32)
		examined = int64(chunkEnd)
	}

	if alignedLen < len(data) {
		if scanCanceled(done) {
			return 0, examined, false
		}
		var tail uint32
		for j := range len(data) - alignedLen {
			tail |= uint32(data[alignedLen+j]) << (8 * j)
		}
		sum += uint64(tail)
		sum = (sum & 0xffffffff) + (sum >> 32)
		examined = int64(len(data))
	}

	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	total := sum + uint64(len(data))
	if total > math.MaxInt64 {
		return math.MaxInt64, examined, true
	}
	return int64(total), examined, true
}
