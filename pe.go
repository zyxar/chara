package chara

import (
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"errors"
)

var (
	ErrFileHashNotMatch = errors.New("hash not match")
)

func validateFileHash(file *pe.File, hash []byte) bool {
	return bytes.Compare(calculateFileHash(file), hash) == 0
}

func calculateFileHash(file *pe.File) []byte {
	hash := md5.New()
	hash.Write(PE_MAGIC_BYTES)
	file.FileHeader.TimeDateStamp = 0
	binary.Write(hash, binary.LittleEndian, &file.FileHeader)
	var directory [16]pe.DataDirectory
	switch h := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		// exclude DataDirectory
		binary.Write(hash, binary.LittleEndian, h.Magic)
		binary.Write(hash, binary.LittleEndian, h.MajorLinkerVersion)
		binary.Write(hash, binary.LittleEndian, h.MinorLinkerVersion)
		binary.Write(hash, binary.LittleEndian, h.SizeOfCode)
		binary.Write(hash, binary.LittleEndian, h.SizeOfInitializedData)
		binary.Write(hash, binary.LittleEndian, h.SizeOfUninitializedData)
		binary.Write(hash, binary.LittleEndian, h.AddressOfEntryPoint&0xFFFE0000)
		binary.Write(hash, binary.LittleEndian, h.BaseOfCode)
		binary.Write(hash, binary.LittleEndian, h.BaseOfData)
		binary.Write(hash, binary.LittleEndian, h.ImageBase)
		binary.Write(hash, binary.LittleEndian, h.SectionAlignment)
		binary.Write(hash, binary.LittleEndian, h.FileAlignment)
		binary.Write(hash, binary.LittleEndian, h.MajorOperatingSystemVersion)
		binary.Write(hash, binary.LittleEndian, h.MinorOperatingSystemVersion)
		binary.Write(hash, binary.LittleEndian, uint16(0) /*h.MajorImageVersion*/)
		binary.Write(hash, binary.LittleEndian, uint16(0) /*h.MinorImageVersion*/)
		binary.Write(hash, binary.LittleEndian, h.MajorSubsystemVersion)
		binary.Write(hash, binary.LittleEndian, h.MinorSubsystemVersion)
		binary.Write(hash, binary.LittleEndian, h.Win32VersionValue)
		binary.Write(hash, binary.LittleEndian, h.SizeOfImage&0xFFFFF000)
		binary.Write(hash, binary.LittleEndian, h.SizeOfHeaders)
		binary.Write(hash, binary.LittleEndian, uint32(0) /*h.CheckSum*/)
		binary.Write(hash, binary.LittleEndian, h.Subsystem)
		binary.Write(hash, binary.LittleEndian, h.DllCharacteristics)
		binary.Write(hash, binary.LittleEndian, h.SizeOfStackReserve)
		binary.Write(hash, binary.LittleEndian, h.SizeOfStackCommit)
		binary.Write(hash, binary.LittleEndian, h.SizeOfHeapReserve)
		binary.Write(hash, binary.LittleEndian, h.SizeOfHeapCommit)
		binary.Write(hash, binary.LittleEndian, h.LoaderFlags)
		binary.Write(hash, binary.LittleEndian, h.NumberOfRvaAndSizes)
		directory = h.DataDirectory
	case *pe.OptionalHeader64:
		// exclude DataDirectory
		binary.Write(hash, binary.LittleEndian, h.Magic)
		binary.Write(hash, binary.LittleEndian, h.MajorLinkerVersion)
		binary.Write(hash, binary.LittleEndian, h.MinorLinkerVersion)
		binary.Write(hash, binary.LittleEndian, h.SizeOfCode)
		binary.Write(hash, binary.LittleEndian, h.SizeOfInitializedData)
		binary.Write(hash, binary.LittleEndian, h.SizeOfUninitializedData)
		binary.Write(hash, binary.LittleEndian, h.AddressOfEntryPoint&0xFFFE0000)
		binary.Write(hash, binary.LittleEndian, h.BaseOfCode)
		binary.Write(hash, binary.LittleEndian, h.ImageBase)
		binary.Write(hash, binary.LittleEndian, h.SectionAlignment)
		binary.Write(hash, binary.LittleEndian, h.FileAlignment)
		binary.Write(hash, binary.LittleEndian, h.MajorOperatingSystemVersion)
		binary.Write(hash, binary.LittleEndian, h.MinorOperatingSystemVersion)
		binary.Write(hash, binary.LittleEndian, uint16(0) /*h.MajorImageVersion*/)
		binary.Write(hash, binary.LittleEndian, uint16(0) /*h.MinorImageVersion*/)
		binary.Write(hash, binary.LittleEndian, h.MajorSubsystemVersion)
		binary.Write(hash, binary.LittleEndian, h.MinorSubsystemVersion)
		binary.Write(hash, binary.LittleEndian, h.Win32VersionValue)
		binary.Write(hash, binary.LittleEndian, h.SizeOfImage&0xFFFFF000)
		binary.Write(hash, binary.LittleEndian, h.SizeOfHeaders)
		binary.Write(hash, binary.LittleEndian, uint32(0) /*h.CheckSum*/)
		binary.Write(hash, binary.LittleEndian, h.Subsystem)
		binary.Write(hash, binary.LittleEndian, h.DllCharacteristics)
		binary.Write(hash, binary.LittleEndian, h.SizeOfStackReserve)
		binary.Write(hash, binary.LittleEndian, h.SizeOfStackCommit)
		binary.Write(hash, binary.LittleEndian, h.SizeOfHeapReserve)
		binary.Write(hash, binary.LittleEndian, h.SizeOfHeapCommit)
		binary.Write(hash, binary.LittleEndian, h.LoaderFlags)
		binary.Write(hash, binary.LittleEndian, h.NumberOfRvaAndSizes)
		directory = h.DataDirectory
	}
	// import table
	dir := directory[1]
	dir.VirtualAddress &= 0xFFFFFF00
	dir.Size &= 0xFFFFFF00
	binary.Write(hash, binary.LittleEndian, &dir)
	// resource table
	dir = directory[2]
	binary.Write(hash, binary.LittleEndian, dir.Size&0xFFFFFF00)
	// all section names and characteristics
	for i := range file.Sections {
		binary.Write(hash, binary.LittleEndian, file.Sections[i].Size&0xFFFFF000)
		binary.Write(hash, binary.LittleEndian, file.Sections[i].Characteristics)
	}
	return hash.Sum(nil)
}

func detectExecutableSections(file *pe.File) (p []pe.SectionHeader) {
	for i := range file.Sections {
		if file.Sections[i].Characteristics&IMAGE_SCN_CNT_CODE != 0 {
			p = append(p, file.Sections[i].SectionHeader)
		}
	}
	return
}

func DetectExecutableSections(name string) ([]pe.SectionHeader, error) {
	file, err := pe.Open(name)
	if err != nil {
		return nil, err
	}
	return detectExecutableSections(file), nil
}

func ValidateFileHash(name string, hash []byte) error {
	file, err := pe.Open(name)
	if err != nil {
		return err
	}
	if !validateFileHash(file, hash) {
		return ErrFileHashNotMatch
	}
	return nil
}

func ScanFile(name string) ([]pe.SectionHeader, []byte, error) {
	file, err := pe.Open(name)
	if err != nil {
		return nil, nil, err
	}
	return detectExecutableSections(file), calculateFileHash(file), nil
}
