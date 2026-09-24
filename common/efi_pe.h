// SPDX-License-Identifier:     BSD-2-Clause
/*
 * Copyright (c) 2017-2019 Heinrich Schuchardt
 *
 * Shared PE/COFF/EFI structures, constants, and lookup tables used by
 * both the command line tool (efianalyze.c) and the Qt GUI
 * (qt/pe_parser.cpp).
 *
 * This header contains only data definitions (structs, defines, string
 * tables) and small side effect free lookup helpers so that it can be
 * compiled unmodified from both a C (gcc) build and a C++ (Qt/MOC)
 * build.
 */
#ifndef EFI_PE_H
#define EFI_PE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IMAGE_FILE_MACHINE_I386		0x014c
#define IMAGE_FILE_MACHINE_AMD64	0x8664
#define IMAGE_FILE_MACHINE_IA64		0x0200
#define IMAGE_FILE_MACHINE_ARM		0x01c0 /* not in UEFI 2.10 */
#define IMAGE_FILE_MACHINE_THUMB	0x01c2
#define IMAGE_FILE_MACHINE_ARMNT	0x01c4 /* not in UEFI 2.10 */
#define IMAGE_FILE_MACHINE_EBC		0x0ebc
#define IMAGE_FILE_MACHINE_ARM64	0xaa64
#define IMAGE_FILE_MACHINE_RISCV32	0x5032
#define IMAGE_FILE_MACHINE_RISCV64	0x5064
#define IMAGE_FILE_MACHINE_RISCV128	0x5128
#define IMAGE_FILE_MACHINE_LOONGARCH32	0x6232
#define IMAGE_FILE_MACHINE_LOONGARCH64	0x6264

#define IMAGE_FILE_RELOCS_STRIPPED		0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE		0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED		0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED		0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM		0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE		0x0020
#define IMAGE_FILE_16BIT_MACHINE		0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO		0x0080
#define IMAGE_FILE_32BIT_MACHINE		0x0100
#define IMAGE_FILE_DEBUG_STRIPPED		0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP		0x0800
#define IMAGE_FILE_SYSTEM			0x1000
#define IMAGE_FILE_DLL				0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY		0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI		0x8000

#define IMAGE_SUBSYSTEM_EFI_APPLICATION		10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER	12
#define IMAGE_SUBSYSTEM_EFI_ROM			13

#define OPTIONAL_HEADER_MAGIC_PE32	0x010b
#define OPTIONAL_HEADER_MAGIC_PE32_PLUS	0x020b

typedef struct _IMAGE_DATA_DIRECTORY {
	uint32_t VirtualAddress;
	uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct coff_header {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};

struct optional_header_standard_fields {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
};

struct optional_header_pe32_extra_field {
	uint32_t BaseOfData;
};

struct optional_header_windows_specific_fields_32 {
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserver;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY ExportTable;
	IMAGE_DATA_DIRECTORY ImportTable;
	IMAGE_DATA_DIRECTORY ResourceTable;
	IMAGE_DATA_DIRECTORY ExceptionTable;
	IMAGE_DATA_DIRECTORY CertificateTable;
	IMAGE_DATA_DIRECTORY BaseRelocationTable;
	IMAGE_DATA_DIRECTORY Debug;
	IMAGE_DATA_DIRECTORY Architecture;
	IMAGE_DATA_DIRECTORY GlobalPtr;
	IMAGE_DATA_DIRECTORY TLSTable;
	IMAGE_DATA_DIRECTORY LoadConfigTable;
	IMAGE_DATA_DIRECTORY BoundImport;
	IMAGE_DATA_DIRECTORY IAT;
	IMAGE_DATA_DIRECTORY DelayImportDescriptor;
	IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
	IMAGE_DATA_DIRECTORY Reserved;
};

struct optional_header_windows_specific_fields {
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserver;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY ExportTable;
	IMAGE_DATA_DIRECTORY ImportTable;
	IMAGE_DATA_DIRECTORY ResourceTable;
	IMAGE_DATA_DIRECTORY ExceptionTable;
	IMAGE_DATA_DIRECTORY CertificateTable;
	IMAGE_DATA_DIRECTORY BaseRelocationTable;
	IMAGE_DATA_DIRECTORY Debug;
	IMAGE_DATA_DIRECTORY Architecture;
	IMAGE_DATA_DIRECTORY GlobalPtr;
	IMAGE_DATA_DIRECTORY TLSTable;
	IMAGE_DATA_DIRECTORY LoadConfigTable;
	IMAGE_DATA_DIRECTORY BoundImport;
	IMAGE_DATA_DIRECTORY IAT;
	IMAGE_DATA_DIRECTORY DelayImportDescriptor;
	IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
	IMAGE_DATA_DIRECTORY Reserved;
};

struct section_header {
	char Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
};

/**
 * efi_pe_characteristic_string() - description of a COFF Characteristics
 * bit
 *
 * @bit:	bit number (0..15) of the Characteristics field
 * Return:	description, or NULL if @bit is out of range
 */
const char *efi_pe_characteristic_string(unsigned int bit);

/**
 * efi_pe_section_characteristic_string() - description of a section
 * Characteristics bit
 *
 * @bit:	bit number (0..31) of a section's Characteristics field
 * Return:	description, or NULL if @bit is out of range. The
 *		description "Reserved." is returned for reserved bits.
 */
const char *efi_pe_section_characteristic_string(unsigned int bit);

/*
 * Description strings for the bits of the DllCharacteristics field.
 * Bit i (1 << i) is described by efi_pe_dll_characteristics[i].
 */
extern const char * const efi_pe_dll_characteristics[16];

/*
 * Labels for the entries of the data directory table (the array of
 * IMAGE_DATA_DIRECTORY entries starting at ExportTable in the Windows
 * specific fields of the optional header). Entry i is described by
 * efi_pe_data_directory_names[i].
 */
extern const char * const efi_pe_data_directory_names[16];

/**
 * efi_pe_machine_type_name() - human readable machine type description
 *
 * @machine:	COFF Machine field value
 * Return:	description, or NULL if the machine type is not recognized
 */
const char *efi_pe_machine_type_name(uint16_t machine);

/**
 * efi_pe_subsystem_name() - human readable Windows subsystem description
 *
 * @subsystem:	Subsystem field value
 * Return:	description, or NULL if the subsystem is not recognized
 */
const char *efi_pe_subsystem_name(uint16_t subsystem);

/**
 * efi_pe_fdt_compatible() - identify a flattened device tree (FDT/DTB)
 * and return its root /compatible property
 *
 * Some EFI binaries embed a device tree in one of their sections
 * (e.g. U-Boot's FIT-less DTB payloads). This checks whether @data
 * looks like a valid FDT blob (magic number, followed by a full
 * libfdt structural check) and, if so, returns the first string of
 * the root node's "compatible" property.
 *
 * This function never treats "not an FDT" as an error: it simply
 * returns NULL. Callers must not report a NULL return as a failure
 * to the user; it only means the section is not a device tree (or is
 * malformed/truncated), which is the common, expected case for the
 * vast majority of sections.
 *
 * @data:	buffer to inspect (e.g. a section's raw data)
 * @size:	size of @data in bytes
 * Return:	newly malloc'd NUL-terminated string with the first
 *		entry of the root /compatible property, or NULL if
 *		@data is not a valid FDT, is too small/large to
 *		plausibly be one, has no /compatible property, or on
 *		allocation failure. Caller must free() the result.
 */
char *efi_pe_fdt_compatible(const void *data, size_t size);

/**
 * efi_pe_fdt_compatible_fd() - efi_pe_fdt_compatible() reading from a
 * file descriptor
 *
 * Reads @size bytes at @offset from @fd into a temporary buffer and
 * calls efi_pe_fdt_compatible() on it. The caller is expected to have
 * already checked that @offset + @size does not exceed the size of
 * the file; this function additionally re-checks that the read
 * actually returns the requested number of bytes.
 *
 * As with efi_pe_fdt_compatible(), a NULL return is not an error
 * condition, just means "not a device tree".
 *
 * @fd:		file descriptor open for reading
 * @offset:	file offset of the candidate FDT blob
 * @size:	size of the candidate FDT blob in bytes
 * Return:	newly malloc'd NUL-terminated string with the first
 *		entry of the root /compatible property, or NULL.
 *		Caller must free() the result.
 */
char *efi_pe_fdt_compatible_fd(int fd, long long offset, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* EFI_PE_H */

