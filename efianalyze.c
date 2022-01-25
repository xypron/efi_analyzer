// SPDX-License-Identifier:     BSD-2-Clause
/*
 * Copyright (c) 2017-2019 Heinrich Schuchardt
 *
 * Tool to analyze UEFI binaries
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFLEN 10

/**
 * rds() - read structure from file.
 *
 * The program is aborted if an error occurs.
 *
 * @A:	file descriptor
 * @B:	position
 * @C:	structure
 */
#define rds(A,B,C) read_structure(A, B, sizeof(*C), C)

#define IMAGE_FILE_MACHINE_AMD64	0x8664
#define IMAGE_FILE_MACHINE_I386		0x014c
#define IMAGE_FILE_MACHINE_ARM		0x01c0
#define IMAGE_FILE_MACHINE_THUMB	0x01c2
#define IMAGE_FILE_MACHINE_ARMNT	0x01c4
#define IMAGE_FILE_MACHINE_EBC		0x0ebc
#define IMAGE_FILE_MACHINE_ARM64	0xaa64
#define IMAGE_FILE_MACHINE_RISCV32	0x5032
#define IMAGE_FILE_MACHINE_RISCV64	0x5064
#define IMAGE_FILE_MACHINE_RISCV128	0x5128

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

char *characteristic_strings[] = {
	"Relocation information was stripped from the file.",
	"The file is executable.",
	"COFF line numbers were stripped from the file.",
	"COFF symbol table entries were stripped from file.",
	"Aggressively trim the working set. This value is obsolete.",
	"The application can handle addresses larger than 2 GiB.",
	"Use of this flag is reserved for future use.",
	"Little endian: LSB precedes MSB in memory.",
	"The computer supports 32-bit words.",
	"Debugging information was removed.",
	"If the image is on removable media, copy and run from swap file.",
	"If the image is on the network, copy and run from swap file.",
	"The image is a system file.",
	"The image is a dynamic link library (DLL).",
	"The file should be run only on a uniprocessor computer.",
	"Big endian: MSB precedes LSB in memory.",
};

char *section_characteristics[] = {
	"Reserved.",
	"Reserved.",
	"Reserved.",
	"The section should not be padded to the next boundary.",
	"Reserved.",
	"The section contains executable code.",
	"The section contains initialized data.",
	"The section contains uninitialized data.",
	"Reserved.",
	"The section contains comments or other information.",
	"Reserved.",
	"The section will not become part of the image.",
	"The section contains COMDAT data.",
	"Reserved.",
	"Reset speculative exceptions handling bits in the TLB entries.",
	"The section contains data referenced through the global pointer.",
	"Reserved.",
	"Reserved.",
	"Reserved.",
	"Reserved.",
	"Align data on a 1-byte boundary.",
	"Align data on a 2-byte boundary.",
	"Align data on a 8-byte boundary.",
	"Align data on a 128-byte boundary.",
	"The section contains extended relocations.",
	"The section can be discarded as needed.",
	"The section cannot be cached.",
	"The section cannot be paged.",
	"The section can be shared in memory.",
	"The section can be executed as code.",
	"The section can be read.",
	"The section can be written to.",
};

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
	uint32_t SizeOfInitilizedData;
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

struct pci_expansion_rom_header {
	uint16_t Signature;
	uint16_t InitializationSize;
	uint32_t EfiSignature;
	uint32_t EfiMachineType;
	uint16_t CompressionType;
	uint8_t Reserved[8];
	uint16_t EfiImageHeaderOffset;
	uint16_t PcirOffset;
};

/**
 * usage() - prints help.
 */
static void usage(void)
{
	printf("Usage: efianalyze FILENAME\n");
	printf("Analyze UEFI binary\n");
}

/**
 * print_characteristics - print characteristics
 */
void print_characteristics(uint16_t c)
{
	unsigned int i, mask = 1;

	printf("Characteristics: 0x%04x\n", c);
	for (i = 0; i < 16; ++i, mask <<= 1) {
		if (c & mask)
			printf("  * %s\n", characteristic_strings[i]);
	}
}

/**
 * print_table_info() - print tables
 *
 * @tables:	pointer to tables
 * @num_tables:	number of tables
 */
static void print_table_info(IMAGE_DATA_DIRECTORY *tables, uint32_t num_tables)
{
	IMAGE_DATA_DIRECTORY *end = &tables[num_tables];
	int pos = 0;
	const char *labels[] = {
		"Exports",
		"Imports",
		"Resources",
		"Exceptions",
		"Certificates",
		"Base Relocations",
		"Debug",
		"Architecture",
		"GlobalPtr",
		"TLS",
		"Load Config",
		"Bound Import",
		"IAT",
		"Delay Import Descriptor",
		"CLR Runtime Header",
		"Reserved",
	};

	printf("Number data tables: %d\n", num_tables);
	for(IMAGE_DATA_DIRECTORY *table = tables; table < end; ++table)
		printf("  %-20s: 0x%08x - 0x%08x\n", labels[pos++],
		       table->VirtualAddress,
		       table->VirtualAddress + table->Size);
}

/**
 * print_section_characteristics() - print section characteristics
 *
 * @c:	section characteristics bitmap
 */
static void print_section_characteristics(uint32_t c)
{
	unsigned int i, mask = 1, align;

	align = c & 0xf00000;
	c &= ~0xf00000;

	printf("  Characteristics: 0x%08x\n", c);
	for (i = 0; i < 32; ++i, mask <<= 1) {
		if (c & mask)
			printf("    * %s\n", section_characteristics[i]);
	}

	if (align) {
		align = 1 << ((align >> 20)- 1);
		printf("    * Align data on a %u byte boundary.\n", align);
	}
}

/**
 * read_structure - read structure from file
 *
 * The program is aborted if an error occurs.
 *
 * @fd:		file descriptor
 * @pos:	position
 * @len:	length of the buffer
 * @buffer:	target buffer
 */
static void read_structure(int fd, off_t pos, size_t len, void *buffer)
{
	off_t offset;
	ssize_t count;

	offset = lseek(fd, pos, SEEK_SET);
	if (offset == -1) {
		fprintf(stderr, "Failed to lseek 0x%llx\n", (long long)pos);
		exit(EXIT_FAILURE);
	}

	count = read(fd, buffer, len);
	if (count != len) {
		fprintf(stderr,
		        "Failed to read 0x%zx bytes at offset 0x%llx\n",
		        len, (long long)pos);
		exit(EXIT_FAILURE);
	}
}

/**
 * check_string () - checks if a string is at the expected position in a file
 *
 * The program is aborted if the string is not found.
 *
 * @fd:		file descriptor
 * @pos:	position in file
 * @len:	length of string to compare
 * @expected:	expected string
 */
static void check_string(int fd, off_t pos, size_t len, const char *expected)
{
	off_t offset;
	ssize_t count;

	char actual[BUFLEN];

	offset = lseek(fd, pos, SEEK_SET);
	if (offset == -1) {
		perror("");
		fprintf(stderr, "Failed to lseek 0x%llx\n", (long long)pos);
		exit(EXIT_FAILURE);
	}

	count = read(fd, actual, len);
	if (count != len) {
		fprintf(stderr,
		        "Failed to read 0x%zx bytes at offset 0x%llx\n",
		        len, (long long)pos);
		exit(EXIT_FAILURE);
	}

	if (memcmp(actual, expected, len)) {
		size_t i;

		actual[count] = 0;
		for (i = 0; i < count; ++i) {
			if (actual[i] < 0x20 || actual[i] >= 0x80)
				actual[i] = '?';
		}
		fprintf(stderr,
		        "Expected '%s', found '%s' at offset 0x%llx\n",
		        expected, actual, (long long)pos);
		exit(EXIT_FAILURE);
	}
}

/**
 * print_machine_type() - print manche type
 *
 * @machine:	machine type
 */
void print_machine_type(uint16_t machine)
{
	printf("Machine type: 0x%04x, ", machine);
	switch (machine) {
	case IMAGE_FILE_MACHINE_AMD64:
		printf("x64\n");
		break;
	case IMAGE_FILE_MACHINE_I386:
		printf("Intel 386\n");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		printf("ARM little endian\n");
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		printf("ARM or Thumb (\"interworking\")\n");
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		printf("ARM Thumb-2 little endian \n");
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		printf("ARM64 little endian\n");
		break;
	case IMAGE_FILE_MACHINE_RISCV32:
		printf("RISC-V 32-bit\n");
		break;
	case IMAGE_FILE_MACHINE_RISCV64:
		printf("RISC-V 64-bit\n");
		break;
	case IMAGE_FILE_MACHINE_RISCV128:
		printf("RISC-V 128-bit\n");
		break;
	case IMAGE_FILE_MACHINE_EBC:
		printf("EFI byte code\n");
		break;
	default:
		printf("Unknown machine type\n");
	}
}

/**
 * print_section_info() - print section description
 *
 * @fd:		file descriptor
 * @pos:	start of section information
 * @coff:	COFF header
 */
void print_section_info(int fd, off_t pos, struct coff_header *coff)
{
	int i;
	struct section_header sh;

	printf("Number of sections: %d\n", coff->NumberOfSections);
	for (i = 0; i < coff->NumberOfSections; ++i) {
		rds(fd, pos, &sh);
		pos += sizeof(sh);
		printf("Section[%d]: %.8s\n", i, sh.Name);
		printf("  Virtual size: 0x%x\n", sh.VirtualSize);
		printf("  Virtual address: 0x%x\n", sh.VirtualAddress);
		printf("  Size of raw data: 0x%x\n", sh.SizeOfRawData);
		printf("  Pointer to raw data: 0x%x\n", sh.PointerToRawData);
		printf("  End of raw data: 0x%x\n",
		       sh.PointerToRawData + sh.SizeOfRawData);
		if (sh.PointerToRelocations)
			printf("  Pointer to relocations: 0x%x\n",
			       sh.PointerToRelocations);
		if (sh.NumberOfRelocations)
			printf("  %d relocations\n", sh.NumberOfRelocations);
		if (sh.NumberOfLinenumbers)
			printf("  %d line numbers\n",
			       sh.NumberOfLinenumbers);
		print_section_characteristics(sh.Characteristics);
	}
}

/**
 * skip_pci_rom_header() - skip EFI PCI Expansion ROM Header
 *
 * @fd:		file descriptor
 * Return:	offset to EFI image
 */
uint32_t skip_pci_rom_header(int fd)
{
	struct pci_expansion_rom_header hd;

	rds(fd, 0, &hd);

	if (hd.Signature != 0xaa55)
		return 0;
	if (hd.EfiSignature != 0x0ef1)
		return 0;
	printf("EFI PCI Expansion ROM\n");
	if (hd.CompressionType) {
		printf("Compressed image not supported\n");
		exit(EXIT_FAILURE);
	}
	return hd.EfiImageHeaderOffset;
}

/**
 * print_subsystem() - print Windows subsystem
 *
 * @subsystem:	subsystem
 */
void print_subsystem(uint16_t subsystem)
{
	printf("Subsystem: ");
	switch(subsystem) {
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("EFI application\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("EFI boot service driver\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("EFI runtime driver\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("EFI ROM image\n");
		break;
	default:
		printf("Unknown Windows subsystem %d\n", subsystem);
	}
}


/**
 * check_alignment() - check file and section alignment
 *
 * @section_alignment:	section alignement
 * @file_alignment:	file alignment
 */
static void check_alignment(uint32_t section_alignment, uint32_t file_alignment)
{
	if (section_alignment < 2 ||
	    (section_alignment & (section_alignment - 1)))
		printf("Illegal SectionAlignment\n");
	printf("SectionAlignment: 0x%x\n", section_alignment);
	if (file_alignment < 2 || file_alignment > 0x10000 ||
	    (file_alignment & (file_alignment - 1)))
		printf("Illegal FileAlignment\n");
	printf("FileAlignment: 0x%x\n", file_alignment);
	if (section_alignment < 4096 && file_alignment != section_alignment)
		printf("FileAlignment != SectionAlignment\n");
}

/**
 * analyze() -  analyze EFI binary
 *
 * @fd:		file descriptor
 * Return:	0 for success
 */
int analyze(int fd)
{
	int ret;
	int i;
	uint32_t pe_offset;
	uint32_t efi_offset;
	struct coff_header coff;
	struct optional_header_standard_fields ohs;
	struct optional_header_pe32_extra_field ohpx;
	struct optional_header_windows_specific_fields ohw;
	struct optional_header_windows_specific_fields_32 ohw32;
	IMAGE_DATA_DIRECTORY *tables;
	uint32_t num_tables;
	off_t pos, pos_sections, pos_tables;

	efi_offset = skip_pci_rom_header(fd);
	check_string(fd, efi_offset, 2, "MZ");
	pos = efi_offset + 0x3c;
	rds(fd, pos, &pe_offset);
	printf("Offset to PE: 0x%x\n", pe_offset);
	pe_offset += efi_offset;
	check_string(fd, pe_offset, 4, "PE\0\0");
	pos = pe_offset + sizeof(pe_offset);
	rds(fd, pos, &coff);
	print_machine_type(coff.Machine);
	if (coff.PointerToSymbolTable) {
		fprintf(stderr, "PointerToSymbolTable should be 0.\n");
	}
	if (coff.NumberOfSymbols) {
		fprintf(stderr, "NumberOfSymbols should be 0.\n");
	}
	print_characteristics(coff.Characteristics);

	pos += sizeof(coff);
	rds(fd, pos, &ohs);
	pos_sections = pos + coff.SizeOfOptionalHeader;
	pos += sizeof(ohs);
	printf("BaseOfCode: 0x%x\n", ohs.BaseOfCode);
	printf("AddressOfEntryPoint: 0x%x\n", ohs.AddressOfEntryPoint);

	printf("Image type: ");
	switch (ohs.Magic) {
	case OPTIONAL_HEADER_MAGIC_PE32:
		printf("PE32\n");
		rds(fd, pos, &ohpx);
		pos += sizeof(ohpx);
		break;
	case OPTIONAL_HEADER_MAGIC_PE32_PLUS:
		printf("PE32+\n");
		break;
	default:
		fprintf(stderr, "Wrong OHS Magic 0x%04x\n", ohs.Magic);
		exit(EXIT_FAILURE);
	}

	if (ohs.Magic == OPTIONAL_HEADER_MAGIC_PE32) {
		rds(fd, pos, &ohw32);
		pos += sizeof(ohw32);

		print_subsystem(ohw32.Subsystem);

		printf("ImageBase: 0x%x\n", ohw32.ImageBase);
		check_alignment(ohw32.SectionAlignment, ohw32.FileAlignment);
		printf("SizeOfImage: 0x%x\n", ohw32.SizeOfImage);
		printf(".reloc.address: 0x%x\n",
		       ohw32.BaseRelocationTable.VirtualAddress);
		printf(".reloc.size: 0x%x\n", ohw32.BaseRelocationTable.Size);
		tables = &ohw32.ExportTable;
		pos_tables = pos - 16 * sizeof(IMAGE_DATA_DIRECTORY);
		num_tables = ohw32.NumberOfRvaAndSizes;
	} else {
		rds(fd, pos, &ohw);
		pos += sizeof(ohw);

		print_subsystem(ohw.Subsystem);

		printf("ImageBase: 0x%llx\n", ohw.ImageBase);
		check_alignment(ohw.SectionAlignment, ohw.FileAlignment);
		printf("SizeOfImage: 0x%x\n", ohw.SizeOfImage);
		printf(".reloc.address: 0x%x\n",
		       ohw.BaseRelocationTable.VirtualAddress);
		printf(".reloc.size: 0x%x\n", ohw.BaseRelocationTable.Size);
		tables = &ohw.ExportTable;
		pos_tables = pos - 16 * sizeof(IMAGE_DATA_DIRECTORY);
		num_tables = ohw.NumberOfRvaAndSizes;
	}
	if (num_tables > 16) {
		fprintf(stderr,
			"NumberOfRvaAndSizes must be less or equal 16\n");
		exit(EXIT_FAILURE);
	}
	if (pos_tables + num_tables * sizeof(IMAGE_DATA_DIRECTORY) !=
	    pos_sections) {
		fprintf(stderr,
			"Mismatch NumberOfRvaAndSizes, SizeOfOptionalHeader\n");
		exit(EXIT_FAILURE);
	}
	print_table_info(tables, num_tables);
	print_section_info(fd, pos_sections, &coff);

	close(fd);
	return EXIT_SUCCESS;

}

/**
 * main() - entry point
 *
 * @argc:	number of arguments
 * @argv:	comand line arguments
 * Return:	0 for success
 */
int main(int argc, char *argv[])
{
	int fd, ret;

	if (argc != 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		usage();
		exit(EXIT_SUCCESS);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("Cannot open file");
		exit(EXIT_FAILURE);
	}

	printf("%s\n", argv[1]);
	ret = analyze(fd);

	close(fd);
	return ret;
}
