// SPDX-License-Identifier:     BSD-2-Clause
/*
 * Copyright (c) 2017-2019 Heinrich Schuchardt
 *
 * Tool to analyze UEFI binaries
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/efi_pe.h"

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
static void print_characteristics(uint16_t c)
{
	unsigned int i, mask = 1;

	printf("Characteristics: 0x%04x\n", c);
	for (i = 0; i < 16; ++i, mask <<= 1) {
		if (c & mask)
			printf("  * %s\n", efi_pe_characteristic_string(i));
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

	printf("Number data tables: %d\n", num_tables);
	for(IMAGE_DATA_DIRECTORY *table = tables; table < end; ++table)
		printf("  %-20.20s: 0x%08x - 0x%08x\n",
		       efi_pe_data_directory_names[pos++],
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
			printf("    * %s\n", efi_pe_section_characteristic_string(i));
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
	if ((size_t)count != len) {
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

	unsigned char actual[BUFLEN];

	offset = lseek(fd, pos, SEEK_SET);
	if (offset == -1) {
		perror("");
		fprintf(stderr, "Failed to lseek 0x%llx\n", (long long)pos);
		exit(EXIT_FAILURE);
	}

	count = read(fd, actual, len);
	if ((size_t)count != len) {
		fprintf(stderr,
		        "Failed to read 0x%zx bytes at offset 0x%llx\n",
		        len, (long long)pos);
		exit(EXIT_FAILURE);
	}

	if (memcmp(actual, expected, len)) {
		size_t i;

		actual[count] = 0;
		for (i = 0; i < len; ++i) {
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
static void print_machine_type(uint16_t machine)
{
	const char *name = efi_pe_machine_type_name(machine);

	printf("Machine type: 0x%04x, %s\n", machine,
	       name ? name : "Unknown machine type");
}

/**
 * print_section_info() - print section description
 *
 * @fd:		file descriptor
 * @pos:	start of section information
 * @coff:	COFF header
 */
static void print_section_info(int fd, off_t pos, struct coff_header *coff)
{
	int i;
	struct section_header sh;
	off_t section_table_start = pos;
	off_t first_section_addr = UINT_MAX;

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
		if (sh.SizeOfRawData &&
		    sh.PointerToRawData < first_section_addr)
			first_section_addr = sh.PointerToRawData;
	}
	if (first_section_addr != UINT_MAX)
		printf("Maximum number of section table entries = %llu\n",
		       (long long unsigned int)
		       (first_section_addr - section_table_start) / sizeof(sh));
}

/**
 * skip_pci_rom_header() - skip EFI PCI Expansion ROM Header
 *
 * @fd:		file descriptor
 * Return:	offset to EFI image
 */
static uint32_t skip_pci_rom_header(int fd)
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
static void print_subsystem(uint16_t subsystem)
{
	const char *name = efi_pe_subsystem_name(subsystem);

	printf("Subsystem: ");
	if (name)
		printf("%s\n", name);
	else
		printf("Unknown Windows subsystem %d\n", subsystem);
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
 * print_dll_characteristics - print DLL characteristics
 *
 * @c:	DLL characteristics
 */
static void print_dll_characteristics(unsigned int c)
{
	unsigned int i, mask = 1;

	printf("DLL Characteristics: 0x%04x\n", c);
	for (i = 0; i < 16; ++i, mask <<= 1) {
		if (c & mask)
			printf("  * %s\n", efi_pe_dll_characteristics[i]);
	}
}

/**
 * analyze() -  analyze EFI binary
 *
 * @fd:		file descriptor
 * Return:	0 for success
 */
static int analyze(int fd)
{
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
	printf("LinkerVersion %d.%d\n",
	       ohs.MajorLinkerVersion, ohs.MinorLinkerVersion);
	printf("BaseOfCode: 0x%x\n", ohs.BaseOfCode);
	printf("SizeOfCode: 0x%x\n", ohs.SizeOfCode);
	printf("SizeOfInitializedData: 0x%x\n", ohs.SizeOfInitializedData);
	printf("SizeOfSizeOfUninitializedData: 0x%x\n", ohs.SizeOfUninitializedData);
	printf("AddressOfEntryPoint: 0x%x\n", ohs.AddressOfEntryPoint);

	printf("Image type: ");
	switch (ohs.Magic) {
	case OPTIONAL_HEADER_MAGIC_PE32:
		printf("PE32\n");
		rds(fd, pos, &ohpx);
		pos += sizeof(ohpx);
		rds(fd, pos, &ohw32);
		pos += sizeof(ohw32);
		print_subsystem(ohw32.Subsystem);
		print_dll_characteristics(ohw32.DllCharacteristics);
		printf("ImageBase: 0x%x\n", ohw32.ImageBase);
		check_alignment(ohw32.SectionAlignment, ohw32.FileAlignment);
		printf("SizeOfImage: 0x%x\n", ohw32.SizeOfImage);
		printf(".reloc.address: 0x%x\n",
		       ohw32.BaseRelocationTable.VirtualAddress);
		printf(".reloc.size: 0x%x\n", ohw32.BaseRelocationTable.Size);
		tables = &ohw32.ExportTable;
		pos_tables = pos - 16 * sizeof(IMAGE_DATA_DIRECTORY);
		num_tables = ohw32.NumberOfRvaAndSizes;
		break;
	case OPTIONAL_HEADER_MAGIC_PE32_PLUS:
		printf("PE32+\n");
		rds(fd, pos, &ohw);
		pos += sizeof(ohw);
		print_subsystem(ohw.Subsystem);
		print_dll_characteristics(ohw.DllCharacteristics);
		printf("ImageBase: 0x%llx\n",
		       (unsigned long long)ohw.ImageBase);
		check_alignment(ohw.SectionAlignment, ohw.FileAlignment);
		printf("SizeOfImage: 0x%x\n", ohw.SizeOfImage);
		printf(".reloc.address: 0x%x\n",
		       ohw.BaseRelocationTable.VirtualAddress);
		printf(".reloc.size: 0x%x\n", ohw.BaseRelocationTable.Size);
		tables = &ohw.ExportTable;
		pos_tables = pos - 16 * sizeof(IMAGE_DATA_DIRECTORY);
		num_tables = ohw.NumberOfRvaAndSizes;
		break;
	default:
		fprintf(stderr, "Wrong OHS Magic 0x%04x\n", ohs.Magic);
		exit(EXIT_FAILURE);
	}
	if (num_tables > 16) {
		fprintf(stderr,
			"NumberOfRvaAndSizes must be less or equal 16\n");
		exit(EXIT_FAILURE);
	}
	if ((off_t)(pos_tables + num_tables * sizeof(IMAGE_DATA_DIRECTORY)) !=
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
