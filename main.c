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
#define IMAGE_FILE_MACHINE_ARM64	0xaa64
#define IMAGE_FILE_MACHINE_RISCV32	0x5032
#define IMAGE_FILE_MACHINE_RISCV64	0x5064
#define IMAGE_FILE_MACHINE_RISCV128	0x5128

#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12

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
	IMAGE_DATA_DIRECTORY CLRRuntimeHeaer;
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
	IMAGE_DATA_DIRECTORY CLRRuntimeHeaer;
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
 * usage() - prints help.
 */
static void usage(void)
{
	printf("Usage: efianalyze FILENAME\n");
	printf("Analyze UEFI binary\n");
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
		fprintf(stderr, "Failed to lseek 0x%zx\n", pos);
		exit(EXIT_FAILURE);
	}

	count = read(fd, buffer, len);
	if (count != len) {
		fprintf(stderr,
		        "Failed to read 0x%zx bytes at offset 0x%zx\n",
		        len, pos);
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
		fprintf(stderr, "Failed to lseek 0x%zx\n", pos);
		exit(EXIT_FAILURE);
	}

	count = read(fd, actual, len);
	if (count != len) {
		fprintf(stderr,
		        "Failed to read 0x%zx bytes at offset 0x%zx\n",
		        len, pos);
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
		        "Expected '%s', found '%s' at offset 0x%zx\n",
		        expected, actual, pos);
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
	default:
		printf("Unknown machine type\n");
	}
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
	struct coff_header coff;
	struct optional_header_standard_fields ohs;
	struct optional_header_pe32_extra_field ohpx;
	struct optional_header_windows_specific_fields ohw;
	struct optional_header_windows_specific_fields_32 ohw32;
	struct section_header sh;

	off_t pos, pos_tables;

	check_string(fd, 0, 2, "MZ");
	pos = 0x3c;
	rds(fd, pos, &pe_offset);
	printf("Offset to PE = %x\n", pe_offset);
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
	printf("Characteristics 0x%x\n", coff.Characteristics);

	pos += sizeof(coff);
	rds(fd, pos, &ohs);
	pos_tables = pos + coff.SizeOfOptionalHeader;
	pos += sizeof(ohs);
	printf("Image type: ");
	switch (ohs.Magic) {
	case OPTIONAL_HEADER_MAGIC_PE32:
		printf("PE32\n");
		rds(fd, pos, &ohpx);
		pos += sizeof(ohpx);
		if (sizeof(ohs) + sizeof(ohpx) + sizeof(ohw32) !=
		    coff.SizeOfOptionalHeader) {
			fprintf(stderr,
			        "Size of optional header: 0x%x != 0x%x\n",
			        coff.SizeOfOptionalHeader,
			        sizeof(ohs) + sizeof(ohpx) + sizeof(ohw32));
		}
		break;
	case OPTIONAL_HEADER_MAGIC_PE32_PLUS:
		printf("PE32+\n");
		if (sizeof(ohs) + sizeof(ohw) != coff.SizeOfOptionalHeader) {
			fprintf(stderr,
			        "Size of optional header: 0x%x != 0x%x\n",
			        coff.SizeOfOptionalHeader, sizeof(ohs) + sizeof(ohw));
		}
		break;
	default:
		fprintf(stderr, "Wrong OHS Magic 0x%04x\n", ohs.Magic);
		exit(EXIT_FAILURE);
	}

	if (ohs.Magic == OPTIONAL_HEADER_MAGIC_PE32) {
		rds(fd, pos, &ohw32);

		switch(ohw32.Subsystem) {
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			printf("EFI application\n");
			break;
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			printf("EFI boot service driver\n");
			break;
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			printf("EFI runtime driver\n");
			break;
		default:
			fprintf(stderr, "Illegal Windows subsystem %d\n",
			        ohw32.Subsystem);
		}

		printf("ImageBase=0x%lx\n", ohw32.ImageBase);
		printf("SectionAlignment=0x%lx\n",
		       (unsigned long)ohw32.SectionAlignment);
		printf("SizeOfImage=0x%lx\n", ohw32.SizeOfImage);
		printf(".reloc.address=0x%x\n",
		       ohw32.BaseRelocationTable.VirtualAddress);
		printf(".reloc.size=0x%x\n", ohw32.BaseRelocationTable.Size);
	} else {
		rds(fd, pos, &ohw);

		switch(ohw.Subsystem) {
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			printf("EFI application\n");
			break;
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			printf("EFI boot service driver\n");
			break;
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			printf("EFI runtime driver\n");
			break;
		default:
			fprintf(stderr, "Illegal Windows subsystem %d\n",
			        ohw.Subsystem);
		}

		printf("ImageBase=0x%lx\n", ohw.ImageBase);
		printf("SectionAlignment=0x%lx\n", ohw.SectionAlignment);
		printf("SizeOfImage=0x%lx\n", ohw.SizeOfImage);
		printf(".reloc.address=0x%x\n",
		       ohw.BaseRelocationTable.VirtualAddress);
		printf(".reloc.size=0x%x\n", ohw.BaseRelocationTable.Size);
	}

	printf("BaseOfCode=0x%lx\n", ohs.BaseOfCode);
	printf("AddressOfEntryPoint=0x%lx\n", ohs.AddressOfEntryPoint);
	printf("Number of Sections %d\n", coff.NumberOfSections);
	pos = pos_tables;
	for (i = 0; i < coff.NumberOfSections; ++i) {
		rds(fd, pos, &sh);
		pos += sizeof(sh);
		sh.Name[8] = 0;
		printf ("Section[%d] %s\n", i, sh.Name);
		printf("Virtual size 0x%x\n", sh.VirtualSize);
		printf("Virtual address 0x%x\n", sh.VirtualAddress);
		printf("Size of raw data 0x%x\n", sh.SizeOfRawData);
		printf("Pointer to raw data 0x%x\n", sh.PointerToRawData);
		printf("End of raw data 0x%x\n",
		       sh.PointerToRawData + sh.SizeOfRawData);
		if (sh.PointerToRelocations)
			printf("Pointer to relocations 0x%x\n",
			       sh.PointerToRelocations);
		if (sh.NumberOfRelocations)
			printf("%d relocations\n", sh.NumberOfRelocations);
		if (sh.NumberOfLinenumbers)
			printf("%d number of line numbers\n",
			       sh.NumberOfLinenumbers);
	}
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

	ret = analyze(fd);

	close(fd);
	return ret;
}
