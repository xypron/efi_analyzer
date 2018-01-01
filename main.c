#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFLEN 10

#define rds(A,B,C) read_structure(A, B, sizeof(*C), C)

#define IMAGE_FILE_MACHINE_AMD64	0x8664
#define IMAGE_FILE_MACHINE_I386		0x014c
#define IMAGE_FILE_MACHINE_ARM		0x01c0
#define IMAGE_FILE_MACHINE_ARM64	0xaa64

#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12

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

static void read_structure(int fd, off_t pos, size_t len, void *buffer)
{
	off_t offset;
	ssize_t count;

	offset = lseek(fd, pos, SEEK_SET);
	if (offset == -1) {
		fprintf(stderr, "%s(%d): failed to lseek\n",
		        __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	count = read(fd, buffer, len);
	if (count != len) {
		fprintf(stderr, "%s(%d): failed to read\n",
		        __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void check_string(int fd, off_t pos, size_t len, const char *expected)
{
	off_t offset;
	ssize_t count;

	char actual[BUFLEN];

	offset = lseek(fd, pos, SEEK_SET);
	if (offset == -1) {
		perror("");
		fprintf(stderr, "%s(%d): failed to lseek 0x%x\n",
		        __FILE__, __LINE__,
		        pos);
		exit(EXIT_FAILURE);
	}

	count = read(fd, actual, len);
	if (count != len) {
		fprintf(stderr, "%s(%d): failed to read\n",
		        __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	actual[count] = 0;

	if (strcmp(actual, expected)) {
		fprintf(stderr, "%s(%d): %s != %s\n",
		        __FILE__, __LINE__,
		        actual, expected);
	}
}


int main(int argc, char *argv[])
{
	int ret;
	int fd;
	int i;

	uint32_t pe_offset;
	struct coff_header coff;
	struct optional_header_standard_fields ohs;
	struct section_header sh;

	off_t pos;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s FILENAME\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("Cannot open file");
		exit(EXIT_FAILURE);
	}

	check_string(fd, 0, 2, "MZ");
	pos = 0x3c;
	rds(fd, pos, &pe_offset);
	printf("Offset to PE = %x\n", pe_offset);
	check_string(fd, pe_offset, 4, "PE\0\0");
	pos = pe_offset + sizeof(pe_offset);
	rds(fd, pos, &coff);
	printf("Machine type: ");
	switch (coff.Machine) {
	case IMAGE_FILE_MACHINE_AMD64:
		printf("x64\n");
		break;
	case IMAGE_FILE_MACHINE_I386:
		printf("Intel 386\n");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		printf("ARM little endian\n");
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		printf("ARM64 little endian\n");
		break;
	default:
		fprintf(stderr, "Unknown machine type %04x\n", coff.Machine);
		exit(EXIT_FAILURE);
	}
	if (coff.PointerToSymbolTable) {
		fprintf(stderr, "PointerToSymbolTable should be 0.\n");
		exit(EXIT_FAILURE);
	}
	if (coff.NumberOfSymbols) {
		fprintf(stderr, "NumberOfSymbols should be 0.\n");
	}
	if (sizeof(ohs) != coff.SizeOfOptionalHeader) {
		fprintf(stderr, "Size of optional header: 0x%x != 0x%x\n",
		coff.SizeOfOptionalHeader, sizeof(ohs));
	}
	printf("Characteristics 0x%x\n", coff.Characteristics);

	pos += sizeof(coff);
	rds(fd, pos, &ohs);
	pos += coff.SizeOfOptionalHeader;
	switch (ohs.Magic) {
	case 0x020b:
		printf("PE32+\n");
		break;
	default:
		fprintf(stderr, "Wrong OHS Magic\n");
		exit(EXIT_FAILURE);
	}
	printf("Magic 0x%x\n", ohs.Magic);

	switch(ohs.Subsystem) {
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
		fprintf(stderr, "Illegal Windows subsystem %d", ohs.Subsystem);
	}

	printf("ImageBase=0x%lx\n", ohs.ImageBase);
	printf("AddressOfEntryPoint=0x%lx\n", ohs.AddressOfEntryPoint);
	printf("BaseOfCode=0x%lx\n", ohs.BaseOfCode);
	printf(".reloc.address=0x%x\n", ohs.BaseRelocationTable.VirtualAddress);
	printf(".reloc.size=0x%x\n", ohs.BaseRelocationTable.Size);

	printf("Number of Sections %d\n", coff.NumberOfSections);

	for (i = 0; i < coff.NumberOfSections; ++i) {
		rds(fd, pos, &sh);
		pos += sizeof(sh);
		sh.Name[8] = 0;
		printf ("Section[%d] %s\n", i, sh.Name);
		if (sh.VirtualSize)
			printf("Virtual size 0x%x\n", sh.VirtualSize);
		if (sh.VirtualAddress)
			printf("Virtual adress 0x%x\n", sh.VirtualAddress);
		if (sh.SizeOfRawData);
			printf("Size of raw data 0x%x\n", sh.SizeOfRawData);
		if (sh.PointerToRawData);
			printf("Pointer to raw data 0x%x\n", sh.PointerToRawData);
		if (sh.NumberOfRelocations)
			printf("%d relocations\n", sh.NumberOfRelocations);
		if (sh.NumberOfLinenumbers)
			printf("%d number of line numbers\n", sh.NumberOfLinenumbers);
		if (!strcmp(sh.Name, ".reloc"))
			printf("BINGO\n");
	}

	close(fd);
	return EXIT_SUCCESS;

}
