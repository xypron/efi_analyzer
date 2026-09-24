// SPDX-License-Identifier:     BSD-2-Clause
/*
 * Copyright (c) 2017-2019 Heinrich Schuchardt
 *
 * Shared PE/COFF/EFI string tables and lookup helpers, see efi_pe.h.
 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libfdt.h>

#include "efi_pe.h"

/*
 * Real device trees embedded in EFI binaries are small (typically a
 * few KiB to a few hundred KiB). Reject implausibly large candidates
 * up front so that a corrupt or hostile SizeOfRawData value cannot
 * trigger a huge allocation attempt merely to find out it is not an
 * FDT.
 */
#define FDT_MAX_PLAUSIBLE_SIZE (16u * 1024u * 1024u)

static const char * const efi_pe_characteristic_strings[16] = {
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

static const char * const efi_pe_section_characteristics[32] = {
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

const char * const efi_pe_dll_characteristics[16] = {
	"Reserved.",
	"Reserved.",
	"Reserved.",
	"Reserved.",
	"Reserved.",
	"Image can handle a high entropy 64-bit virtual address space.",
	"DLL can be relocated at load time.",
	"Code Integrity checks are enforced.",
	"Image is NX compatible.",
	"Isolation aware, but do not isolate the image.",
	"Does not use structured exception (SE) handling.",
	"Do not bind the image.",
	"Image must execute in an AppContainer.",
	"A WDM driver.",
	"Image supports Control Flow Guard.",
	"Terminal Server aware.",
};

const char *efi_pe_characteristic_string(unsigned int bit)
{
	if (bit >= sizeof(efi_pe_characteristic_strings) /
		   sizeof(efi_pe_characteristic_strings[0]))
		return NULL;

	return efi_pe_characteristic_strings[bit];
}

const char *efi_pe_section_characteristic_string(unsigned int bit)
{
	if (bit >= sizeof(efi_pe_section_characteristics) /
		   sizeof(efi_pe_section_characteristics[0]))
		return NULL;

	return efi_pe_section_characteristics[bit];
}

const char * const efi_pe_data_directory_names[16] = {
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

const char *efi_pe_machine_type_name(uint16_t machine)
{
	switch (machine) {
	case IMAGE_FILE_MACHINE_I386:
		return "Intel 386";
	case IMAGE_FILE_MACHINE_AMD64:
		return "x64";
	case IMAGE_FILE_MACHINE_IA64:
		return "Intel Itanium";
	case IMAGE_FILE_MACHINE_ARM:
		return "ARM little endian";
	case IMAGE_FILE_MACHINE_THUMB:
		return "ARM or Thumb (\"interworking\")";
	case IMAGE_FILE_MACHINE_ARMNT:
		return "ARM Thumb-2 little endian";
	case IMAGE_FILE_MACHINE_ARM64:
		return "ARM64 little endian";
	case IMAGE_FILE_MACHINE_LOONGARCH32:
		return "LoongArch 32-bit";
	case IMAGE_FILE_MACHINE_LOONGARCH64:
		return "LoongArch 64-bit";
	case IMAGE_FILE_MACHINE_RISCV32:
		return "RISC-V 32-bit";
	case IMAGE_FILE_MACHINE_RISCV64:
		return "RISC-V 64-bit";
	case IMAGE_FILE_MACHINE_RISCV128:
		return "RISC-V 128-bit";
	case IMAGE_FILE_MACHINE_EBC:
		return "EFI byte code";
	default:
		return NULL;
	}
}

const char *efi_pe_subsystem_name(uint16_t subsystem)
{
	switch (subsystem) {
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "EFI application";
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		return "EFI boot service driver";
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		return "EFI runtime driver";
	case IMAGE_SUBSYSTEM_EFI_ROM:
		return "EFI ROM image";
	default:
		return NULL;
	}
}

char *efi_pe_fdt_compatible(const void *data, size_t size)
{
	uint32_t magic;
	const void *compatible;
	int root;
	int len;
	char *result;

	if (!data || size < sizeof(struct fdt_header) ||
	    size > FDT_MAX_PLAUSIBLE_SIZE)
		return NULL;

	/*
	 * Cheap magic check before running the full libfdt structural
	 * validation, to quickly skip the overwhelming majority of
	 * sections that are not device trees at all.
	 */
	memcpy(&magic, data, sizeof(magic));
	if (fdt32_to_cpu(magic) != FDT_MAGIC)
		return NULL;

	if (fdt_check_full(data, size) != 0)
		return NULL;

	root = fdt_path_offset(data, "/");
	if (root < 0)
		return NULL;

	compatible = fdt_getprop(data, root, "compatible", &len);
	if (!compatible || len <= 0)
		return NULL;

	/*
	 * The "compatible" property is a list of NUL-separated
	 * strings; return only the first (most specific) entry. It is
	 * not guaranteed to be NUL-terminated within the queried
	 * length, so bound the copy explicitly.
	 */
	len = (int)strnlen(compatible, (size_t)len);
	result = malloc((size_t)len + 1);
	if (!result)
		return NULL;
	memcpy(result, compatible, (size_t)len);
	result[len] = '\0';

	return result;
}

char *efi_pe_fdt_compatible_fd(int fd, long long offset, size_t size)
{
	void *buf;
	ssize_t n;
	char *result;

	if (size < sizeof(struct fdt_header) || size > FDT_MAX_PLAUSIBLE_SIZE)
		return NULL;

	buf = malloc(size);
	if (!buf)
		return NULL;

	n = pread(fd, buf, size, (off_t)offset);
	if (n != (ssize_t)size) {
		free(buf);
		return NULL;
	}

	result = efi_pe_fdt_compatible(buf, size);
	free(buf);

	return result;
}

/*
 * efi_zboot_header_read() and efi_zboot_compression_string() use
 * pread() to access the file at an explicit, absolute offset (0).
 * pread() never reads or modifies the file descriptor's current
 * read/write position, so calling this function has no effect on -
 * and is unaffected by - any lseek()-based or position-tracking
 * sequential reads (e.g. read_structure()/rds() in the callers of
 * this function) that a caller performs before or after this call.
 */
int efi_zboot_header_read(int fd, struct efi_zboot_header *hdr)
{
	ssize_t n;

	n = pread(fd, hdr, sizeof(*hdr), 0);
	if (n != (ssize_t)sizeof(*hdr))
		return 0;

	if (memcmp(hdr->msdos_magic, "MZ", 2) != 0)
		return 0;
	if (memcmp(hdr->zimg_magic, "zimg", 4) != 0)
		return 0;

	return 1;
}

void efi_zboot_compression_string(const struct efi_zboot_header *hdr,
				   char out[33])
{
	size_t len, i;

	len = strnlen(hdr->compression_type, sizeof(hdr->compression_type));
	memcpy(out, hdr->compression_type, len);
	out[len] = '\0';

	for (i = 0; i < len; ++i) {
		unsigned char c = (unsigned char)out[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z') || c == '.' || c == '_' ||
		      c == '-'))
			out[i] = '_';
	}

	if (len == 0)
		memcpy(out, "bin", 4);
}
