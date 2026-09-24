// SPDX-License-Identifier:     BSD-2-Clause

#include "pe_parser.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../common/efi_pe.h"

struct pci_expansion_rom_header {
	uint16_t Signature;
	uint8_t InitializationSize;
	uint32_t EfiSignature;
	uint16_t EfiSubsystem;
	uint16_t EfiMachineType;
	uint16_t CompressionType;
	uint8_t Reserved[8];
	uint16_t EfiImageHeaderOffset;
	uint16_t PcirOffset;
} __attribute__((packed));

#define PE_PARSER_ERROR pe_parser_error_quark()

static GQuark pe_parser_error_quark(void)
{
	return g_quark_from_static_string("pe-parser-error-quark");
}

/*
 * rds() - read structure from file at a given offset.
 *
 * @fd:		file descriptor
 * @pos:	offset in the file
 * @data:	buffer to read into
 * @len:	number of bytes to read
 * Return:	TRUE on success
 */
static gboolean rds(int fd, off_t pos, void *data, size_t len)
{
	ssize_t n = pread(fd, data, len, pos);

	return n == (ssize_t)len;
}

#define RDS(fd, pos, obj) rds(fd, pos, obj, sizeof(*(obj)))

/*
 * Add a row with a fixed Property/Value pair as a child of @parent.
 * @parent may be NULL for a top level row.
 */
static GtkTreeIter add_row(GtkTreeStore *store, GtkTreeIter *parent,
			    const char *property, const char *value)
{
	GtkTreeIter iter;

	gtk_tree_store_append(store, &iter, parent);
	gtk_tree_store_set(store, &iter,
			    PE_COL_PROPERTY, property,
			    PE_COL_VALUE, value ? value : "",
			    -1);
	return iter;
}

static GtkTreeIter add_row_printf(GtkTreeStore *store, GtkTreeIter *parent,
				   const char *property, const char *fmt, ...)
{
	char *value;
	va_list ap;
	GtkTreeIter iter;

	va_start(ap, fmt);
	value = g_strdup_vprintf(fmt, ap);
	va_end(ap);

	iter = add_row(store, parent, property, value);
	g_free(value);
	return iter;
}

/*
 * Add one row per set bit of @value, from bit 0 to bit @nbits - 1.
 * The row's Property column holds "0x%0Nx" (the bit mask) and the
 * Value column holds the description returned by @name_fn(bit), or
 * "Unknown" if @name_fn returns NULL for that bit.
 *
 * @width is the number of hex digits used to print the bit mask
 * (4 for a 16-bit field, 8 for a 32-bit field).
 */
static void append_flag_rows(GtkTreeStore *store, GtkTreeIter *parent,
			      uint32_t value, unsigned int nbits,
			      unsigned int width,
			      const char *(*name_fn)(unsigned int))
{
	uint32_t mask = 1;
	unsigned int j;

	for (j = 0; j < nbits; ++j, mask <<= 1) {
		if (value & mask) {
			const char *desc = name_fn(j);
			char property[16];

			snprintf(property, sizeof(property), "0x%0*x", width,
				 mask);
			add_row(store, parent, property,
				desc ? desc : "Unknown");
		}
	}
}

static const char *dll_characteristic_name(unsigned int bit)
{
	if (bit >= 16)
		return NULL;
	return efi_pe_dll_characteristics[bit];
}

/* Section name fields are up to 8 bytes, not necessarily NUL terminated. */
static char *section_name_string(const char name[8])
{
	size_t len = 0;

	while (len < 8 && name[len])
		++len;
	return g_strndup(name, len);
}

gboolean pe_parser_parse_file(const char *path, GtkTreeStore *store,
			       GError **error)
{
	int fd;
	uint32_t pe_offset = 0;
	char pe_sig[4];
	off_t pos, pos_sections;
	struct coff_header coff;
	struct optional_header_standard_fields ohs;
	uint32_t num_tables = 0;
	IMAGE_DATA_DIRECTORY table_list[16];
	GtkTreeIter file_iter, coff_iter, coff_char_iter, ohs_iter;
	GtkTreeIter dir_iters[16];
	GtkTreeIter sections_iter;
	unsigned int i;
	gboolean have_dirs;

	gtk_tree_store_clear(store);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		g_set_error(error, PE_PARSER_ERROR, 0,
			    "Cannot open file: %s", g_strerror(errno));
		return FALSE;
	}

	file_iter = add_row(store, NULL, "File", NULL);
	{
		char *base = g_path_get_basename(path);

		add_row(store, &file_iter, "Name", base);
		g_free(base);
	}

	{
		struct pci_expansion_rom_header rom_hd;

		if (RDS(fd, 0, &rom_hd) && rom_hd.Signature == 0xaa55 &&
		    rom_hd.EfiSignature == 0x0ef1) {
			if (rom_hd.CompressionType) {
				g_set_error(error, PE_PARSER_ERROR, 0,
					    "Compressed image not supported");
				close(fd);
				return FALSE;
			}
			pe_offset = rom_hd.EfiImageHeaderOffset;
			add_row_printf(store, &file_iter,
				       "EFI PCI Expansion ROM Offset",
				       "%u", pe_offset);
		} else {
			uint16_t mz;

			if (!RDS(fd, 0, &mz)) {
				g_set_error(error, PE_PARSER_ERROR, 0,
					    "Cannot read MZ signature");
				close(fd);
				return FALSE;
			}
			if (mz == 0x5a4d) { /* "MZ" */
				if (!RDS(fd, 0x3c, &pe_offset)) {
					g_set_error(error, PE_PARSER_ERROR, 0,
						    "Cannot read PE offset");
					close(fd);
					return FALSE;
				}
			}
		}
	}

	add_row_printf(store, &file_iter, "Offset to PE", "0x%x", pe_offset);

	if (!rds(fd, pe_offset, pe_sig, sizeof(pe_sig)) ||
	    memcmp(pe_sig, "PE\0\0", 4) != 0) {
		g_set_error(error, PE_PARSER_ERROR, 0,
			    "PE signature not found");
		close(fd);
		return FALSE;
	}

	pos = pe_offset + 4;
	if (!RDS(fd, pos, &coff)) {
		g_set_error(error, PE_PARSER_ERROR, 0,
			    "Cannot read COFF header");
		close(fd);
		return FALSE;
	}

	coff_iter = add_row(store, NULL, "COFF Header", NULL);
	{
		const char *name = efi_pe_machine_type_name(coff.Machine);
		char *value = g_strdup_printf("0x%04x, %s", coff.Machine,
					      name ? name : "Unknown");

		add_row(store, &coff_iter, "Machine type", value);
		g_free(value);
	}

	coff_char_iter = add_row_printf(store, &coff_iter, "Characteristics",
					 "0x%04x", coff.Characteristics);
	append_flag_rows(store, &coff_char_iter, coff.Characteristics, 16, 4,
			  efi_pe_characteristic_string);

	pos += sizeof(coff);
	if (!RDS(fd, pos, &ohs)) {
		g_set_error(error, PE_PARSER_ERROR, 0,
			    "Cannot read optional header");
		close(fd);
		return FALSE;
	}

	pos_sections = pos + coff.SizeOfOptionalHeader;
	pos += sizeof(ohs);

	ohs_iter = add_row(store, NULL, "Optional Header", NULL);
	add_row_printf(store, &ohs_iter, "LinkerVersion", "%u.%u",
		       ohs.MajorLinkerVersion, ohs.MinorLinkerVersion);
	add_row_printf(store, &ohs_iter, "BaseOfCode", "0x%x", ohs.BaseOfCode);
	add_row_printf(store, &ohs_iter, "SizeOfCode", "0x%x", ohs.SizeOfCode);
	add_row_printf(store, &ohs_iter, "SizeOfInitializedData", "0x%x",
		       ohs.SizeOfInitializedData);
	add_row_printf(store, &ohs_iter, "SizeOfUninitializedData", "0x%x",
		       ohs.SizeOfUninitializedData);
	add_row_printf(store, &ohs_iter, "AddressOfEntryPoint", "0x%x",
		       ohs.AddressOfEntryPoint);

	if (ohs.Magic == OPTIONAL_HEADER_MAGIC_PE32) {
		struct optional_header_pe32_extra_field ohpx;
		struct optional_header_windows_specific_fields_32 ohw32;
		const char *name;
		GtkTreeIter dll_char_iter;
		IMAGE_DATA_DIRECTORY *tbl_ptr;

		add_row(store, &ohs_iter, "Image type", "PE32");
		RDS(fd, pos, &ohpx);
		pos += sizeof(ohpx);
		RDS(fd, pos, &ohw32);
		pos += sizeof(ohw32);

		name = efi_pe_subsystem_name(ohw32.Subsystem);
		add_row(store, &ohs_iter, "Subsystem",
			name ? name : "Unknown Windows subsystem");

		dll_char_iter = add_row_printf(store, &ohs_iter,
						"DLL Characteristics",
						"0x%04x",
						ohw32.DllCharacteristics);
		append_flag_rows(store, &dll_char_iter,
				  ohw32.DllCharacteristics, 16, 4,
				  dll_characteristic_name);

		add_row_printf(store, &ohs_iter, "ImageBase", "0x%x",
			       ohw32.ImageBase);
		add_row_printf(store, &ohs_iter, "SectionAlignment", "0x%x",
			       ohw32.SectionAlignment);
		add_row_printf(store, &ohs_iter, "FileAlignment", "0x%x",
			       ohw32.FileAlignment);
		add_row_printf(store, &ohs_iter, "SizeOfImage", "0x%x",
			       ohw32.SizeOfImage);

		num_tables = ohw32.NumberOfRvaAndSizes;
		tbl_ptr = &ohw32.ExportTable;
		for (i = 0; i < num_tables && i < 16; ++i)
			table_list[i] = tbl_ptr[i];
	} else if (ohs.Magic == OPTIONAL_HEADER_MAGIC_PE32_PLUS) {
		struct optional_header_windows_specific_fields ohw;
		const char *name;
		GtkTreeIter dll_char_iter;
		IMAGE_DATA_DIRECTORY *tbl_ptr;

		add_row(store, &ohs_iter, "Image type", "PE32+");
		RDS(fd, pos, &ohw);
		pos += sizeof(ohw);

		name = efi_pe_subsystem_name(ohw.Subsystem);
		add_row(store, &ohs_iter, "Subsystem",
			name ? name : "Unknown Windows subsystem");

		dll_char_iter = add_row_printf(store, &ohs_iter,
						"DLL Characteristics",
						"0x%04x",
						ohw.DllCharacteristics);
		append_flag_rows(store, &dll_char_iter,
				  ohw.DllCharacteristics, 16, 4,
				  dll_characteristic_name);

		add_row_printf(store, &ohs_iter, "ImageBase", "0x%llx",
			       (unsigned long long)ohw.ImageBase);
		add_row_printf(store, &ohs_iter, "SectionAlignment", "0x%x",
			       ohw.SectionAlignment);
		add_row_printf(store, &ohs_iter, "FileAlignment", "0x%x",
			       ohw.FileAlignment);
		add_row_printf(store, &ohs_iter, "SizeOfImage", "0x%x",
			       ohw.SizeOfImage);

		num_tables = ohw.NumberOfRvaAndSizes;
		tbl_ptr = &ohw.ExportTable;
		for (i = 0; i < num_tables && i < 16; ++i)
			table_list[i] = tbl_ptr[i];
	} else {
		g_set_error(error, PE_PARSER_ERROR, 0,
			    "Wrong OHS Magic 0x%04x", ohs.Magic);
		close(fd);
		return FALSE;
	}

	have_dirs = num_tables > 0;
	if (have_dirs) {
		GtkTreeIter dirs_iter;
		char *label = g_strdup_printf("Data Directories (%u)",
					       num_tables);

		dirs_iter = add_row(store, NULL, label, NULL);
		g_free(label);

		for (i = 0; i < num_tables && i < 16; ++i) {
			const char *name = efi_pe_data_directory_names[i];
			char *value = g_strdup_printf(
				"0x%08x - 0x%08x",
				table_list[i].VirtualAddress,
				table_list[i].VirtualAddress +
					table_list[i].Size);

			gtk_tree_store_append(store, &dir_iters[i],
					       &dirs_iter);
			gtk_tree_store_set(store, &dir_iters[i],
					    PE_COL_PROPERTY, name,
					    PE_COL_VALUE, value,
					    PE_COL_IS_DATA_DIR, TRUE,
					    PE_COL_RAW_OFFSET, 0,
					    PE_COL_RAW_SIZE,
					    table_list[i].Size,
					    PE_COL_NAME, name,
					    -1);
			g_free(value);
		}
	}

	{
		char *label = g_strdup_printf("Sections (%u)",
					       coff.NumberOfSections);

		sections_iter = add_row(store, NULL, label, NULL);
		g_free(label);
	}

	{
		off_t sec_pos = pos_sections;
		unsigned int sec_no;

		for (sec_no = 0; sec_no < coff.NumberOfSections; ++sec_no) {
			struct section_header sh;
			char *sec_name, *label;
			GtkTreeIter sec_iter, char_iter;
			uint32_t c, align;

			if (!RDS(fd, sec_pos, &sh))
				break;
			sec_pos += sizeof(sh);

			sec_name = section_name_string(sh.Name);
			label = g_strdup_printf("[%u] %s", sec_no, sec_name);

			gtk_tree_store_append(store, &sec_iter,
					       &sections_iter);
			gtk_tree_store_set(store, &sec_iter,
					    PE_COL_PROPERTY, label,
					    PE_COL_IS_SECTION, TRUE,
					    PE_COL_RAW_OFFSET,
					    sh.PointerToRawData,
					    PE_COL_RAW_SIZE, sh.SizeOfRawData,
					    PE_COL_NAME, sec_name,
					    -1);
			g_free(label);

			add_row_printf(store, &sec_iter, "Virtual size",
				       "0x%x", sh.VirtualSize);
			add_row_printf(store, &sec_iter, "Virtual address",
				       "0x%x", sh.VirtualAddress);
			add_row_printf(store, &sec_iter, "Size of raw data",
				       "0x%x", sh.SizeOfRawData);
			add_row_printf(store, &sec_iter,
				       "Pointer to raw data", "0x%x",
				       sh.PointerToRawData);

			c = sh.Characteristics;
			align = c & 0xf00000;
			c &= ~0xf00000u;

			char_iter = add_row_printf(store, &sec_iter,
						    "Characteristics",
						    "0x%08x",
						    sh.Characteristics);
			append_flag_rows(store, &char_iter, c, 32, 8,
					  efi_pe_section_characteristic_string);

			if (align) {
				unsigned int shift = (align >> 20) - 1;
				char *prop = g_strdup_printf(
					"0x%08x",
					sh.Characteristics & 0xf00000);

				add_row_printf(store, &char_iter, prop,
					       "Align data on a %u byte boundary.",
					       1u << shift);
				g_free(prop);
			}

			/* Resolve RVAs for data directories. */
			if (have_dirs) {
				unsigned int j;

				for (j = 0; j < num_tables && j < 16; ++j) {
					uint32_t dir_rva =
						table_list[j].VirtualAddress;
					uint32_t dir_size =
						table_list[j].Size;
					uint32_t offset, available, actual;

					/*
					 * The Certificate Table (index 4)
					 * VirtualAddress is a file offset,
					 * not an RVA.
					 */
					if (j == 4) {
						gtk_tree_store_set(store,
							&dir_iters[j],
							PE_COL_RAW_OFFSET,
							dir_rva,
							PE_COL_RAW_SIZE,
							dir_size, -1);
						continue;
					}

					if (dir_rva < sh.VirtualAddress ||
					    dir_rva >= sh.VirtualAddress +
						       sh.VirtualSize)
						continue;

					offset = dir_rva -
						 sh.VirtualAddress +
						 sh.PointerToRawData;
					if (offset >= sh.PointerToRawData +
						      sh.SizeOfRawData)
						continue;

					available =
						(sh.PointerToRawData +
						 sh.SizeOfRawData) - offset;
					actual = dir_size > available ?
							 available : dir_size;

					gtk_tree_store_set(store,
						&dir_iters[j],
						PE_COL_RAW_OFFSET, offset,
						PE_COL_RAW_SIZE, actual,
						-1);
				}
			}

			g_free(sec_name);
		}
	}

	close(fd);
	return TRUE;
}
