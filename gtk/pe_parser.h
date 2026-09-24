// SPDX-License-Identifier:     BSD-2-Clause

#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <gtk/gtk.h>

/*
 * Columns of the GtkTreeStore built by pe_parser_parse_file().
 *
 * PE_COL_PROPERTY and PE_COL_VALUE hold the two visible columns shown
 * by the GtkTreeView (analogous to the "Property"/"Value" columns of
 * the Qt QStandardItemModel).
 *
 * The remaining columns hold metadata needed to save a section or a
 * resolved data directory to a file from the context menu (analogous
 * to the Qt::UserRole+N item data used by qt/pe_parser.cpp).
 */
enum {
	PE_COL_PROPERTY,	/* string:  left column text */
	PE_COL_VALUE,		/* string:  right column text */
	PE_COL_IS_SECTION,	/* boolean: row is a section */
	PE_COL_IS_DATA_DIR,	/* boolean: row is a resolved data directory */
	PE_COL_RAW_OFFSET,	/* uint:    file offset of raw data */
	PE_COL_RAW_SIZE,	/* uint:    size of raw data */
	PE_COL_NAME,		/* string:  section/directory name */
	PE_N_COLS
};

/**
 * pe_parser_parse_file() - parse a PE/COFF/EFI binary into a tree store
 *
 * @path:	path of the file to parse
 * @store:	tree store to fill; any existing content is cleared
 * @error:	set on failure
 * Return:	TRUE on success, FALSE on failure (with @error set)
 */
gboolean pe_parser_parse_file(const char *path, GtkTreeStore *store,
			       GError **error);

#endif /* PE_PARSER_H */
