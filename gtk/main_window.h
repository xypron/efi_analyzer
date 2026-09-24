// SPDX-License-Identifier:     BSD-2-Clause

#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <gtk/gtk.h>

#define EFI_ANALYZER_TYPE_MAIN_WINDOW (efi_analyzer_main_window_get_type())

G_DECLARE_FINAL_TYPE(EfiAnalyzerMainWindow, efi_analyzer_main_window,
		      EFI_ANALYZER, MAIN_WINDOW, GtkApplicationWindow)

/**
 * efi_analyzer_main_window_new() - create the main window
 *
 * @app:	application the window belongs to
 * Return:	the new window
 */
EfiAnalyzerMainWindow *efi_analyzer_main_window_new(GtkApplication *app);

/**
 * efi_analyzer_main_window_load_file() - parse and display a file
 *
 * @win:	main window
 * @path:	path of the file to load
 */
void efi_analyzer_main_window_load_file(EfiAnalyzerMainWindow *win,
					 const char *path);

#endif /* MAIN_WINDOW_H */
