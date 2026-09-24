// SPDX-License-Identifier:     BSD-2-Clause

#include "main_window.h"

#include <gtk/gtk.h>

static void activate(GtkApplication *app, gpointer user_data)
{
	(void)user_data;
	efi_analyzer_main_window_new(app);
}

static void open_files(GtkApplication *app, GFile **files, gint n_files,
			const char *hint, gpointer user_data)
{
	EfiAnalyzerMainWindow *win;
	int i;

	(void)hint;
	(void)user_data;

	win = efi_analyzer_main_window_new(app);
	for (i = 0; i < n_files; ++i) {
		char *path = g_file_get_path(files[i]);

		if (path)
			efi_analyzer_main_window_load_file(win, path);
		g_free(path);
	}
}

int main(int argc, char *argv[])
{
	GtkApplication *app;
	int status;

	app = gtk_application_new("org.efianalyzer.gtk",
				   G_APPLICATION_HANDLES_OPEN);
	g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
	g_signal_connect(app, "open", G_CALLBACK(open_files), NULL);

	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);

	return status;
}
