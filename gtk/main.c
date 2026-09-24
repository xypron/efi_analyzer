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

	/*
	 * Use a NULL application ID so GApplication does not try to
	 * register/own a well-known name on the session D-Bus. This app
	 * has no single-instance/D-Bus-activation requirement, and trying
	 * to own "org.efianalyzer.gui" fails under strict snap confinement
	 * unless a "dbus" slot is declared and connected (AppArmor denies
	 * it by default: "... is not allowed to own the service ... due to
	 * AppArmor policy").
	 */
	app = gtk_application_new(NULL, G_APPLICATION_HANDLES_OPEN);
	g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
	g_signal_connect(app, "open", G_CALLBACK(open_files), NULL);

	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);

	return status;
}
