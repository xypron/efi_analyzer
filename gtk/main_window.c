// SPDX-License-Identifier:     BSD-2-Clause

#include "main_window.h"
#include "pe_parser.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

struct _EfiAnalyzerMainWindow {
	GtkApplicationWindow parent_instance;

	GtkWidget *tree_view;
	GtkTreeStore *store;
	GtkWidget *status_bar;
	guint status_context_id;
	char *current_file_path;
	int property_column_width;
};

G_DEFINE_TYPE(EfiAnalyzerMainWindow, efi_analyzer_main_window,
	      GTK_TYPE_APPLICATION_WINDOW)

static void load_file(EfiAnalyzerMainWindow *win, const char *path);
static char *config_file_path(void);
static void read_settings(EfiAnalyzerMainWindow *win);
static void write_settings(EfiAnalyzerMainWindow *win);

/* ---- File > Open ------------------------------------------------- */

static void on_open_response(GtkDialog *dialog, gint response,
			      gpointer user_data)
{
	EfiAnalyzerMainWindow *win = user_data;

	if (response == GTK_RESPONSE_ACCEPT) {
		char *path = gtk_file_chooser_get_filename(
			GTK_FILE_CHOOSER(dialog));

		load_file(win, path);
		g_free(path);
	}
	gtk_widget_destroy(GTK_WIDGET(dialog));
}

static void action_open(GSimpleAction *action, GVariant *parameter,
			 gpointer user_data)
{
	EfiAnalyzerMainWindow *win = user_data;
	GtkWidget *dialog;
	GtkFileFilter *filter;

	(void)action;
	(void)parameter;

	dialog = gtk_file_chooser_dialog_new(
		"Open EFI Binary", GTK_WINDOW(win),
		GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel",
		GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);

	filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "EFI Binaries (*.efi)");
	gtk_file_filter_add_pattern(filter, "*.efi");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

	filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "All Files");
	gtk_file_filter_add_pattern(filter, "*");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

	g_signal_connect(dialog, "response",
			  G_CALLBACK(on_open_response), win);
	gtk_widget_show(dialog);
}

static void action_quit(GSimpleAction *action, GVariant *parameter,
			 gpointer user_data)
{
	EfiAnalyzerMainWindow *win = user_data;

	(void)action;
	(void)parameter;
	gtk_window_close(GTK_WINDOW(win));
}

/* ---- Context menu: copy value ------------------------------------ */

static void copy_value_activated(GtkMenuItem *item, gpointer user_data)
{
	const char *text = user_data;
	GtkClipboard *clipboard;

	(void)item;
	clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	gtk_clipboard_set_text(clipboard, text, -1);
}

static void free_string_closure(gpointer data, GClosure *closure)
{
	(void)closure;
	g_free(data);
}

/* ---- Context menu: save section/directory ------------------------- */

struct save_info {
	EfiAnalyzerMainWindow *win;
	guint32 raw_offset;
	guint32 raw_size;
	char *name;
	gboolean is_data_dir;
};

static void save_info_free(struct save_info *info)
{
	g_free(info->name);
	g_free(info);
}

static void on_save_response(GtkDialog *dialog, gint response,
			      gpointer user_data)
{
	struct save_info *info = user_data;

	if (response == GTK_RESPONSE_ACCEPT) {
		char *save_path = gtk_file_chooser_get_filename(
			GTK_FILE_CHOOSER(dialog));
		int in_fd, out_fd;
		char *buf;
		ssize_t n;

		in_fd = open(info->win->current_file_path, O_RDONLY);
		if (in_fd == -1) {
			GtkWidget *msg = gtk_message_dialog_new(
				GTK_WINDOW(info->win), GTK_DIALOG_MODAL,
				GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
				"Failed to open source file.");
			gtk_dialog_run(GTK_DIALOG(msg));
			gtk_widget_destroy(msg);
			g_free(save_path);
			goto out;
		}

		buf = g_malloc(info->raw_size);
		n = pread(in_fd, buf, info->raw_size, info->raw_offset);
		close(in_fd);
		if (n != (ssize_t)info->raw_size) {
			GtkWidget *msg = gtk_message_dialog_new(
				GTK_WINDOW(info->win), GTK_DIALOG_MODAL,
				GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
				"Failed to read all section data.");
			gtk_dialog_run(GTK_DIALOG(msg));
			gtk_widget_destroy(msg);
			g_free(buf);
			g_free(save_path);
			goto out;
		}

		out_fd = open(save_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (out_fd == -1 ||
		    write(out_fd, buf, info->raw_size) !=
			    (ssize_t)info->raw_size) {
			GtkWidget *msg = gtk_message_dialog_new(
				GTK_WINDOW(info->win), GTK_DIALOG_MODAL,
				GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
				"Failed to save file.");
			gtk_dialog_run(GTK_DIALOG(msg));
			gtk_widget_destroy(msg);
		} else {
			char *msg_text = g_strdup_printf(
				info->is_data_dir ?
					"Directory saved to: %s" :
					"Section saved to: %s",
				save_path);

			gtk_statusbar_pop(
				GTK_STATUSBAR(info->win->status_bar),
				info->win->status_context_id);
			gtk_statusbar_push(
				GTK_STATUSBAR(info->win->status_bar),
				info->win->status_context_id, msg_text);
			g_free(msg_text);
		}
		if (out_fd != -1)
			close(out_fd);
		g_free(buf);
		g_free(save_path);
	}
out:
	gtk_widget_destroy(GTK_WIDGET(dialog));
	save_info_free(info);
}

static void save_section_activated(GtkMenuItem *item, gpointer user_data)
{
	struct save_info *info = user_data;
	GtkWidget *dialog;
	char *default_name;
	unsigned int i;

	(void)item;

	if (info->raw_size == 0) {
		GtkWidget *msg = gtk_message_dialog_new(
			GTK_WINDOW(info->win), GTK_DIALOG_MODAL,
			GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
			"%s has a raw size of 0.", info->name);
		gtk_dialog_run(GTK_DIALOG(msg));
		gtk_widget_destroy(msg);
		save_info_free(info);
		return;
	}

	if (!info->win->current_file_path) {
		save_info_free(info);
		return;
	}

	default_name = g_strdup(info->name);
	for (i = 0; default_name[i]; ++i) {
		char c = default_name[i];

		if (!g_ascii_isalnum(c) && c != '_' && c != '.' && c != '-')
			default_name[i] = '_';
	}

	dialog = gtk_file_chooser_dialog_new(
		info->is_data_dir ? "Save Directory" : "Save Section",
		GTK_WINDOW(info->win), GTK_FILE_CHOOSER_ACTION_SAVE,
		"_Cancel", GTK_RESPONSE_CANCEL, "_Save",
		GTK_RESPONSE_ACCEPT, NULL);
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog),
					   default_name);
	g_free(default_name);

	g_signal_connect(dialog, "response",
			  G_CALLBACK(on_save_response), info);
	gtk_widget_show(dialog);
}

/* ---- Tree view context menu --------------------------------------- */

static gboolean on_button_press(GtkWidget *widget, GdkEventButton *event,
				 gpointer user_data)
{
	EfiAnalyzerMainWindow *win = user_data;
	GtkTreeView *tv = GTK_TREE_VIEW(widget);
	GtkTreePath *path = NULL;
	GtkTreeViewColumn *column = NULL;
	GtkTreeIter iter;
	GtkMenu *menu;
	gboolean has_entry = FALSE;

	if (event->type != GDK_BUTTON_PRESS || event->button != 3)
		return FALSE;

	if (!gtk_tree_view_get_path_at_pos(tv, (gint)event->x, (gint)event->y,
					    &path, &column, NULL, NULL))
		return FALSE;

	if (!gtk_tree_model_get_iter(GTK_TREE_MODEL(win->store), &iter,
				     path)) {
		gtk_tree_path_free(path);
		return FALSE;
	}

	menu = GTK_MENU(gtk_menu_new());

	/* Column 1 is the Value column. */
	if (column == gtk_tree_view_get_column(tv, 1)) {
		char *value;

		gtk_tree_model_get(GTK_TREE_MODEL(win->store), &iter,
				    PE_COL_VALUE, &value, -1);
		if (value && *g_strstrip(value)) {
			GtkWidget *mi = gtk_menu_item_new_with_label(
				"Copy value");

			g_signal_connect_data(
				mi, "activate",
				G_CALLBACK(copy_value_activated),
				g_strdup(value), free_string_closure, 0);
			gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
			has_entry = TRUE;
		}
		g_free(value);
	}

	{
		gboolean is_section = FALSE, is_dir = FALSE;
		guint32 raw_offset = 0, raw_size = 0;
		char *name = NULL;

		gtk_tree_model_get(GTK_TREE_MODEL(win->store), &iter,
				    PE_COL_IS_SECTION, &is_section,
				    PE_COL_IS_DATA_DIR, &is_dir,
				    PE_COL_RAW_OFFSET, &raw_offset,
				    PE_COL_RAW_SIZE, &raw_size,
				    PE_COL_NAME, &name, -1);
		if (is_section || is_dir) {
			GtkWidget *mi = gtk_menu_item_new_with_label(
				is_dir ? "Save directory to file..." :
					 "Save section to file...");
			struct save_info *info = g_new0(struct save_info, 1);

			info->win = win;
			info->raw_offset = raw_offset;
			info->raw_size = raw_size;
			info->name = g_strdup(name ? name : "");
			info->is_data_dir = is_dir;

			g_signal_connect(mi, "activate",
					  G_CALLBACK(save_section_activated),
					  info);
			gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
			has_entry = TRUE;
		}
		g_free(name);
	}

	gtk_tree_path_free(path);

	if (!has_entry) {
		gtk_widget_destroy(GTK_WIDGET(menu));
		return FALSE;
	}

	gtk_widget_show_all(GTK_WIDGET(menu));
	gtk_menu_popup_at_pointer(menu, (GdkEvent *)event);
	return TRUE;
}

/* ---- Load a file --------------------------------------------------- */

static void expand_all_rows(GtkTreeView *tv)
{
	gtk_tree_view_expand_all(tv);
}

static void load_file(EfiAnalyzerMainWindow *win, const char *path)
{
	GError *error = NULL;
	GtkTreeViewColumn *col0;

	col0 = gtk_tree_view_get_column(GTK_TREE_VIEW(win->tree_view), 0);
	if (col0)
		win->property_column_width =
			gtk_tree_view_column_get_width(col0);

	if (pe_parser_parse_file(path, win->store, &error)) {
		char *msg;

		g_free(win->current_file_path);
		win->current_file_path = g_strdup(path);

		expand_all_rows(GTK_TREE_VIEW(win->tree_view));

		if (win->property_column_width > 0 && col0)
			gtk_tree_view_column_set_fixed_width(
				col0, win->property_column_width);

		msg = g_strdup_printf("Loaded: %s", path);
		gtk_statusbar_pop(GTK_STATUSBAR(win->status_bar),
				   win->status_context_id);
		gtk_statusbar_push(GTK_STATUSBAR(win->status_bar),
				    win->status_context_id, msg);
		g_free(msg);
	} else {
		GtkWidget *dialog = gtk_message_dialog_new(
			GTK_WINDOW(win), GTK_DIALOG_MODAL,
			GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
			"Failed to parse file: %s",
			error ? error->message : "unknown error");

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		g_clear_error(&error);

		gtk_statusbar_pop(GTK_STATUSBAR(win->status_bar),
				   win->status_context_id);
		gtk_statusbar_push(GTK_STATUSBAR(win->status_bar),
				    win->status_context_id,
				    "Error loading file");
	}
}

void efi_analyzer_main_window_load_file(EfiAnalyzerMainWindow *win,
					 const char *path)
{
	load_file(win, path);
}

/* ---- Settings persistence ------------------------------------------ */

static char *config_file_path(void)
{
	char *dir = g_build_filename(g_get_user_config_dir(),
				      "efianalyze-gui", NULL);

	g_mkdir_with_parents(dir, 0700);
	{
		char *path = g_build_filename(dir, "config.ini", NULL);

		g_free(dir);
		return path;
	}
}

static void read_settings(EfiAnalyzerMainWindow *win)
{
	GKeyFile *kf = g_key_file_new();
	char *path = config_file_path();
	gint width = -1, height = -1, colwidth = -1;
	gboolean loaded;

	loaded = g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL);
	g_free(path);

	if (loaded) {
		GError *err = NULL;

		width = g_key_file_get_integer(kf, "window", "width", &err);
		g_clear_error(&err);
		height = g_key_file_get_integer(kf, "window", "height", &err);
		g_clear_error(&err);
		colwidth = g_key_file_get_integer(kf, "window",
						   "column_width", &err);
		g_clear_error(&err);
	}
	g_key_file_free(kf);

	if (colwidth > 0) {
		GtkTreeViewColumn *col0 = gtk_tree_view_get_column(
			GTK_TREE_VIEW(win->tree_view), 0);

		win->property_column_width = colwidth;
		/*
		 * Restore the width the column had when the window was
		 * last closed. The column stays resizable by the user
		 * (set in setup_ui()); this only sets its starting width.
		 */
		if (col0)
			gtk_tree_view_column_set_fixed_width(col0, colwidth);
	}

	if (width > 0 && height > 0)
		gtk_window_set_default_size(GTK_WINDOW(win), width, height);
	else
		gtk_window_maximize(GTK_WINDOW(win));
}

static void write_settings(EfiAnalyzerMainWindow *win)
{
	GKeyFile *kf = g_key_file_new();
	char *path = config_file_path();
	gint width, height;
	GtkTreeViewColumn *col0 = gtk_tree_view_get_column(
		GTK_TREE_VIEW(win->tree_view), 0);

	/* Pick up the column's current width, even if it was resized
	 * by the user after the last file was loaded. */
	if (col0) {
		gint w = gtk_tree_view_column_get_width(col0);

		if (w > 0)
			win->property_column_width = w;
	}

	gtk_window_get_size(GTK_WINDOW(win), &width, &height);
	g_key_file_set_integer(kf, "window", "width", width);
	g_key_file_set_integer(kf, "window", "height", height);

	if (win->property_column_width > 0)
		g_key_file_set_integer(kf, "window", "column_width",
					win->property_column_width);

	g_key_file_save_to_file(kf, path, NULL);
	g_free(path);
	g_key_file_free(kf);
}

static gboolean on_delete_event(GtkWidget *widget, GdkEvent *event,
				 gpointer user_data)
{
	(void)event;
	(void)user_data;
	write_settings(EFI_ANALYZER_MAIN_WINDOW(widget));
	return FALSE;
}

/* ---- Widget setup --------------------------------------------------- */

static const GActionEntry win_actions[] = {
	{ .name = "open", .activate = action_open },
	{ .name = "quit", .activate = action_quit },
};

static void setup_ui(EfiAnalyzerMainWindow *win)
{
	GtkWidget *grid;
	GtkWidget *menu_bar, *file_menu, *file_item;
	GtkWidget *open_item, *sep, *quit_item;
	GtkWidget *scrolled;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;

	gtk_window_set_title(GTK_WINDOW(win), "EFI Analyzer");
	gtk_window_set_default_size(GTK_WINDOW(win), 800, 600);

	g_action_map_add_action_entries(G_ACTION_MAP(win), win_actions,
					 G_N_ELEMENTS(win_actions), win);

	grid = gtk_grid_new();
	gtk_orientable_set_orientation(GTK_ORIENTABLE(grid),
					GTK_ORIENTATION_VERTICAL);
	gtk_container_add(GTK_CONTAINER(win), grid);

	/* Menu bar */
	menu_bar = gtk_menu_bar_new();
	file_menu = gtk_menu_new();

	open_item = gtk_menu_item_new_with_mnemonic("_Open...");
	gtk_actionable_set_action_name(GTK_ACTIONABLE(open_item), "win.open");
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), open_item);

	sep = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), sep);

	quit_item = gtk_menu_item_new_with_mnemonic("_Quit");
	gtk_actionable_set_action_name(GTK_ACTIONABLE(quit_item), "win.quit");
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), quit_item);

	file_item = gtk_menu_item_new_with_mnemonic("_File");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item), file_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), file_item);

	gtk_grid_attach(GTK_GRID(grid), menu_bar, 0, 0, 1, 1);

	/* Tree view */
	win->store = gtk_tree_store_new(
		PE_N_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN,
		G_TYPE_BOOLEAN, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING);

	win->tree_view = gtk_tree_view_new_with_model(
		GTK_TREE_MODEL(win->store));
	gtk_tree_view_set_enable_search(GTK_TREE_VIEW(win->tree_view), TRUE);
	gtk_widget_add_events(win->tree_view, GDK_BUTTON_PRESS_MASK);
	g_signal_connect(win->tree_view, "button-press-event",
			  G_CALLBACK(on_button_press), win);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		"Property", renderer, "text", PE_COL_PROPERTY, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_fixed_width(col, 400);
	gtk_tree_view_append_column(GTK_TREE_VIEW(win->tree_view), col);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		"Value", renderer, "text", PE_COL_VALUE, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(win->tree_view), col);

	scrolled = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled), win->tree_view);
	gtk_widget_set_hexpand(scrolled, TRUE);
	gtk_widget_set_vexpand(scrolled, TRUE);
	gtk_grid_attach(GTK_GRID(grid), scrolled, 0, 1, 1, 1);

	/* Status bar */
	win->status_bar = gtk_statusbar_new();
	win->status_context_id = gtk_statusbar_get_context_id(
		GTK_STATUSBAR(win->status_bar), "main");
	gtk_statusbar_push(GTK_STATUSBAR(win->status_bar),
			    win->status_context_id, "Ready");
	gtk_grid_attach(GTK_GRID(grid), win->status_bar, 0, 2, 1, 1);

	g_signal_connect(win, "delete-event",
			  G_CALLBACK(on_delete_event), NULL);
}

static void efi_analyzer_main_window_dispose(GObject *object)
{
	EfiAnalyzerMainWindow *win = EFI_ANALYZER_MAIN_WINDOW(object);

	g_free(win->current_file_path);
	win->current_file_path = NULL;

	G_OBJECT_CLASS(efi_analyzer_main_window_parent_class)
		->dispose(object);
}

static void efi_analyzer_main_window_class_init(
	EfiAnalyzerMainWindowClass *klass)
{
	G_OBJECT_CLASS(klass)->dispose = efi_analyzer_main_window_dispose;
}

static void efi_analyzer_main_window_init(EfiAnalyzerMainWindow *win)
{
	win->property_column_width = -1;
	win->current_file_path = NULL;
	setup_ui(win);
	read_settings(win);
	gtk_widget_show_all(GTK_WIDGET(win));
}

EfiAnalyzerMainWindow *efi_analyzer_main_window_new(GtkApplication *app)
{
	return g_object_new(EFI_ANALYZER_TYPE_MAIN_WINDOW, "application",
			     app, NULL);
}
