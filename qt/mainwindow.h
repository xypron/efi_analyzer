#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <QTreeView>
#include <QCloseEvent>

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void loadCommandLineFile(const QString &filePath);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void openFile();
    void showContextMenu(const QPoint &pos);
    void downloadSection();
    void copyValue();

private:
    void setupUi();
    void loadFile(const QString &filePath);
    void readSettings();
    void writeSettings();

    QTreeView *treeView;
    QStandardItemModel *model;
    QString currentFilePath;
    int m_propertyColumnWidth;
};

#endif // MAINWINDOW_H
