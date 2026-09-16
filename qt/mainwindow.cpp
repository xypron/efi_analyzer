// SPDX-License-Identifier:     BSD-2-Clause

#include "mainwindow.h"
#include "pe_parser.h"

#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QIcon>
#include <QStatusBar>
#include <QSaveFile>
#include <QSettings>
#include <QCloseEvent>
#include <QScreen>
#include <QGuiApplication>
#include <QClipboard>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_propertyColumnWidth(-1)
{
    setupUi();
    readSettings();
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUi()
{
    setWindowTitle(tr("EFI Analyzer"));
    resize(800, 600);

    // Setup Menu
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));

    QAction *openAct = new QAction(QIcon::fromTheme("document-open"), tr("&Open..."), this);
    openAct->setShortcuts(QKeySequence::Open);
    connect(openAct, &QAction::triggered, this, &MainWindow::openFile);
    fileMenu->addAction(openAct);

    fileMenu->addSeparator();

    QAction *quitAct = new QAction(QIcon::fromTheme("application-exit"), tr("&Quit"), this);
    quitAct->setShortcuts(QKeySequence::Quit);
    connect(quitAct, &QAction::triggered, this, &QWidget::close);
    fileMenu->addAction(quitAct);

    // Setup TreeView
    treeView = new QTreeView(this);
    model = new QStandardItemModel(this);
    treeView->setModel(model);
    treeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(treeView, &QTreeView::customContextMenuRequested, this, &MainWindow::showContextMenu);

    // We will expand column 0 to accommodate the output after data is loaded.
    treeView->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    treeView->setAlternatingRowColors(true);
    setCentralWidget(treeView);

    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::openFile()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open EFI Binary"), QString(), tr("EFI Binaries (*.efi);;All Files (*)"));
    if (!fileName.isEmpty()) {
        loadFile(fileName);
    }
}

void MainWindow::loadFile(const QString &filePath)
{
    if (model->columnCount() > 0) {
        m_propertyColumnWidth = treeView->columnWidth(0);
    }

    PeParser parser;
    QString errorMsg;
    if (parser.parseFile(filePath, model, errorMsg)) {
        currentFilePath = filePath;
        treeView->expandAll();

        if (m_propertyColumnWidth > 0) {
            treeView->setColumnWidth(0, m_propertyColumnWidth);
        } else {
            treeView->setColumnWidth(0, treeView->width() / 2);
        }

        statusBar()->showMessage(tr("Loaded: %1").arg(filePath));
    } else {
        QMessageBox::warning(this, tr("Error"), tr("Failed to parse file: %1").arg(errorMsg));
        statusBar()->showMessage(tr("Error loading file"));
    }
}

void MainWindow::showContextMenu(const QPoint &pos)
{
    QModelIndex index = treeView->indexAt(pos);
    if (!index.isValid()) return;

    QStandardItem *item = model->itemFromIndex(index);
    if (!item) return;

    QMenu contextMenu(this);
    bool menuPopulated = false;

    // 1. Check if the user specifically clicked the Value column (column 1)
    if (index.column() == 1) {
        QString cellText = item->text().trimmed();
        if (!cellText.isEmpty()) {
            QAction *copyAct = new QAction(QIcon::fromTheme("edit-copy"), tr("Copy value"), this);
            copyAct->setData(cellText); // Store the string to copy
            connect(copyAct, &QAction::triggered, this, &MainWindow::copyValue);
            contextMenu.addAction(copyAct);
            menuPopulated = true;
        }
    }

    // 2. Download actions (these metadata properties are stored on column 0 items)
    QModelIndex propIndex = index.siblingAtColumn(0);
    QStandardItem *propItem = model->itemFromIndex(propIndex);

    if (propItem) {
        bool isSection = propItem->data(Qt::UserRole + 1).toBool();
        bool isDataDirectory = propItem->data(Qt::UserRole + 5).toBool();
        uint32_t rawSize = propItem->data(Qt::UserRole + 3).toUInt();
        uint32_t rawOffset = propItem->data(Qt::UserRole + 2).toUInt();

        if ((isSection && rawSize > 0) || (isDataDirectory && rawSize > 0 && rawOffset > 0)) {
            if (menuPopulated) {
                contextMenu.addSeparator();
            }
            QString actionText = isSection ? tr("Save section to file...") : tr("Save directory to file...");
            QAction *downloadAct = new QAction(QIcon::fromTheme("document-save"), actionText, this);
            downloadAct->setData(propIndex); // Store the column 0 index so download logic works natively
            connect(downloadAct, &QAction::triggered, this, &MainWindow::downloadSection);
            contextMenu.addAction(downloadAct);
            menuPopulated = true;
        }
    }

    if (menuPopulated) {
        contextMenu.exec(treeView->viewport()->mapToGlobal(pos));
    }
}

void MainWindow::copyValue()
{
    QAction *act = qobject_cast<QAction*>(sender());
    if (!act) return;

    QString textToCopy = act->data().toString();
    if (!textToCopy.isEmpty()) {
        QGuiApplication::clipboard()->setText(textToCopy);
        statusBar()->showMessage(tr("Copied: %1").arg(textToCopy), 3000);
    }
}

void MainWindow::downloadSection()
{
    QAction *act = qobject_cast<QAction*>(sender());
    if (!act) return;

    QModelIndex index = act->data().toModelIndex();
    QStandardItem *item = model->itemFromIndex(index);
    if (!item) return;

    uint32_t rawPtr = item->data(Qt::UserRole + 2).toUInt();
    uint32_t rawSize = item->data(Qt::UserRole + 3).toUInt();
    QString secName = item->data(Qt::UserRole + 4).toString().trimmed();

    if (rawSize == 0) {
        QMessageBox::information(this, tr("Info"), tr("Section %1 has a raw size of 0.").arg(secName));
        return;
    }

    if (currentFilePath.isEmpty()) return;

    QString defaultName = secName;
    defaultName.replace(QRegularExpression("[^a-zA-Z0-9_.-]"), "_");
    bool isDataDir = item->data(Qt::UserRole + 5).toBool();
    QString dialogTitle = isDataDir ? tr("Save Directory") : tr("Save Section");

    QString savePath = QFileDialog::getSaveFileName(this, dialogTitle, defaultName, tr("All Files (*)"));
    if (savePath.isEmpty()) return;

    QFile inFile(currentFilePath);
    if (!inFile.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to open source file."));
        return;
    }

    if (!inFile.seek(rawPtr)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to seek to section data."));
        return;
    }

    QByteArray data = inFile.read(rawSize);
    if (data.size() != static_cast<int>(rawSize)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to read all section data."));
        return;
    }

    QSaveFile outFile(savePath);
    if (!outFile.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to open destination file for writing."));
        return;
    }

    outFile.write(data);
    if (outFile.commit()) {
        statusBar()->showMessage((isDataDir ? tr("Directory saved to: %1") : tr("Section saved to: %1")).arg(savePath));
    } else {
        QMessageBox::warning(this, tr("Error"), tr("Failed to save file."));
    }
}


void MainWindow::readSettings()
{
    QSettings settings("EFIAnalyzerQt", "EFIAnalyzerApp");

    if (settings.contains("columnWidth0")) {
        m_propertyColumnWidth = settings.value("columnWidth0").toInt();
    }

    // First run (or no geometry saved), show full screen initially based on current primary screen
    if (!settings.contains("geometry")) {
        showMaximized();
    } else {
        const QByteArray geometry = settings.value("geometry", QByteArray()).toByteArray();
        if (geometry.isEmpty()) {
            showMaximized();
        } else {
            restoreGeometry(geometry);
        }
    }
}

void MainWindow::writeSettings()
{
    QSettings settings("EFIAnalyzerQt", "EFIAnalyzerApp");
    settings.setValue("geometry", saveGeometry());

    int currentWidth = treeView->columnWidth(0);
    if (currentWidth > 0 && model->columnCount() > 0) {
        settings.setValue("columnWidth0", currentWidth);
    } else if (m_propertyColumnWidth > 0) {
        settings.setValue("columnWidth0", m_propertyColumnWidth);
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    writeSettings();
    event->accept();
}

void MainWindow::loadCommandLineFile(const QString &filePath)
{
    loadFile(filePath);
}
