#include "mainwindow.h"
#include <QIcon>
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Setup typical Qt application identity
    QApplication::setApplicationName("EFI Analyzer Qt");
    QApplication::setApplicationVersion("1.0");

    QApplication::setDesktopFileName("efianalyzer-qt.desktop");
    a.setWindowIcon(QIcon(":/efianalyzer.png"));
    QCommandLineParser parser;
    parser.setApplicationDescription("Analyze UEFI binaries");
    parser.addHelpOption();
    parser.addVersionOption();

    // Positional argument for the file
    parser.addPositionalArgument("file", "The EFI file to open.");
    parser.process(a);

    MainWindow w;

    const QStringList args = parser.positionalArguments();
    if (!args.isEmpty()) {
        w.loadCommandLineFile(args.first());
    }

    w.show();

    return a.exec();
}
