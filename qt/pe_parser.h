#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <QString>
#include <QStandardItemModel>

class PeParser
{
public:
    PeParser();
    ~PeParser();

    bool parseFile(const QString &filePath, QStandardItemModel *model, QString &errorMsg);

private:
    QString getMachineTypeString(uint16_t machine);
    QString getSubsystemString(uint16_t subsystem);
};

#endif // PE_PARSER_H
