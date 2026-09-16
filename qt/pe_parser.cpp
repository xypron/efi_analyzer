#include "pe_parser.h"

#include <QFile>
#include <QDataStream>
#include <QFileInfo>
#include <QList>

#define IMAGE_FILE_MACHINE_I386		0x014c
#define IMAGE_FILE_MACHINE_AMD64	0x8664
#define IMAGE_FILE_MACHINE_IA64		0x0200
#define IMAGE_FILE_MACHINE_ARM		0x01c0
#define IMAGE_FILE_MACHINE_THUMB	0x01c2
#define IMAGE_FILE_MACHINE_ARMNT	0x01c4
#define IMAGE_FILE_MACHINE_EBC		0x0ebc
#define IMAGE_FILE_MACHINE_ARM64	0xaa64
#define IMAGE_FILE_MACHINE_RISCV32	0x5032
#define IMAGE_FILE_MACHINE_RISCV64	0x5064
#define IMAGE_FILE_MACHINE_RISCV128	0x5128
#define IMAGE_FILE_MACHINE_LOONGARCH32	0x6232
#define IMAGE_FILE_MACHINE_LOONGARCH64	0x6264

#define IMAGE_SUBSYSTEM_EFI_APPLICATION		10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER	12
#define IMAGE_SUBSYSTEM_EFI_ROM			13

#define OPTIONAL_HEADER_MAGIC_PE32	0x010b
#define OPTIONAL_HEADER_MAGIC_PE32_PLUS	0x020b

struct IMAGE_DATA_DIRECTORY {
uint32_t VirtualAddress;
uint32_t Size;
};

struct coff_header {
uint16_t Machine;
uint16_t NumberOfSections;
uint32_t TimeDateStamp;
uint32_t PointerToSymbolTable;
uint32_t NumberOfSymbols;
uint16_t SizeOfOptionalHeader;
uint16_t Characteristics;
};

struct optional_header_standard_fields {
uint16_t Magic;
uint8_t MajorLinkerVersion;
uint8_t MinorLinkerVersion;
uint32_t SizeOfCode;
uint32_t SizeOfInitializedData;
uint32_t SizeOfUninitializedData;
uint32_t AddressOfEntryPoint;
uint32_t BaseOfCode;
};

struct optional_header_pe32_extra_field {
uint32_t BaseOfData;
};

struct optional_header_windows_specific_fields_32 {
uint32_t ImageBase;
uint32_t SectionAlignment;
uint32_t FileAlignment;
uint16_t MajorOperatingSystemVersion;
uint16_t MinorOperatingSystemVersion;
uint16_t MajorImageVersion;
uint16_t MinorImageVersion;
uint16_t MajorSubsystemVersion;
uint16_t MinorSubsystemVersion;
uint32_t Win32VersionValue;
uint32_t SizeOfImage;
uint32_t SizeOfHeaders;
uint32_t CheckSum;
uint16_t Subsystem;
uint16_t DllCharacteristics;
uint32_t SizeOfStackReserver;
uint32_t SizeOfStackCommit;
uint32_t SizeOfHeapReserve;
uint32_t SizeOfHeapCommit;
uint32_t LoaderFlags;
uint32_t NumberOfRvaAndSizes;
IMAGE_DATA_DIRECTORY ExportTable;
IMAGE_DATA_DIRECTORY ImportTable;
IMAGE_DATA_DIRECTORY ResourceTable;
IMAGE_DATA_DIRECTORY ExceptionTable;
IMAGE_DATA_DIRECTORY CertificateTable;
IMAGE_DATA_DIRECTORY BaseRelocationTable;
IMAGE_DATA_DIRECTORY Debug;
IMAGE_DATA_DIRECTORY Architecture;
IMAGE_DATA_DIRECTORY GlobalPtr;
IMAGE_DATA_DIRECTORY TLSTable;
IMAGE_DATA_DIRECTORY LoadConfigTable;
IMAGE_DATA_DIRECTORY BoundImport;
IMAGE_DATA_DIRECTORY IAT;
IMAGE_DATA_DIRECTORY DelayImportDescriptor;
IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
IMAGE_DATA_DIRECTORY Reserved;
};

struct optional_header_windows_specific_fields {
uint64_t ImageBase;
uint32_t SectionAlignment;
uint32_t FileAlignment;
uint16_t MajorOperatingSystemVersion;
uint16_t MinorOperatingSystemVersion;
uint16_t MajorImageVersion;
uint16_t MinorImageVersion;
uint16_t MajorSubsystemVersion;
uint16_t MinorSubsystemVersion;
uint32_t Win32VersionValue;
uint32_t SizeOfImage;
uint32_t SizeOfHeaders;
uint32_t CheckSum;
uint16_t Subsystem;
uint16_t DllCharacteristics;
uint64_t SizeOfStackReserver;
uint64_t SizeOfStackCommit;
uint64_t SizeOfHeapReserve;
uint64_t SizeOfHeapCommit;
uint32_t LoaderFlags;
uint32_t NumberOfRvaAndSizes;
IMAGE_DATA_DIRECTORY ExportTable;
IMAGE_DATA_DIRECTORY ImportTable;
IMAGE_DATA_DIRECTORY ResourceTable;
IMAGE_DATA_DIRECTORY ExceptionTable;
IMAGE_DATA_DIRECTORY CertificateTable;
IMAGE_DATA_DIRECTORY BaseRelocationTable;
IMAGE_DATA_DIRECTORY Debug;
IMAGE_DATA_DIRECTORY Architecture;
IMAGE_DATA_DIRECTORY GlobalPtr;
IMAGE_DATA_DIRECTORY TLSTable;
IMAGE_DATA_DIRECTORY LoadConfigTable;
IMAGE_DATA_DIRECTORY BoundImport;
IMAGE_DATA_DIRECTORY IAT;
IMAGE_DATA_DIRECTORY DelayImportDescriptor;
IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
IMAGE_DATA_DIRECTORY Reserved;
};

struct section_header {
char Name[8];
uint32_t VirtualSize;
uint32_t VirtualAddress;
uint32_t SizeOfRawData;
uint32_t PointerToRawData;
uint32_t PointerToRelocations;
uint32_t PointerToLinenumbers;
uint16_t NumberOfRelocations;
uint16_t NumberOfLinenumbers;
uint32_t Characteristics;
};

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

template<typename T>
bool rds(QFile &file, qint64 pos, T &data) {
    if (!file.seek(pos)) return false;
    qint64 readBytes = file.read(reinterpret_cast<char*>(&data), sizeof(T));
    return readBytes == sizeof(T);
}


static const char * const section_characteristics[] = {
"Reserved.",
"Reserved.",
"Reserved.",
"The section should not be padded to the next boundary.",
"Reserved.",
"The section contains executable code.",
"The section contains initialized data.",
"The section contains uninitialized data.",
"Reserved.",
"The section contains comments or other information.",
"Reserved.",
"The section will not become part of the image.",
"The section contains COMDAT data.",
"Reserved.",
"Reset speculative exceptions handling bits in the TLB entries.",
"The section contains data referenced through the global pointer.",
"Reserved.",
"Reserved.",
"Reserved.",
"Reserved.",
"Align data on a 1-byte boundary.",
"Align data on a 2-byte boundary.",
"Align data on a 8-byte boundary.",
"Align data on a 128-byte boundary.",
"The section contains extended relocations.",
"The section can be discarded as needed.",
"The section cannot be cached.",
"The section cannot be paged.",
"The section can be shared in memory.",
"The section can be executed as code.",
"The section can be read.",
"The section can be written to.",
};


static const char * const characteristic_strings[] = {
"Relocation information was stripped from the file.",
"The file is executable.",
"COFF line numbers were stripped from the file.",
"COFF symbol table entries were stripped from file.",
"Aggressively trim the working set. This value is obsolete.",
"The application can handle addresses larger than 2 GiB.",
"Use of this flag is reserved for future use.",
"Little endian: LSB precedes MSB in memory.",
"The computer supports 32-bit words.",
"Debugging information was removed.",
"If the image is on removable media, copy and run from swap file.",
"If the image is on the network, copy and run from swap file.",
"The image is a system file.",
"The image is a dynamic link library (DLL).",
"The file should be run only on a uniprocessor computer.",
"Big endian: MSB precedes LSB in memory.",
};

static const char * const dll_characteristics[] = {
"Reserved.",
"Reserved.",
"Reserved.",
"Reserved.",
"Reserved.",
"Image can handle a high entropy 64-bit virtual address space.",
"DLL can be relocated at load time.",
"Code Integrity checks are enforced.",
"Image is NX compatible.",
"Isolation aware, but do not isolate the image.",
"Does not use structured exception (SE) handling.",
"Do not bind the image.",
"Image must execute in an AppContainer.",
"A WDM driver.",
"Image supports Control Flow Guard.",
"Terminal Server aware.",
};

PeParser::PeParser() {}
PeParser::~PeParser() {}

QString PeParser::getMachineTypeString(uint16_t machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386: return "0x014c, x86 32-bit";
        case IMAGE_FILE_MACHINE_AMD64: return "0x8664, AMD64 64-bit";
        case IMAGE_FILE_MACHINE_IA64: return "0x0200, Itanium";
        case IMAGE_FILE_MACHINE_ARM: return "0x01c0, ARM";
        case IMAGE_FILE_MACHINE_THUMB: return "0x01c2, ARM Thumb";
        case IMAGE_FILE_MACHINE_ARMNT: return "0x01c4, ARMv7";
        case IMAGE_FILE_MACHINE_EBC: return "0x0ebc, EFI Byte Code";
        case IMAGE_FILE_MACHINE_ARM64: return "0xaa64, ARM64";
        case IMAGE_FILE_MACHINE_RISCV32: return "0x5032, RISC-V 32-bit";
        case IMAGE_FILE_MACHINE_RISCV64: return "0x5064, RISC-V 64-bit";
        case IMAGE_FILE_MACHINE_RISCV128: return "0x5128, RISC-V 128-bit";
        case IMAGE_FILE_MACHINE_LOONGARCH32: return "0x6232, LoongArch 32-bit";
        case IMAGE_FILE_MACHINE_LOONGARCH64: return "0x6264, LoongArch 64-bit";
        default: return QString("0x%1, Unknown").arg(machine, 4, 16, QChar('0'));
    }
}

QString PeParser::getSubsystemString(uint16_t subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI boot service driver";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "EFI runtime driver";
        case IMAGE_SUBSYSTEM_EFI_ROM: return "EFI ROM image";
        default: return QString("Unknown subsystem %1").arg(subsystem);
    }
}

bool PeParser::parseFile(const QString &filePath, QStandardItemModel *model, QString &errorMsg) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        errorMsg = "Cannot open file: " + file.errorString();
        return false;
    }

    model->clear();
    model->setHorizontalHeaderLabels({"Property", "Value"});

    QStandardItem *rootItem = model->invisibleRootItem();

    QStandardItem *fileNode = new QStandardItem("File");
    fileNode->setEditable(false);
    QStandardItem *fileValNode = new QStandardItem();
    fileValNode->setEditable(false);
    fileNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Name") << new QStandardItem(QFileInfo(filePath).fileName()));
    rootItem->appendRow(QList<QStandardItem*>() << fileNode << fileValNode);

    uint32_t pe_offset = 0;

    pci_expansion_rom_header rom_hd;
    if (rds(file, 0, rom_hd) && rom_hd.Signature == 0xaa55 && rom_hd.EfiSignature == 0x0ef1) {
        if (rom_hd.CompressionType) {
            errorMsg = "Compressed image not supported";
            return false;
        }
        pe_offset = rom_hd.EfiImageHeaderOffset;
        fileNode->appendRow(QList<QStandardItem*>() << new QStandardItem("EFI PCI Expansion ROM Offset") << new QStandardItem(QString::number(pe_offset)));
    } else {
        uint16_t mz;
        if (!rds(file, 0, mz)) {
            errorMsg = "Cannot read MZ signature";
            return false;
        }
        if (mz == 0x5a4d) { // "MZ"
            if (!rds(file, 0x3c, pe_offset)) {
                errorMsg = "Cannot read PE offset";
                return false;
            }
        }
    }

    fileNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Offset to PE") << new QStandardItem(QString("0x%1").arg(pe_offset, 0, 16)));

    char pe_sig[4];
    if (!rds(file, pe_offset, pe_sig) || qstrncmp(pe_sig, "PE\0\0", 4) != 0) {
        errorMsg = "PE signature not found";
        return false;
    }

    qint64 pos = pe_offset + 4;
    coff_header coff;
    if (!rds(file, pos, coff)) {
        errorMsg = "Cannot read COFF header";
        return false;
    }

    QStandardItem *coffNode = new QStandardItem("COFF Header");
    coffNode->setEditable(false);
    QStandardItem *coffValNode = new QStandardItem();
    coffValNode->setEditable(false);
    rootItem->appendRow(QList<QStandardItem*>() << coffNode << coffValNode);

    coffNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Machine type") << new QStandardItem(getMachineTypeString(coff.Machine)));
    QStandardItem *coffCharNode = new QStandardItem("Characteristics");
    coffCharNode->setEditable(false);
    QStandardItem *coffCharValNode = new QStandardItem();
    coffCharValNode->setEditable(false);
    uint32_t mask = 1;
    for (unsigned int j = 0; j < 16; ++j, mask <<= 1) {
        if (coff.Characteristics & mask) {
            QString desc = QString::fromLatin1(characteristic_strings[j]);
            if (desc != "Reserved." && !desc.startsWith("Use of this flag is reserved")) {
                coffCharNode->appendRow(QList<QStandardItem*>() << new QStandardItem(QString("0x%1").arg(mask, 4, 16, QChar('0'))) << new QStandardItem(desc));
            }
        }
    }
    coffCharValNode->setText(QString("0x%1").arg(coff.Characteristics, 4, 16, QChar('0')));
    coffNode->appendRow(QList<QStandardItem*>() << coffCharNode << coffCharValNode);

    pos += sizeof(coff);
    optional_header_standard_fields ohs;
    if (!rds(file, pos, ohs)) {
        errorMsg = "Cannot read optional header";
        return false;
    }

    qint64 pos_sections = pos + coff.SizeOfOptionalHeader;
    pos += sizeof(ohs);

    QStandardItem *ohsNode = new QStandardItem("Optional Header");
    ohsNode->setEditable(false);
    QStandardItem *ohsValNode = new QStandardItem();
    ohsValNode->setEditable(false);
    rootItem->appendRow(QList<QStandardItem*>() << ohsNode << ohsValNode);

    ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("LinkerVersion") << new QStandardItem(QString("%1.%2").arg(ohs.MajorLinkerVersion).arg(ohs.MinorLinkerVersion)));
    ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("BaseOfCode") << new QStandardItem(QString("0x%1").arg(ohs.BaseOfCode, 0, 16)));
    ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SizeOfCode") << new QStandardItem(QString("0x%1").arg(ohs.SizeOfCode, 0, 16)));
    ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SizeOfInitializedData") << new QStandardItem(QString("0x%1").arg(ohs.SizeOfInitializedData, 0, 16)));
    ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SizeOfUninitializedData") << new QStandardItem(QString("0x%1").arg(ohs.SizeOfUninitializedData, 0, 16)));
    ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("AddressOfEntryPoint") << new QStandardItem(QString("0x%1").arg(ohs.AddressOfEntryPoint, 0, 16)));

    uint32_t num_tables = 0;
    QList<IMAGE_DATA_DIRECTORY> tableList;

    if (ohs.Magic == OPTIONAL_HEADER_MAGIC_PE32) {
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Image type") << new QStandardItem("PE32"));
        optional_header_pe32_extra_field ohpx;
        rds(file, pos, ohpx); pos += sizeof(ohpx);

        optional_header_windows_specific_fields_32 ohw32;
        rds(file, pos, ohw32); pos += sizeof(ohw32);

        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Subsystem") << new QStandardItem(getSubsystemString(ohw32.Subsystem)));
        QStandardItem *dllCharNode = new QStandardItem("DLL Characteristics");
        dllCharNode->setEditable(false);
        QStandardItem *dllCharValNode = new QStandardItem();
        dllCharValNode->setEditable(false);
        uint32_t dllMask = 1;
        for (unsigned int j = 0; j < 16; ++j, dllMask <<= 1) {
            if (ohw32.DllCharacteristics & dllMask) {
                QString desc = QString::fromLatin1(dll_characteristics[j]);
                if (desc != "Reserved.") {
                    dllCharNode->appendRow(QList<QStandardItem*>() << new QStandardItem(QString("0x%1").arg(dllMask, 4, 16, QChar('0'))) << new QStandardItem(desc));
                }
            }
        }
        dllCharValNode->setText(QString("0x%1").arg(ohw32.DllCharacteristics, 4, 16, QChar('0')));
        ohsNode->appendRow(QList<QStandardItem*>() << dllCharNode << dllCharValNode);
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("ImageBase") << new QStandardItem(QString("0x%1").arg(ohw32.ImageBase, 0, 16)));
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SectionAlignment") << new QStandardItem(QString("0x%1").arg(ohw32.SectionAlignment, 0, 16)));
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("FileAlignment") << new QStandardItem(QString("0x%1").arg(ohw32.FileAlignment, 0, 16)));
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SizeOfImage") << new QStandardItem(QString("0x%1").arg(ohw32.SizeOfImage, 0, 16)));

        num_tables = ohw32.NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY *tblPtr = &ohw32.ExportTable;
        for(uint32_t i=0; i<num_tables && i<16; ++i) {
            tableList.append(tblPtr[i]);
        }
    } else if (ohs.Magic == OPTIONAL_HEADER_MAGIC_PE32_PLUS) {
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Image type") << new QStandardItem("PE32+"));
        optional_header_windows_specific_fields ohw;
        rds(file, pos, ohw); pos += sizeof(ohw);

        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("Subsystem") << new QStandardItem(getSubsystemString(ohw.Subsystem)));
        QStandardItem *dllCharNode = new QStandardItem("DLL Characteristics");
        dllCharNode->setEditable(false);
        QStandardItem *dllCharValNode = new QStandardItem();
        dllCharValNode->setEditable(false);
        uint32_t dllMask = 1;
        for (unsigned int j = 0; j < 16; ++j, dllMask <<= 1) {
            if (ohw.DllCharacteristics & dllMask) {
                QString desc = QString::fromLatin1(dll_characteristics[j]);
                if (desc != "Reserved.") {
                    dllCharNode->appendRow(QList<QStandardItem*>() << new QStandardItem(QString("0x%1").arg(dllMask, 4, 16, QChar('0'))) << new QStandardItem(desc));
                }
            }
        }
        dllCharValNode->setText(QString("0x%1").arg(ohw.DllCharacteristics, 4, 16, QChar('0')));
        ohsNode->appendRow(QList<QStandardItem*>() << dllCharNode << dllCharValNode);
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("ImageBase") << new QStandardItem(QString("0x%1").arg(ohw.ImageBase, 0, 16)));
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SectionAlignment") << new QStandardItem(QString("0x%1").arg(ohw.SectionAlignment, 0, 16)));
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("FileAlignment") << new QStandardItem(QString("0x%1").arg(ohw.FileAlignment, 0, 16)));
        ohsNode->appendRow(QList<QStandardItem*>() << new QStandardItem("SizeOfImage") << new QStandardItem(QString("0x%1").arg(ohw.SizeOfImage, 0, 16)));

        num_tables = ohw.NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY *tblPtr = &ohw.ExportTable;
        for(uint32_t i=0; i<num_tables && i<16; ++i) {
            tableList.append(tblPtr[i]);
        }
    } else {
        errorMsg = QString("Wrong OHS Magic 0x%1").arg(ohs.Magic, 4, 16, QChar('0'));
        return false;
    }

    QList<QStandardItem*> directoryItems;
    if (num_tables > 0) {
        QStandardItem *tablesNode = new QStandardItem(QString("Data Directories (%1)").arg(num_tables));
        tablesNode->setEditable(false);
        QStandardItem *tablesValNode = new QStandardItem();
        tablesValNode->setEditable(false);
        rootItem->appendRow(QList<QStandardItem*>() << tablesNode << tablesValNode);

        const char *tableNames[] = {
            "Exports", "Imports", "Resources", "Exceptions", "Certificates", "Base Relocations",
            "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
            "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
        };

        for (uint32_t i = 0; i < num_tables && i < 16; ++i) {
            QString v = QString("0x%1 - 0x%2")
                        .arg(tableList[i].VirtualAddress, 8, 16, QChar('0'))
                        .arg(tableList[i].VirtualAddress + tableList[i].Size, 8, 16, QChar('0'));
            QStandardItem *dirItem = new QStandardItem(tableNames[i]);
            dirItem->setEditable(false);

            // Mark as potential directory, but missing raw offset for now
            dirItem->setData(true, Qt::UserRole + 5); // isDataDirectory
            dirItem->setData(0, Qt::UserRole + 2); // default raw offset 0
            dirItem->setData(tableList[i].Size, Qt::UserRole + 3); // size
            dirItem->setData(QString(tableNames[i]), Qt::UserRole + 4); // name

            directoryItems.append(dirItem);
            tablesNode->appendRow(QList<QStandardItem*>() << dirItem << new QStandardItem(v));
        }
    }

    QStandardItem *sectionsNode = new QStandardItem(QString("Sections (%1)").arg(coff.NumberOfSections));
    sectionsNode->setEditable(false);
    QStandardItem *sectionsValNode = new QStandardItem();
    sectionsValNode->setEditable(false);
    rootItem->appendRow(QList<QStandardItem*>() << sectionsNode << sectionsValNode);

    qint64 sec_pos = pos_sections;
    for (int i = 0; i < coff.NumberOfSections; ++i) {
        section_header sh;
        if (!rds(file, sec_pos, sh)) break;
        sec_pos += sizeof(sh);

        QString secName = QString::fromLatin1(sh.Name, qstrnlen(sh.Name, 8));
        QStandardItem *secItem = new QStandardItem(QString("[%1] %2").arg(i).arg(secName));
        secItem->setEditable(false);
        QStandardItem *secValItem = new QStandardItem();
        secValItem->setEditable(false);

        secItem->setData(true, Qt::UserRole + 1); // isSection
        secItem->setData(sh.PointerToRawData, Qt::UserRole + 2); // PointerToRawData
        secItem->setData(sh.SizeOfRawData, Qt::UserRole + 3); // SizeOfRawData
        secItem->setData(secName, Qt::UserRole + 4); // Section Name

        secItem->appendRow(QList<QStandardItem*>() << new QStandardItem("Virtual size") << new QStandardItem(QString("0x%1").arg(sh.VirtualSize, 0, 16)));
        secItem->appendRow(QList<QStandardItem*>() << new QStandardItem("Virtual address") << new QStandardItem(QString("0x%1").arg(sh.VirtualAddress, 0, 16)));
        secItem->appendRow(QList<QStandardItem*>() << new QStandardItem("Size of raw data") << new QStandardItem(QString("0x%1").arg(sh.SizeOfRawData, 0, 16)));
        secItem->appendRow(QList<QStandardItem*>() << new QStandardItem("Pointer to raw data") << new QStandardItem(QString("0x%1").arg(sh.PointerToRawData, 0, 16)));

        QStandardItem *charNode = new QStandardItem("Characteristics");
        charNode->setEditable(false);
        QStandardItem *charValNode = new QStandardItem();
        charValNode->setEditable(false);

        uint32_t c = sh.Characteristics;
        uint32_t align = c & 0xf00000;
        c &= ~0xf00000;

        uint32_t mask = 1;
        for (unsigned int j = 0; j < 32; ++j, mask <<= 1) {
            if (c & mask) {
                QString desc = QString::fromLatin1(section_characteristics[j]);
                if (desc != "Reserved.") {
                    charNode->appendRow(QList<QStandardItem*>() << new QStandardItem(QString("0x%1").arg(mask, 8, 16, QChar('0'))) << new QStandardItem(desc));
                }
            }
        }

        if (align) {
            align = 1 << ((align >> 20) - 1);
            charNode->appendRow(QList<QStandardItem*>() << new QStandardItem(QString("0x%1").arg(sh.Characteristics & 0xf00000, 8, 16, QChar('0'))) << new QStandardItem(QString("Align data on a %1 byte boundary.").arg(align)));
        }

        charValNode->setText(QString("0x%1").arg(sh.Characteristics, 8, 16, QChar('0')));
        secItem->appendRow(QList<QStandardItem*>() << charNode << charValNode);

        sectionsNode->appendRow(QList<QStandardItem*>() << secItem << secValItem);

        // Resolve RVAs for data directories
        if (num_tables > 0) {
            for (uint32_t j = 0; j < num_tables && j < 16; ++j) {
                uint32_t dirRva = tableList[j].VirtualAddress;
                uint32_t dirSize = tableList[j].Size;

                // Special Case: The Certificate Table (Index 4) VirtualAddress is ACTUALLY a File Offset, not an RVA.
                if (j == 4) {
                    directoryItems[j]->setData(dirRva, Qt::UserRole + 2); // It's already the raw physical file pointer
                    directoryItems[j]->setData(dirSize, Qt::UserRole + 3);
                    continue;
                }

                // If directory is within this section's virtual memory
                if (dirRva >= sh.VirtualAddress && dirRva < sh.VirtualAddress + sh.VirtualSize) {
                    uint32_t offset = dirRva - sh.VirtualAddress + sh.PointerToRawData;

                    // Prevent reading past the actual raw data available on disk
                    if (offset < sh.PointerToRawData + sh.SizeOfRawData) {
                        uint32_t availableRaw = (sh.PointerToRawData + sh.SizeOfRawData) - offset;
                        uint32_t actualSize = (dirSize > availableRaw) ? availableRaw : dirSize;

                        directoryItems[j]->setData(offset, Qt::UserRole + 2); // Correct file offset
                        directoryItems[j]->setData(actualSize, Qt::UserRole + 3); // Correct max readable size
                    }
                }
            }
        }
    }

    file.close();
    return true;
}
