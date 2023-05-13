# EFI Analyzer

The EFI Analyzer can be used to check EFI binaries and to print out header and
section information, e.g.

    $ efianalyze helloworld.efi
    helloworld.efi
    Offset to PE: 0x40
    Machine type: 0xaa64, ARM64 little endian
    Characteristics: 0x022e
      * The file is executable.
      * COFF line numbers were stripped from the file.
      * COFF symbol table entries were stripped from file.
      * The application can handle addresses larger than 2 GiB.
      * Debugging information was removed.
    LinkerVersion 2.20
    BaseOfCode: 0x1000
    AddressOfEntryPoint: 0x1000
    Image type: PE32+
    Subsystem: EFI application
    ImageBase: 0x0
    SectionAlignment: 0x1000
    FileAlignment: 0x200
    SizeOfImage: 0x2200
    .reloc.address: 0x0
    .reloc.size: 0x0
    Number data tables: 6
      Exports             : 0x00000000 - 0x00000000
      Imports             : 0x00000000 - 0x00000000
      Resources           : 0x00000000 - 0x00000000
      Exceptions          : 0x00000000 - 0x00000000
      Certificates        : 0x00000000 - 0x00000000
      Base Relocations    : 0x00000000 - 0x00000000
    Number of sections: 3
    Section[0]: .reloc
      Virtual size: 0x0
      Virtual address: 0x0
      Size of raw data: 0x0
      Pointer to raw data: 0x0
      End of raw data: 0x0
      Characteristics: 0x42000040
        * The section contains initialized data.
        * The section can be discarded as needed.
        * The section can be read.
    Section[1]: .text
      Virtual size: 0xc00
      Virtual address: 0x1000
      Size of raw data: 0xc00
      Pointer to raw data: 0x1000
      End of raw data: 0x1c00
      Characteristics: 0x60000020
        * The section contains executable code.
        * The section can be executed as code.
        * The section can be read.
    Section[2]: .data
      Virtual size: 0x200
      Virtual address: 0x2000
      Size of raw data: 0x200
      Pointer to raw data: 0x2000
      End of raw data: 0x2200
      Characteristics: 0xc0000040
        * The section contains initialized data.
        * The section can be read.
        * The section can be written to.

## Building and installing

The binary is built with

    make

The binary is installed with

    sudo make install

The following variables influence the installation path:

* prefix  - The default installation path prefix is /usr/local. You can replace
            it by setting the variable prefix.
* DESTDIR - The value of variable DESTDIR is prepended to the installation path.

    make install DESTDIR=foo prefix=/usr

installs the binary as `foo/usr/bin/efianalyze`.


## References

* [Microsoft Portable Executable and Common Object File Format Specification
  ](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
* [UEFI Specification Version 2.10](https://uefi.org/specs/UEFI/2.10/)

## License

The EFI Analyzer is distributed under the BSD 2-clause license. See accompanying
file `Copyright`.
