# EFI Analyzer

The EFI Analyzer can be used to check EFI binaries and to print out header and
section information, e.g.

    $ efianalyze helloworld.efi
    Offset to PE = 40
    Machine type: 0xaa64, ARM64 little endian
    Characteristics 0x20e
    Image type: PE32+
    Size of optional header: 0xa0 != 0xf0
    EFI application
    ImageBase=0x0
    SectionAlignment=0x20
    SizeOfImage=0x3a0
    .reloc.address=0x0
    .reloc.size=0x0
    BaseOfCode=0x148
    AddressOfEntryPoint=0x148
    Number of Sections 2
    Section[0] .reloc
    Virtual size 0x0
    Virtual address 0x0
    Size of raw data 0x0
    Pointer to raw data 0x0
    End of raw data 0x0
    Section[1] .text
    Virtual size 0x200
    Virtual address 0x148
    Size of raw data 0x258
    Pointer to raw data 0x148
    End of raw data 0x3a0


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

installs the binary as `foo/usr/bin/efianalyzer`.


## References

* [Microsoft Portable Executable and Common Object File Format Specification
  ](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format)
* [UEFI Specification Version 2.7 (Errata A)
  ](http://www.uefi.org/sites/default/files/resources/UEFI%20Spec%202_7_A%20Sept%206.pdf)


## License

The EFI Analyzer is distributed under the BSD 2-clause license. See accompanying
file `Copyright`.
