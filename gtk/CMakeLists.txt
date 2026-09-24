cmake_minimum_required(VERSION 3.16)
project(efianalyze-gui VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

add_executable(efianalyze-gui
    main.c
    main_window.c
    main_window.h
    pe_parser.c
    pe_parser.h
    ../common/efi_pe.c
    ../common/efi_pe.h
)

target_include_directories(efianalyze-gui PRIVATE ${GTK3_INCLUDE_DIRS})
target_link_libraries(efianalyze-gui PRIVATE ${GTK3_LIBRARIES})
target_compile_options(efianalyze-gui PRIVATE ${GTK3_CFLAGS_OTHER} -Wall -Wextra)

include(GNUInstallDirs)
install(TARGETS efianalyze-gui DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES efianalyze-gui.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES efianalyzer.png DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps)

