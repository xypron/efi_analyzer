cmake_minimum_required(VERSION 3.16)
project(efianalyzer-qt VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

add_executable(efianalyzer-qt
    main.cpp
    mainwindow.cpp
    mainwindow.h
    pe_parser.cpp
    pe_parser.h
)

target_link_libraries(efianalyzer-qt PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)

include(GNUInstallDirs)
install(TARGETS efianalyzer-qt DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES efianalyzer-qt.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES efianalyzer.png DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps)
