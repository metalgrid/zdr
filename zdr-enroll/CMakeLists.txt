# Builds the zdr-enroll QtQuick photo-booth host.
#
# Mirrors zdr-agent/prompt/CMakeLists.txt, plus Qt6::DBus for the
# daemon enroll contract. LayerShellQt is strictly optional: when
# its CMake package is found, main.cpp picks the headers up via
# __has_include; without it the same source builds a plain-window
# host. zdr-enroll is a normal session window and does not attach
# to a layer surface either way.
cmake_minimum_required(VERSION 3.16)
project(zdr-enroll CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick DBus)

add_executable(zdr-enroll main.cpp)
target_link_libraries(zdr-enroll PRIVATE Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::DBus)

find_package(LayerShellQt QUIET)
if(TARGET LayerShellQt::Interface)
    target_link_libraries(zdr-enroll PRIVATE LayerShellQt::Interface)
elseif(TARGET LayerShellQtInterface)
    target_link_libraries(zdr-enroll PRIVATE LayerShellQtInterface)
endif()

install(TARGETS zdr-enroll DESTINATION bin)
install(FILES zdr-enroll.qml DESTINATION share/zdr)
install(FILES zdr-enroll.desktop DESTINATION share/applications)
