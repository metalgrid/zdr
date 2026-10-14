# Builds the optional zdr-prompt QtQuick host.
#
# LayerShellQt is strictly optional: when its CMake package is
# found, main.cpp picks the headers up via __has_include and the
# window becomes a layer-shell Overlay surface; without it the
# same source builds a plain-window host. Nothing here makes Qt
# or layer-shell-qt a hard requirement of zdr-agent itself —
# the agent falls back to qml6 and then to desktop notifications.
cmake_minimum_required(VERSION 3.16)
project(zdr-prompt CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick)

add_executable(zdr-prompt main.cpp)
target_link_libraries(zdr-prompt PRIVATE Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick)

find_package(LayerShellQt QUIET)
if(TARGET LayerShellQt::Interface)
    target_link_libraries(zdr-prompt PRIVATE LayerShellQt::Interface)
elseif(TARGET LayerShellQtInterface)
    target_link_libraries(zdr-prompt PRIVATE LayerShellQtInterface)
endif()

install(TARGETS zdr-prompt DESTINATION lib/zdr)
install(FILES zdr-prompt.qml DESTINATION share/zdr)
