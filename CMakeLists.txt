cmake_minimum_required(VERSION 3.16)
project(UE3kismetAnalyzer CXX)

# El proyecto hermano (ue-CodeRedModding) se porteo a CMake + MSVC, asi que esta
# herramienta usa lo mismo. No hay dependencias externas: ni zlib, ni graphviz,
# ni el motor. Eso es deliberado -- ver README.md.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # /utf-8 hace falta porque los comentarios y los mensajes llevan acentos y
    # el compilador, si no, avisa o los destroza.
    add_compile_options(/utf-8 /W4)
endif()

add_executable(ue3kismet
    src/main.cpp
    src/ue3package.cpp
)

if(MSVC)
    target_compile_definitions(ue3kismet PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
