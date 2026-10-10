@echo off
REM ---------------------------------------------------------------------------
REM  Compila ue3kismet con MSVC, sin depender de que el entorno ya este puesto.
REM
REM  Por que no se llama directamente a cmake: CMake necesita el entorno de
REM  Visual Studio igual que cl.exe, asi que el paso dificil es el mismo y
REM  quitarlo de en medio deja menos piezas que puedan fallar. El CMakeLists.txt
REM  esta para el IDE y para el dia que esto se integre en el build del SDK.
REM
REM  vcvarsall.bat NO esta en el PATH: hay que localizarlo con vswhere.
REM  Ver RnD-ELECTRIC-ENGINEER-OVERSEER.md, que es donde esta escrito.
REM ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

REM Ponerse en la carpeta del propio .bat: las rutas de abajo son relativas, y
REM invocado desde otro directorio compilaria otra cosa o nada.
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo No se encuentra vswhere.exe en "%VSWHERE%"
    exit /b 1
)

set "VCVARS="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSROOT=%%i"
)
if not defined VSROOT (
    echo vswhere no ha encontrado ninguna instalacion de Visual Studio con C++.
    exit /b 1
)

set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" (
    echo No se encuentra vcvarsall.bat en "%VCVARS%"
    exit /b 1
)

echo Entorno: %VCVARS% x86
call "%VCVARS%" x86 >nul
if errorlevel 1 (
    echo vcvarsall.bat ha fallado.
    exit /b 1
)

if not exist build mkdir build

echo Compilando...
cl /nologo /std:c++17 /W4 /utf-8 /EHsc /O2 /D_CRT_SECURE_NO_WARNINGS ^
   /Fo:build\ /Fe:build\ue3kismet.exe ^
   src\main.cpp src\ue3package.cpp
if errorlevel 1 (
    echo.
    echo La compilacion ha fallado.
    exit /b 1
)

echo.
echo Listo: build\ue3kismet.exe
