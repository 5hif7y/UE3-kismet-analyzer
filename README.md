# UE3-kismet-analyzer

Tools for **reading and analysing Unreal Engine 3 packages** — `.u`, `.upk`, `.ccmap` —
and, on top of that, rebuilding the graph of their Kismet sequences and their UnrealScript
bytecode.

It is a port of [kismet-analyzer](https://github.com/trumank/kismet-analyzer) by Truman
Kilen, which does the same for UE4. **The difference is not cosmetic:** UE4 uses
UAssetAPI and Blueprint bytecode; UE3 uses a different package version (**576** in
CrimeCraft), a different container, and a Kismet that is a **graph of objects**, not
bytecode. That is why the port is C++ and reads the format directly.

It was written against **CrimeCraft** (UE3 build 576, licensee 5), and every number below
comes from that game's packages.

## Why its own reader, and not the engine's

A UE3 engine ships a linker that reads packages. This could have been built on top of one.
It was not, for two reasons that cost real time:

1. **An engine linker does not digest every package you care about.** Pointed at a large
   cooked package it can desynchronise part-way through and say nothing useful about
   where. A reader of your own can be aimed at anything, and **when it fails it says
   where.**
2. **It cannot read `.ccmap` files**, which are cooked maps that expect the build they
   were cooked for.

## Status

| part | state |
| --- | --- |
| Package header | **done and verified** |
| Name table | **done and verified** |
| Import table | **done and verified** |
| Export table | **done and verified** |
| Tagged property stream | **1,280 of 1,711 close exactly**, 253 end early, 178 fail |
| Kismet graph (`USequence`/`USequenceOp`) | **done.** `graph` emits DOT |
| UnrealScript bytecode (`EX_*`) | not started |
| GraphViz / DOT output | **done**, and to SVG with Graphviz |
| Batch walk | **done.** `tree` emits every sequence in a directory |
| Class hierarchy | **done.** `hierarchy` emits the tree as SVG. 2,866 classes |

Real properties already come out of the stream: `SequenceObjects`, `DefaultViewX` (900),
`DefaultViewZoom` (0.8), `AnimSeqName`, `NumFrames`. Three traps on the way, all of them
version traps: **`NAME_None` is not index 0**, `BoolProperty` occupies **4** bytes in 576,
and `ByteProperty` carries no `EnumName` before version 633.

**The 431 that fail are two bounded families** — actors with a serialisation of their own,
and large arrays whose `Size` does not cover their data. They are characterised, not
mysterious; what is missing is a rule that bounds all of them.

What exists works: it reads `CrimeCraft.u` — 366,986,751 bytes, 56,719 names, 1,992
imports, 185,659 exports — from beginning to end.

```
$ build\ue3kismet.exe info CrimeCraft.u
fichero               ...\CrimeCraft.u
tamano                366986751 bytes
FileVersion           328256  (version 576, licencia 5)
VersionMotor          4701
contenido cocinado    87
nombres               56719
importaciones         1992
exportaciones         185659

VERIFICACIONES (comprobado al abrir)
  ok  encabezado: 109 bytes hasta NameOffset=109
  ok  nombres: 56719 entradas, cierran exactas en 1829129 = ImportOffset
  ok  importaciones: 1992 entradas de 28 bytes, cierran exactas en 1829129+55776 = ExportOffset
  ok  exportaciones: 185659 entradas (65 objetos de red repartidos), cierran exactas en 14509977 = DependsOffset
  ok  datos: 185659 exportaciones con contenido, de 15252613 a 366986751; el fichero mide 366986751
```

> [!warning] **The command names are English. The messages are not — yet.**
> The sample above is **the real output**, kept verbatim so this page does not claim
> something the program does not do. **An English README that shows output the tool never
> printed is a document that lies**, and this repository would rather show a gap than a
> falsehood.
>
> **What is done:** every command name, and the help screen.
> **What is pending:** the ~97 output messages in `src/main.cpp`, still Spanish.
> **It is mechanical and bounded** — one file, one pass — and it is listed here rather
> than left for a reader to discover by running it.

## Build

```console
build.bat
```

No dependencies: no zlib, no graphviz, no engine. `build.bat` finds Visual Studio with
`vswhere.exe` and calls `cl.exe`; the `CMakeLists.txt` is there for an IDE and for the day
this is folded into a larger build.

## Usage

```console
ue3kismet info <package>              header and checks
ue3kismet classes <package> [n]       exports grouped by class
ue3kismet exports <package> [n]       export listing
ue3kismet imports <package> [n]       import listing
ue3kismet names <package> [n]         first names of the table
```

## The format, as measured

**None of this was copied from engine source.** The version of UE3 that was available to
read is a late branch and **no longer keeps the version gates of the 576 era**, so its
code cannot be used as a source. **Everything was measured against a real package and
verified by closure** — every table has to end exactly where the header says the next one
begins.

```
header     109 bytes up to NameOffset, with FolderName="None"
names      [i32 len][len bytes][8 trailing]              56,719 entries
import     28 bytes = FName(8) FName(8) i32 FName(8)      1,992 entries
export     68 bytes + 4 per net object                  185,659 entries
```

Three things that are not what you would expect, each of which cost a measurement:

> [!warning] `FName` occupies **eight** bytes on disk, not four
> Index and number. With four, the import table measures 16 and does not add up: it
> measures 28. What gives it away is that the integer next to each index is always 0 — it
> is the *number* field of an `FName`, not a field of its own.

> [!warning] `FGenerationInfo` is 12 bytes: it carries `NetObjectCount`
> With 8, the header does not reach `NameOffset`, and `EngineVersion` comes out as 96,161
> instead of 4,701. That is the discriminator, and it is the number the engine itself
> reports.

> [!warning] The export entry is **not** a fixed size
> 68 bytes plus 4 for each net object of its generation. The 260 bytes left over 68 give
> exactly 65 objects, and they explain why chaining offsets breaks at export **108,197**
> and not before.

## What is not here yet

The *analysis*. This repository is, for now, the reader; the analyser goes on top. What has
been located to build it, in the engine's own headers:

| piece | where |
| --- | --- |
| The complete `EExprToken` enum, with this version's numbers | `Core/Inc/UnStack.h:109` |
| The authoritative bytecode deserialiser | `Core/Inc/ScriptSerialization.h:233` |
| The bytecode header on disk (two integers before the blob) | `Core/Src/UnClass.cpp:1088` |
| `USequence` / `USequenceOp` and their link types | `Engine/Inc/EngineSequenceClasses.h:906`, `:614` |
| A level's sequence graph | `ULevel::GameSequences`, `Engine/Inc/UnLevel.h:608` |

And one warning that saves half a day: **in UE3, Kismet is not bytecode.** It is a graph of
`USequenceOp` objects joined by `FSeqOpOutputLink`, serialised as ordinary `UObject`
properties. The bytecode belongs to UnrealScript, which is a different thing. **`UK2Node`
does not exist in UE3** — that is a UE4 concept.

## License

MIT. See `LICENSE`: the original is Truman Kilen's, and this port derives from it.
