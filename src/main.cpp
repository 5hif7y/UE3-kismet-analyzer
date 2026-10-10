// main.cpp -- interfaz de linea de comandos de UE3-kismet-analyzer.
//
// De momento solo lee paquetes: encabezado y las tres tablas. El analisis de
// bytecode y el dibujo del grafo van encima de esto y todavia no estan.

#include "ue3package.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

static void Uso() {
    std::printf(
        "UE3-kismet-analyzer -- a UE3 package reader and analyser\n"
        "\n"
        "  ue3kismet info <package>              header and checks\n"
        "  ue3kismet classes <package> [n]       exports grouped by class\n"
        "  ue3kismet exports <package> [n]       export listing\n"
        "  ue3kismet imports <package> [n]       import listing\n"
        "  ue3kismet names <package> [n]         first names of the table\n"
        "  ue3kismet search <package> <text> [n] exports by class or name\n"
        "  ue3kismet data <package> <index> [n]  dump of one export's data\n"
        "  ue3kismet props <package> <index>     tagged property trace\n"
        "  ue3kismet flow <package> [n]          where the tag stream breaks\n"
        "  ue3kismet refs <package> <index>      who references an export\n"
        "  ue3kismet graph <package> <index>     Kismet graph as DOT\n"
        "  ue3kismet tree <dir>                  every sequence in a directory\n"
        "  ue3kismet hierarchy <package> [n]     the class tree as SVG\n"
        "\n"
        "The package may be .u, .upk or .ccmap: the reader looks at the\n"
        "content, not at the extension.\n");
}

static int Entero(const char* s, int porDefecto) {
    if (!s) return porDefecto;
    char* fin = nullptr;
    long v = std::strtol(s, &fin, 10);
    if (fin == s || v < 0) return porDefecto;
    return static_cast<int>(v);
}

static double Porcentaje(long long parte, long long total) {
    if (total <= 0) return 0.0;
    return 100.0 * static_cast<double>(parte) / static_cast<double>(total);
}

static int CmdInfo(const ue3::Paquete& p) {
    std::printf("file                 %s\n", p.Ruta().c_str());
    std::printf("size                 %llu bytes\n",
                static_cast<unsigned long long>(p.Tamano()));
    std::printf("FileVersion          %u  (version %u, licensee %u)\n",
                p.FileVersion, p.Version(), p.Licencia());
    std::printf("folder               \"%s\"\n", p.Carpeta.c_str());
    std::printf("package flags        0x%08X\n", p.BanderasPaquete);
    std::printf("header size          %d\n", p.TamanoEncabezado);
    std::printf("EngineVersion        %d\n", p.VersionMotor);
    std::printf("cooked content       %d\n", p.VersionContenidoCocinado);
    std::printf("names                %zu\n", p.Nombres.size());
    std::printf("imports              %zu\n", p.Importaciones.size());
    std::printf("exports              %zu\n", p.Exportaciones.size());
    std::printf("net objects          %d\n", p.TamanoObjetosRed);
    std::printf("\n");

    std::printf("CHECKS (verified on open)\n");
    for (const auto& v : p.Verificaciones()) std::printf("  ok  %s\n", v.c_str());

    if (!p.Avisos().empty()) {
        std::printf("\nWARNINGS\n");
        for (const auto& a : p.Avisos()) std::printf("  !!  %s\n", a.c_str());
    }
    return 0;
}

static int CmdClases(const ue3::Paquete& p, int limite) {
    auto v = ue3::RecuentarPorClase(p);
    std::printf("%-52s %10s  %6s\n", "class", "objects", "%");
    std::printf("%-52s %10s  %6s\n", std::string(52, '-').c_str(),
                std::string(10, '-').c_str(), std::string(6, '-').c_str());
    int n = 0;
    for (const auto& r : v) {
        if (limite > 0 && n >= limite) break;
        std::printf("%-52s %10d  %5.1f%%\n", r.Clase.c_str(), r.Cuenta,
                    Porcentaje(r.Cuenta, static_cast<long long>(p.Exportaciones.size())));
        ++n;
    }
    std::printf("\n%zu distinct classes in %zu exports\n", v.size(),
                p.Exportaciones.size());
    return 0;
}

static int CmdExportaciones(const ue3::Paquete& p, int limite) {
    int n = 0;
    for (const auto& e : p.Exportaciones) {
        if (limite > 0 && n >= limite) break;
        std::printf("%6d  %-40s  size=%-9d off=%-10d class=%d super=%d outer=%d\n",
                    n, p.Texto(e.NombreObjeto.Indice).c_str(),
                    e.TamanoSerializado, e.OffsetSerializado,
                    e.IndiceClase, e.IndiceSuper, e.IndiceExterno);
        ++n;
    }
    return 0;
}

static int CmdImportaciones(const ue3::Paquete& p, int limite) {
    int n = 0;
    for (const auto& im : p.Importaciones) {
        if (limite > 0 && n >= limite) break;
        // Se imprime la ruta del objeto Y de que es. Las dos cosas: la ruta es
        // el nombre util, y "de que es" es lo que dice si la entrada es una
        // clase, un paquete o un objeto corriente.
        std::printf("%6d  %-44s  is: %s.%s  outer=%d\n", n,
                    p.RutaObjeto(-(n + 1)).c_str(),
                    p.Texto(im.PaqueteClase.Indice).c_str(),
                    p.Texto(im.NombreClase.Indice).c_str(),
                    im.IndiceExterno);
        ++n;
    }
    return 0;
}

// Busca exportaciones cuya clase o cuyo nombre contengan un texto, sin
// distinguir mayusculas. Es el instrumento para llegar a una exportacion
// concreta de un paquete de 185.000: sin esto, encontrar la primera
// USequence de CrimeCraft.u es leer un listado a ojo.
static std::string EnMinusculas(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

static int CmdBuscar(const ue3::Paquete& p, const std::string& texto, int limite) {
    const std::string aguja = EnMinusculas(texto);
    int hallados = 0;
    for (size_t i = 0; i < p.Exportaciones.size(); ++i) {
        const auto& e = p.Exportaciones[i];
        const std::string clase = ue3::NombreClaseDe(p, e.IndiceClase);
        const std::string nombre = p.Texto(e.NombreObjeto.Indice);
        if (EnMinusculas(clase).find(aguja) == std::string::npos &&
            EnMinusculas(nombre).find(aguja) == std::string::npos) {
            continue;
        }
        if (limite > 0 && hallados >= limite) break;
        std::printf("%6zu  %-34s  %-30s  size=%-8d off=%d\n", i + 1,
                    clase.c_str(), nombre.c_str(), e.TamanoSerializado,
                    e.OffsetSerializado);
        ++hallados;
    }
    std::printf("\n%d coincidencias\n", hallados);
    return 0;
}

// Volcado hexadecimal de los datos serializados de una exportacion, con
// direccion relativa al principio de la exportacion. Es la herramienta con la
// que se va a averiguar la forma del flujo de propiedades.
static int CmdDatos(const ue3::Paquete& p, int indice, int limite) {
    const size_t k = static_cast<size_t>(indice - 1);
    if (indice <= 0 || k >= p.Exportaciones.size()) {
        std::fprintf(stderr, "no such export %d (there are %zu)\n", indice,
                     p.Exportaciones.size());
        return 2;
    }
    const auto& e = p.Exportaciones[k];
    std::printf("export %d  \"%s\"  class=%s\n", indice,
                p.Texto(e.NombreObjeto.Indice).c_str(),
                ue3::NombreClaseDe(p, e.IndiceClase).c_str());
    std::printf("path          %s\n", p.RutaObjeto(indice).c_str());
    std::printf("offset        %d\n", e.OffsetSerializado);
    std::printf("size          %d\n\n", e.TamanoSerializado);

    const std::vector<ue3::u8>& d = p.Datos();
    const size_t inicio = static_cast<size_t>(e.OffsetSerializado);
    size_t n = static_cast<size_t>(e.TamanoSerializado);
    if (limite > 0 && n > static_cast<size_t>(limite)) n = static_cast<size_t>(limite);

    for (size_t i = 0; i < n; i += 16) {
        std::printf("%6zu  ", i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < n) std::printf("%02X ", d[inicio + i + j]);
            else           std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (size_t j = 0; j < 16 && i + j < n; ++j) {
            unsigned char c = d[inicio + i + j];
            std::printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        std::printf("|\n");
    }
    if (static_cast<size_t>(e.TamanoSerializado) > n) {
        std::printf("... (%d more bytes)\n",
                    e.TamanoSerializado - static_cast<int>(n));
    }
    return 0;
}

static ue3::i32 LeeI32En(const ue3::Paquete& p, ue3::u64 offset) {
    const std::vector<ue3::u8>& d = p.Datos();
    return static_cast<ue3::i32>(
        static_cast<ue3::u32>(d[offset]) |
        (static_cast<ue3::u32>(d[offset + 1]) << 8) |
        (static_cast<ue3::u32>(d[offset + 2]) << 16) |
        (static_cast<ue3::u32>(d[offset + 3]) << 24));
}

// Las referencias a objetos de una exportacion: las que son aristas del grafo.
//
// Dos formas, y las dos importan para el Kismet:
//   - ObjectProperty de 4 bytes: una sola referencia. `ParentSequence` es una.
//   - ArrayProperty cuyo tamano es 4 + 4*n: el conteo del TArray y luego n
//     referencias. `SequenceObjects` es esto, y son los nodos de la secuencia;
//     `OutputLinks` e `InputLinks` son las aristas, aunque su tamano no cuadre
//     con esta cuenta porque sus elementos son structs, no referencias sueltas.
//
// El cotejo 4 + 4*n == tamano es lo que distingue un array de referencias de
// uno de enteros, y no siempre acierta: por eso se dice cuando cuadra y cuando
// no, en vez de suponer.
static int CmdRefs(const ue3::Paquete& p, int indice) {
    if (indice <= 0 || static_cast<size_t>(indice) > p.Exportaciones.size()) {
        std::fprintf(stderr, "no such export %d\n", indice);
        return 2;
    }
    const ue3::Exportacion& e = p.Exportaciones[static_cast<size_t>(indice - 1)];
    std::printf("%s\n  class %s\n\n", p.RutaObjeto(indice).c_str(),
                ue3::NombreClaseDe(p, e.IndiceClase).c_str());

    const ue3::Flujo f = ue3::LeerFlujo(p, e);
    if (!f.Cierra()) {
        std::fprintf(stderr, "el flujo no cierra: %s\n", f.Error.c_str());
        return 1;
    }

    int total = 0;
    for (const auto& t : f.Etiquetas) {
        if (t.Tipo == "ObjectProperty" && t.Tamano == 4) {
            const ue3::i32 ref = LeeI32En(p, t.OffsetDatos);
            std::printf("  %-28s -> %s\n", t.Nombre.c_str(),
                        p.RutaObjeto(ref).c_str());
            ++total;
        } else if (t.Tipo == "ArrayProperty" && t.Tamano >= 4) {
            const ue3::i32 n = LeeI32En(p, t.OffsetDatos);
            const bool cuadra = (n >= 0) &&
                (4 + static_cast<ue3::i64>(n) * 4 == static_cast<ue3::i64>(t.Tamano));
            if (!cuadra) {
                std::printf("  %-28s    array of %d elements (size=%d, not a "
                            "vector de referencias)\n", t.Nombre.c_str(), n, t.Tamano);
                continue;
            }
            std::printf("  %-28s    %d referencias:\n", t.Nombre.c_str(), n);
            for (ue3::i32 k = 0; k < n; ++k) {
                const ue3::i32 ref = LeeI32En(p, t.OffsetDatos + 4 + 4 * static_cast<ue3::u64>(k));
                std::printf("      %3d  %s\n", k, p.RutaObjeto(ref).c_str());
                ++total;
            }
        }
    }
    std::printf("\n  %d object references in total\n", total);
    return 0;
}

// Nodo del grafo: el nombre suelto de un objeto, sin la ruta.
static std::string NombreCorto(const ue3::Paquete& p, ue3::i32 indice) {
    if (indice > 0 && static_cast<size_t>(indice) <= p.Exportaciones.size()) {
        return p.Texto(p.Exportaciones[static_cast<size_t>(indice - 1)].NombreObjeto.Indice);
    }
    if (indice < 0 && static_cast<size_t>(-indice - 1) < p.Importaciones.size()) {
        return p.Texto(p.Importaciones[static_cast<size_t>(-indice - 1)].NombreObjeto.Indice);
    }
    return "?";
}

// Aplica una funcion a cada etiqueta de un flujo y a las de sus flujos
// anidados. Es lo que hace falta porque el Kismet tiene tags dentro de tags:
// `OutputLinks` es un array cuyos elementos son flujos de tags, y dentro de
// cada uno hay un `Links` que son las aristas de verdad.
template <typename F>
static void RecorreEtiquetas(const ue3::Paquete& p, const ue3::Flujo& f, F&& fn) {
    for (const auto& t : f.Etiquetas) fn(t);
}

// El grafo de una secuencia de Kismet, en DOT.
//
// Dos niveles, y el segundo es el que cuesta ver:
//   1. `SequenceObjects` de la secuencia: el array de objetos. Son los NODOS.
//   2. `OutputLinks` de cada operador: un array cuyos elementos son a su vez un
//      flujo de tags, y dentro de cada uno un `Links` que es un array de
//      `FSeqOpOutputInputLink` = { LinkedOp, InputLinkIdx }, ocho bytes cada
//      uno. Son las ARISTAS.
static int GrafoADot(const ue3::Paquete& p, int indice, std::string& dot) {
    if (indice <= 0 || static_cast<size_t>(indice) > p.Exportaciones.size()) {
        std::fprintf(stderr, "no such export %d\n", indice);
        return 2;
    }
    const ue3::Exportacion& e = p.Exportaciones[static_cast<size_t>(indice - 1)];
    const ue3::Flujo f = ue3::LeerFlujo(p, e);
    if (!f.Cierra()) {
        std::fprintf(stderr, "el flujo de la secuencia no cierra: %s\n", f.Error.c_str());
        return 1;
    }

    // --- Nodos ---
    std::vector<ue3::i32> nodos;
    for (const auto& t : f.Etiquetas) {
        if (t.Nombre != "SequenceObjects" || t.Tipo != "ArrayProperty") continue;
        const ue3::i32 n = LeeI32En(p, t.OffsetDatos);
        for (ue3::i32 k = 0; k < n; ++k) {
            nodos.push_back(LeeI32En(p, t.OffsetDatos + 4 + 4 * static_cast<ue3::u64>(k)));
        }
    }
    if (nodos.empty()) {
        std::fprintf(stderr, "esta exportacion no tiene SequenceObjects\n");
        return 1;
    }
    std::fprintf(stderr, "%s: %zu objetos\n", p.RutaObjeto(indice).c_str(), nodos.size());

    // El DOT se construye en memoria en vez de imprimirse: hay que poder
    // canalizarlo a `dot`.
    std::ostringstream os;
    os << "digraph kismet {\n"
          "  graph [fontname=\"monospace\", rankdir=LR];\n"
          "  node [fontname=\"monospace\", shape=box];\n"
          "  edge [fontname=\"monospace\"];\n\n";

    for (size_t k = 0; k < nodos.size(); ++k) {
        const ue3::i32 ref = nodos[k];
        os << "  n" << k << " [label=\"" << NombreCorto(p, ref) << "\\n"
           << ue3::NombreClaseDe(p, ref > 0
                  ? p.Exportaciones[static_cast<size_t>(ref - 1)].IndiceClase : 0)
           << "\"];\n";
    }
    os << "\n";

    // --- Aristas ---
    int aristas = 0;
    for (size_t k = 0; k < nodos.size(); ++k) {
        const ue3::i32 ref = nodos[k];
        if (ref <= 0) continue;
        const auto& op = p.Exportaciones[static_cast<size_t>(ref - 1)];
        const ue3::Flujo fo = ue3::LeerFlujo(p, op);

        for (const auto& t : fo.Etiquetas) {
            if (t.Nombre != "OutputLinks" || t.Tipo != "ArrayProperty") continue;

            const ue3::u64 ini = t.OffsetDatos;
            const ue3::u64 fin = ini + static_cast<ue3::u64>(t.Tamano);
            const ue3::i32 nEnlaces = LeeI32En(p, ini);

            // Cada elemento del array es un flujo de tags propio. Se recorren
            // uno detras de otro: cada flujo dice cuantos bytes ha consumido.
            ue3::u64 cursor = ini + 4;
            for (ue3::i32 j = 0; j < nEnlaces && cursor < fin; ++j) {
                const ue3::Flujo elem = ue3::LeerFlujoEntre(p, cursor, fin);
                if (!elem.Cierra()) break;
                cursor += elem.BytesConsumidos;

                for (const auto& et : elem.Etiquetas) {
                    if (et.Nombre != "Links" || et.Tipo != "ArrayProperty") continue;

                    // El array de enlaces es, otra vez, un array de flujos de
                    // tags: cada `FSeqOpOutputInputLink` mide 64 bytes, que son
                    // los tags de `LinkedOp` (28) y `InputLinkIdx` (28) mas el
                    // terminador (8). No son ocho bytes planos.
                    //
                    // Suponer ocho bytes daba aristas con indice de entrada 590
                    // y destinos que eran expresiones de material: se leia como
                    // enlaces cualquier array llamado `Links`.
                    const ue3::i32 nSalidas = LeeI32En(p, et.OffsetDatos);
                    const ue3::u64 finL = et.OffsetDatos + static_cast<ue3::u64>(et.Tamano);
                    if (nSalidas < 0) continue;

                    ue3::u64 cursorL = et.OffsetDatos + 4;
                    for (ue3::i32 q = 0; q < nSalidas && cursorL < finL; ++q) {
                        const ue3::Flujo enlace = ue3::LeerFlujoEntre(p, cursorL, finL);
                        if (!enlace.Cierra()) {
                            std::fprintf(stderr, "  un enlace no cierra: %s\n",
                                         enlace.Error.c_str());
                            break;
                        }
                        cursorL += enlace.BytesConsumidos;

                        ue3::i32 destino = 0, entrada = 0;
                        for (const auto& e2 : enlace.Etiquetas) {
                            if (e2.Nombre == "LinkedOp" && e2.Tipo == "ObjectProperty") {
                                destino = LeeI32En(p, e2.OffsetDatos);
                            } else if (e2.Nombre == "InputLinkIdx" && e2.Tipo == "IntProperty") {
                                entrada = LeeI32En(p, e2.OffsetDatos);
                            }
                        }
                        if (destino <= 0) continue;
                        // El destino tiene que estar entre los nodos; si no, se
                        // dice en vez de inventarse un nodo.
                        int kd = -1;
                        for (size_t z = 0; z < nodos.size(); ++z) {
                            if (nodos[z] == destino) { kd = static_cast<int>(z); break; }
                        }
                        if (kd < 0) {
                            std::fprintf(stderr, "  destino fuera de la secuencia: %s\n",
                                         p.RutaObjeto(destino).c_str());
                            continue;
                        }
                        os << "  n" << k << " -> n" << kd
                           << " [label=\"" << entrada << "\"];\n";
                        ++aristas;
                    }
                }
            }
        }
    }
    os << "}\n";
    dot = os.str();
    std::fprintf(stderr, "%d aristas\n", aristas);
    return 0;
}

// ---------------------------------------------------------------------------
// Volcado a SVG, canalizando a Graphviz.
//
// Es lo que hacia el original, y por la misma via. Se comprobo antes de
// escribir esto que `dot` existe en esta maquina -- en el PATH, version 14.1.5,
// en C:\Program Files\Graphviz\bin. La skill de bajo nivel es explicita en eso:
// recomendar una herramienta que no esta cuesta una sesion.
//
// Se pasa por ficheros temporales en vez de por tuberia. En Windows, `_popen`
// da o escritura o lectura, no las dos, asi que la tuberia exigiria hilos o
// solapado; dos ficheros y un `system` hacen lo mismo y no failen silencio.
// ---------------------------------------------------------------------------
static bool EjecutaDot(const std::string& ejecutable, const std::string& dotTexto,
                       const std::string& rutaDot, const std::string& rutaSvg,
                       std::string& error) {
    {
        std::FILE* f = std::fopen(rutaDot.c_str(), "wb");
        if (!f) { error = "no se puede escribir " + rutaDot; return false; }
        std::fwrite(dotTexto.data(), 1, dotTexto.size(), f);
        std::fclose(f);
    }

    // La orden va entre comillas por fuera para que cmd.exe no parta las rutas
    // con espacios, y el ejecutable entrecomillado por dentro.
    const std::string orden = "\"\""
        + ejecutable + "\" -Tsvg \"" + rutaDot + "\" -o \"" + rutaSvg + "\"\"";

    const int rc = std::system(orden.c_str());
    if (rc != 0) {
        std::ostringstream os;
        os << "`" << ejecutable << "` ha devuelto " << rc
           << ". Comprueba que Graphviz esta instalado, o pasa --dot-exe <ruta>.";
        error = os.str();
        return false;
    }
    return true;
}

static std::string LeeFichero(const std::string& ruta) {
    std::FILE* f = std::fopen(ruta.c_str(), "rb");
    if (!f) return std::string();
    std::string s;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
    std::fclose(f);
    return s;
}

// La pagina que envuelve el SVG.
//
// El original embebia un visor aparte (trumank/svg-viewer). Aqui se escribe uno
// minimo: el SVG en linea, rueda para acercar y arrastrar para desplazar. Son
// cuarenta lineas y evita traer un submodulo entero para eso.
static std::string EnvuelveEnHtml(const std::string& svg, const std::string& titulo) {
    std::ostringstream os;
    os << "<!doctype html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n"
          "<title>" << titulo << "</title>\n<style>\n"
          "  html,body{margin:0;height:100%;background:#fbfbfd;"
          "font:13px/1.4 ui-monospace,Consolas,monospace;color:#1b1b1f}\n"
          "  #barra{padding:6px 10px;border-bottom:1px solid #d8d8e0;"
          "display:flex;gap:12px;align-items:center}\n"
          "  #lienzo{position:absolute;inset:34px 0 0 0;overflow:hidden;cursor:grab}\n"
          "  #lienzo.arrastrando{cursor:grabbing}\n"
          "  #lienzo svg{position:absolute;transform-origin:0 0}\n"
          "  button{font:inherit;padding:2px 8px}\n"
          "</style>\n</head>\n<body>\n"
          "<div id=\"barra\"><strong>" << titulo << "</strong>"
          "<button onclick=\"escala(1.25)\">+</button>"
          "<button onclick=\"escala(0.8)\">&minus;</button>"
          "<button onclick=\"reinicia()\">centrar</button>"
          "<span id=\"nivel\"></span></div>\n"
          "<div id=\"lienzo\">\n" << svg << "\n</div>\n"
          "<script>\n"
          "const l=document.getElementById('lienzo'),s=l.querySelector('svg'),"
          "n=document.getElementById('nivel');\n"
          "let k=1,x=0,y=0,ax=0,ay=0,arr=false;\n"
          "function pinta(){s.style.transform=`translate(${x}px,${y}px) scale(${k})`;"
          "n.textContent=Math.round(k*100)+'%';}\n"
          "function escala(f,px,py){const r=l.getBoundingClientRect();"
          "const cx=px??r.width/2,cy=py??r.height/2;"
          "const nk=Math.min(8,Math.max(0.05,k*f));"
          "x=cx-(cx-x)*(nk/k);y=cy-(cy-y)*(nk/k);k=nk;pinta();}\n"
          "function reinicia(){const r=l.getBoundingClientRect(),"
          "b=s.getBBox(),k0=Math.min(r.width/(b.width+40),r.height/(b.height+40),1.5);"
          "k=k0;x=(r.width-b.width*k)/2-b.x*k;y=(r.height-b.height*k)/2-b.y*k;pinta();}\n"
          "l.addEventListener('wheel',e=>{e.preventDefault();"
          "const r=l.getBoundingClientRect();"
          "escala(e.deltaY<0?1.12:1/1.12,e.clientX-r.left,e.clientY-r.top);},{passive:false});\n"
          "l.addEventListener('pointerdown',e=>{arr=true;ax=e.clientX-x;ay=e.clientY-y;"
          "l.classList.add('arrastrando');l.setPointerCapture(e.pointerId);});\n"
          "l.addEventListener('pointermove',e=>{if(!arr)return;"
          "x=e.clientX-ax;y=e.clientY-ay;pinta();});\n"
          "l.addEventListener('pointerup',e=>{arr=false;"
          "l.classList.remove('arrastrando');});\n"
          "reinicia();\n"
          "</script>\n</body>\n</html>\n";
    return os.str();
}

// ---------------------------------------------------------------------------
// El recorrido por lotes: el equivalente de `gen-cfg-tree` del original.
//
// Reglas que un lote necesita y que un comando suelto no:
//   - un fichero malo NO puede tumbar el lote: se apunta y se sigue;
//   - hay que poder parar antes de tiempo, para probar sin recorrer 5 GB;
//   - el progreso se ve, porque un lote silencioso de media hora es
//     indistinguible de uno colgado.
//
// Y una optimizacion que no es cosmetica: para saber si una exportacion es una
// secuencia basta el ULTIMO componente de su clase. Construir la ruta entera de
// cada exportacion de CrimeCraft.u son 185.659 recorridos de cadena para
// descartarlas todas.
// ---------------------------------------------------------------------------
static std::string NombreHoja(const ue3::Paquete& p, ue3::i32 indice) {
    if (indice > 0 && static_cast<size_t>(indice) <= p.Exportaciones.size()) {
        return p.Texto(p.Exportaciones[static_cast<size_t>(indice - 1)].NombreObjeto.Indice);
    }
    if (indice < 0 && static_cast<size_t>(-indice - 1) < p.Importaciones.size()) {
        return p.Texto(p.Importaciones[static_cast<size_t>(-indice - 1)].NombreObjeto.Indice);
    }
    return std::string();
}

static bool EsSecuencia(const std::string& hoja) {
    return hoja == "Sequence" || hoja == "PrefabSequence" ||
           hoja == "PrefabSequenceContainer";
}

static int CmdArbol(const std::string& raiz, const std::string& salida,
                    const std::string& extension, int maximo) {
    namespace fs = std::filesystem;

    std::vector<fs::path> ficheros;
    {
        std::error_code ec;
        for (fs::recursive_directory_iterator it(raiz, ec), fin; it != fin; it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file(ec)) continue;
            if (it->path().extension() == extension) ficheros.push_back(it->path());
        }
    }
    std::sort(ficheros.begin(), ficheros.end());
    if (maximo > 0 && static_cast<int>(ficheros.size()) > maximo) {
        ficheros.resize(static_cast<size_t>(maximo));
    }
    std::fprintf(stderr, "%zu paquetes a recorrer (%s)\n", ficheros.size(),
                 extension.c_str());

    fs::create_directories(salida);

    std::ostringstream indice;
    int paquetesOk = 0, paquetesMal = 0, secuencias = 0;

    for (size_t i = 0; i < ficheros.size(); ++i) {
        const fs::path& ruta = ficheros[i];
        std::fprintf(stderr, "[%zu/%zu] %s\n", i + 1, ficheros.size(),
                     ruta.filename().string().c_str());

        ue3::Paquete p;
        try {
            p = ue3::Paquete::Abrir(ruta.string());
        } catch (const std::exception& ex) {
            std::fprintf(stderr, "    se salta: %s\n", ex.what());
            ++paquetesMal;
            continue;
        }
        ++paquetesOk;

        // Las secuencias de este paquete.
        std::vector<int> indices;
        for (size_t k = 0; k < p.Exportaciones.size(); ++k) {
            if (EsSecuencia(NombreHoja(p, p.Exportaciones[k].IndiceClase))) {
                indices.push_back(static_cast<int>(k) + 1);
            }
        }
        if (indices.empty()) continue;

        for (int idx : indices) {
            std::string dot;
            if (GrafoADot(p, idx, dot) != 0) continue;

            std::string nombre = p.Texto(p.Exportaciones[static_cast<size_t>(idx - 1)]
                                             .NombreObjeto.Indice);
            for (char& c : nombre) {
                if (c == '/' || c == '\\' || c == ':' || c == '*' ||
                    c == '?' || c == '"' || c == '<' || c == '>' || c == '|') c = '_';
            }
            // El nombre de fichero NO puede ser paquete + nombre de secuencia.
            //
            // Las secuencias de Kismet anidan, y las anidadas repiten nombre: en
            // `industrial06_Gangland` hay 25 objetos distintos llamados
            // `miners_a`, cada uno colgando de una rama distinta. Con
            // paquete + nombre, los 25 escriben al mismo fichero y quedan 24
            // desaparecidos sin que nada avise. Medido: 1.066 secuencias
            // recorridas, 762 ficheros escritos.
            //
            // El indice de exportacion desempata, y es lo unico que lo hace
            // siempre. El nombre largo queda para el indice, que es donde se
            // navega.
            const std::string base = ruta.stem().string() + "-" + nombre + "-" +
                                     std::to_string(idx);
            const std::string destino = (fs::path(salida) / (base + ".html")).string();
            const std::string tmpDot = (fs::path(salida) / (base + ".tmp.dot")).string();
            const std::string tmpSvg = (fs::path(salida) / (base + ".tmp.svg")).string();

            std::string error;
            if (!EjecutaDot("dot", dot, tmpDot, tmpSvg, error)) {
                std::fprintf(stderr, "    dot falla: %s\n", error.c_str());
                continue;
            }
            const std::string svg = LeeFichero(tmpSvg);
            if (svg.empty()) continue;

            const std::string titulo = ruta.stem().string() + "  -  " + nombre;
            const std::string html = EnvuelveEnHtml(svg, titulo);
            std::FILE* f = std::fopen(destino.c_str(), "wb");
            if (f) {
                std::fwrite(html.data(), 1, html.size(), f);
                std::fclose(f);
            }
            std::remove(tmpDot.c_str());
            std::remove(tmpSvg.c_str());

            // En el indice va la ruta entera y no solo el nombre: es lo unico
            // que distingue 25 secuencias iguales llamadas igual.
            indice << "  <li><a href=\"" << base << ".html\">"
                   << p.RutaObjeto(idx) << "</a></li>\n";
            ++secuencias;
        }
    }

    {
        std::ostringstream os;
        os << "<!doctype html>\n<html lang=\"es\"><head><meta charset=\"utf-8\">\n"
              "<title>Kismet de CrimeCraft</title>\n<style>\n"
              "  body{font:14px/1.5 ui-monospace,Consolas,monospace;margin:24px;"
              "max-width:70em;color:#1b1b1f;background:#fbfbfd}\n"
              "  li{margin:2px 0}\n"
              "  .resumen{color:#555;margin-bottom:18px}\n"
              "</style></head><body>\n"
              "<h1>Kismet de CrimeCraft</h1>\n"
              "<p class=\"resumen\">"
           << paquetesOk << " paquetes leidos, " << paquetesMal
           << " descartados, <strong>" << secuencias << "</strong> secuencias.</p>\n"
              "<ul>\n"
           << indice.str()
           << "</ul>\n</body></html>\n";
        const std::string rutaIndice = (fs::path(salida) / "index.html").string();
        std::FILE* f = std::fopen(rutaIndice.c_str(), "wb");
        if (f) {
            const std::string s = os.str();
            std::fwrite(s.data(), 1, s.size(), f);
            std::fclose(f);
        }
    }

    std::fprintf(stderr, "\n%d paquetes leidos, %d descartados, %d secuencias\n",
                 paquetesOk, paquetesMal, secuencias);
    std::fprintf(stderr, "indice: %s\n",
                 (fs::path(salida) / "index.html").string().c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// La jerarquia de clases: la otra mitad de lo que sacaba `gen-cfg-tree`.
//
// Una clase es una exportacion cuya CLASE es `Class` -- el mismo truco de
// mirar el ultimo componente que en las secuencias. Su superclase esta en
// `IndiceSuper` de la tabla de exportaciones, que es justo el campo que el
// lector ya tiene.
//
// Dos precauciones que el tamano impone: sin filtro, `CrimeCraft.u` da decenas
// de miles de clases y el grafo no se lee; y el filtro por raiz exige subir la
// cadena de superclases, que es lo que decide si una clase entra.
// ---------------------------------------------------------------------------
static int CmdJerarquia(const std::string& raiz, const std::string& salida,
                        const std::string& extension, const std::string& claseRaiz,
                        int maximo) {
    namespace fs = std::filesystem;

    std::vector<fs::path> ficheros;
    {
        std::error_code ec;
        for (fs::recursive_directory_iterator it(raiz, ec), fin; it != fin; it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file(ec)) continue;
            if (it->path().extension() == extension) ficheros.push_back(it->path());
        }
    }
    std::sort(ficheros.begin(), ficheros.end());
    if (maximo > 0 && static_cast<int>(ficheros.size()) > maximo) {
        ficheros.resize(static_cast<size_t>(maximo));
    }
    std::fprintf(stderr, "%zu paquetes (%s)\n", ficheros.size(), extension.c_str());

    // clase -> superclase, por ruta. Un mapa ordena y desduplica solo.
    std::map<std::string, std::string> padres;
    int sinSuper = 0;

    for (const fs::path& ruta : ficheros) {
        ue3::Paquete p;
        try {
            p = ue3::Paquete::Abrir(ruta.string());
        } catch (const std::exception& ex) {
            std::fprintf(stderr, "  se salta %s: %s\n",
                         ruta.filename().string().c_str(), ex.what());
            continue;
        }
        int enEste = 0;
        for (size_t k = 0; k < p.Exportaciones.size(); ++k) {
            const auto& e = p.Exportaciones[k];

            // Una clase se reconoce porque NO TIENE CLASE: `IndiceClase == 0`.
            //
            // No es un descuido del cocinero. `UClass` es su propia metaclase
            // --`Class->Class == Class`--, asi que escribir la referencia seria
            // una autorreferencia, y el cargador la resuelve por su cuenta. Lo
            // que queda en el fichero es un cero.
            //
            // La primera version buscaba `NombreHoja(IndiceClase) == "Class"` y
            // encontraba **cero** en los nueve paquetes de guion, porque
            // `Core.Class` no aparece en ningun histograma: nadie apunta a el.
            //
            // La comprobacion de que el cero significa lo que se cree es
            // externa a este lector: `CrimeCraft.u` tiene **1.298** exports sin
            // clase, y la extraccion de UnrealScript de este proyecto recupero
            // **1.293** clases con una herramienta distinta.
            if (e.IndiceClase != 0) continue;
            const std::string nombre = p.RutaObjeto(static_cast<ue3::i32>(k) + 1);
            if (e.IndiceSuper == 0) {
                ++sinSuper;
                padres.emplace(nombre, std::string());
            } else {
                padres[nombre] = p.RutaObjeto(e.IndiceSuper);
            }
            ++enEste;
        }
        std::fprintf(stderr, "  %-28s %5d clases\n",
                     ruta.filename().string().c_str(), enEste);
    }

    // Filtro por raiz: sube la cadena de superclases y comprueba si pasa por
    // ella. Sin esto el grafo de CrimeCraft.u no se puede leer.
    int generadas = 0;
    if (!claseRaiz.empty()) {
        std::vector<std::string> conservar;
        for (const auto& par : padres) {
            std::string a = par.first;
            int saltos = 0;
            while (!a.empty() && saltos++ < 256) {
                if (a == claseRaiz ||
                    a.substr(a.rfind('.') == std::string::npos ? 0 : a.rfind('.') + 1) == claseRaiz) {
                    conservar.push_back(par.first);
                    break;
                }
                auto it = padres.find(a);
                if (it == padres.end()) break;
                a = it->second;
            }
        }
        std::map<std::string, std::string> filtrado;
        for (const std::string& c : conservar) filtrado[c] = padres[c];
        // Las superclases de las conservadas tambien tienen que estar, o las
        // aristas apuntarian a nodos que no existen.
        for (const auto& par : padres) {
            if (filtrado.count(par.second)) filtrado.emplace(par.first, par.second);
        }
        padres.swap(filtrado);
    }
    generadas = static_cast<int>(padres.size());

    std::fprintf(stderr, "clases: %d (%d sin superclase)\n", generadas, sinSuper);
    if (padres.empty()) {
        std::fprintf(stderr, "no hay nada que dibujar\n");
        return 1;
    }

    std::ostringstream os;
    os << "digraph jerarquia {\n"
          "  graph [fontname=\"monospace\", rankdir=BT];\n"
          "  node [fontname=\"monospace\", shape=box];\n"
          "  edge [fontname=\"monospace\"];\n\n";
    for (const auto& par : padres) {
        if (par.second.empty()) continue;
        os << "  \"" << par.first << "\" -> \"" << par.second << "\";\n";
    }
    os << "}\n";

    const std::string tmpDot = salida + ".tmp.dot";
    const std::string tmpSvg = salida + ".tmp.svg";
    std::string error;
    if (!EjecutaDot("dot", os.str(), tmpDot, tmpSvg, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 1;
    }
    const std::string svg = LeeFichero(tmpSvg);
    if (svg.empty()) {
        std::fprintf(stderr, "`dot` no ha producido SVG\n");
        return 1;
    }
    const std::string html = EnvuelveEnHtml(svg, "Jerarquia de clases");
    std::FILE* f = std::fopen(salida.c_str(), "wb");
    if (f) {
        std::fwrite(html.data(), 1, html.size(), f);
        std::fclose(f);
    }
    std::remove(tmpDot.c_str());
    std::remove(tmpSvg.c_str());
    std::fprintf(stderr, "SVG de %zu bytes -> %s\n", svg.size(), salida.c_str());
    return 0;
}

// El volcado: DOT a la salida, y opcionalmente a fichero, y SVG envuelto en una
// pagina si se pide.
static int CmdGrafo(const ue3::Paquete& p, int indice, int argc, char** argv) {
    std::string rutaDot, rutaSvg, rutaDotExe = "dot";
    for (int i = 4; i + 1 < argc; ++i) {
        const std::string op = argv[i];
        if (op == "--svg")            rutaSvg    = argv[i + 1];
        else if (op == "--dot")       rutaDot    = argv[i + 1];
        else if (op == "--dot-exe")   rutaDotExe = argv[i + 1];
    }

    std::string dot;
    const int rc = GrafoADot(p, indice, dot);
    if (rc != 0) return rc;

    if (!rutaDot.empty()) {
        std::FILE* f = std::fopen(rutaDot.c_str(), "wb");
        if (!f) {
            std::fprintf(stderr, "no se puede escribir %s\n", rutaDot.c_str());
            return 1;
        }
        std::fwrite(dot.data(), 1, dot.size(), f);
        std::fclose(f);
        std::fprintf(stderr, "DOT escrito en %s\n", rutaDot.c_str());
    }

    if (rutaSvg.empty()) {
        std::fputs(dot.c_str(), stdout);
        return 0;
    }

    // Los temporales van junto al SVG de salida, no en %TEMP%: asi no hay que
    // adivinar donde esta el directorio temporal, y se ve lo que se deja.
    const std::string tmpDot = rutaSvg + ".dot";
    const std::string tmpSvg = rutaSvg + ".svg";
    std::string error;
    if (!EjecutaDot(rutaDotExe, dot, tmpDot, tmpSvg, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 1;
    }

    const std::string svg = LeeFichero(tmpSvg);
    if (svg.empty()) {
        std::fprintf(stderr, "`dot` no ha producido SVG\n");
        return 1;
    }
    std::fprintf(stderr, "SVG de %zu bytes\n", svg.size());

    const std::string titulo = NombreCorto(p, indice) + "  -  " + p.RutaObjeto(indice);
    const std::string html = EnvuelveEnHtml(svg, titulo);
    std::FILE* f = std::fopen(rutaSvg.c_str(), "wb");
    if (!f) {
        std::fprintf(stderr, "no se puede escribir %s\n", rutaSvg.c_str());
        return 1;
    }
    std::fwrite(html.data(), 1, html.size(), f);
    std::fclose(f);
    std::fprintf(stderr, "pagina escrita en %s\n", rutaSvg.c_str());

    std::remove(tmpDot.c_str());
    std::remove(tmpSvg.c_str());
    return 0;
}

// Las propiedades de una exportacion, tal y como salen del flujo de tags.
static int CmdPropiedades(const ue3::Paquete& p, int indice) {
    if (indice <= 0 || static_cast<size_t>(indice) > p.Exportaciones.size()) {
        std::fprintf(stderr, "no such export %d (there are %zu)\n", indice,
                     p.Exportaciones.size());
        return 2;
    }
    const ue3::Exportacion& e = p.Exportaciones[static_cast<size_t>(indice - 1)];
    std::printf("export %d  \"%s\"  class=%s\n", indice,
                p.Texto(e.NombreObjeto.Indice).c_str(),
                ue3::NombreClaseDe(p, e.IndiceClase).c_str());
    std::printf("path %s\n", p.RutaObjeto(indice).c_str());
    std::printf("data at %d, %d bytes\n\n", e.OffsetSerializado, e.TamanoSerializado);

    const ue3::Flujo f = ue3::LeerFlujo(p, e);
    for (const auto& t : f.Etiquetas) {
        std::printf("  %-30s %-16s tam=%-7d array=%d\n", t.Nombre.c_str(),
                    t.Tipo.c_str(), t.Tamano, t.IndiceArray);
    }
    std::printf("\n  %zu properties; consumed %llu of %d bytes\n",
                f.Etiquetas.size(),
                static_cast<unsigned long long>(f.BytesConsumidos),
                e.TamanoSerializado);
    if (!f.Cierra()) std::printf("  DOES NOT CLOSE: %s\n", f.Error.c_str());
    return f.Cierra() ? 0 : 1;
}

// Cobertura del lector de flujo sobre el paquete entero. Es la medida que dice
// si el lector sirve: un flujo que cierra es una exportacion leida entera.
static int CmdFlujo(const ue3::Paquete& p, int limite) {
    int exact = 0, early = 0, failed = 0, empty = 0;
    std::map<std::string, int> fallosPorClase;
    std::map<std::string, int> sobraPorClase;

    for (size_t i = 0; i < p.Exportaciones.size(); ++i) {
        const auto& e = p.Exportaciones[i];
        if (e.TamanoSerializado <= 0) { ++empty; continue; }
        const ue3::Flujo f = ue3::LeerFlujo(p, e);
        const std::string clase = ue3::NombreClaseDe(p, e.IndiceClase);

        // No basta con que el flujo no de error: el terminador tiene que caer
        // EXACTAMENTE en la frontera de la exportacion. Un flujo que termina
        // antes deja bytes sin explicar, y uno que se pasa esta mal leido. La
        // primera version de esta cuenta solo miraba el error, y daba 1.533
        // cuando las que cierran de verdad son menos.
        if (!f.Cierra()) {
            ++failed;
            fallosPorClase[clase]++;
        } else if (f.BytesConsumidos == static_cast<ue3::u64>(e.TamanoSerializado)) {
            ++exact;
        } else {
            ++early;
            sobraPorClase[clase]++;
        }
    }

    std::printf("exports               %zu\n", p.Exportaciones.size());
    std::printf("  close exactly        %d\n", exact);
    std::printf("  end early         %d\n", early);
    std::printf("  failed               %d\n", failed);
    std::printf("  no data                %d\n", empty);
    std::printf("  NAME_None at index %d\n", p.IndiceNone);
    std::printf("\nclasses with most failures:\n");
    std::vector<std::pair<std::string, int>> orden(fallosPorClase.begin(), fallosPorClase.end());
    std::sort(orden.begin(), orden.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    for (size_t i = 0; i < orden.size() && i < 12; ++i) {
        std::printf("  %-50s %d\n", orden[i].first.c_str(), orden[i].second);
    }
    return 0;
}

static int CmdNombres(const ue3::Paquete& p, int limite) {
    int n = 0;
    for (const auto& e : p.Nombres) {
        if (limite > 0 && n >= limite) break;
        std::printf("%6d  %-48s  cola=0x%08X%08X\n", n, e.Texto.c_str(),
                    e.Cola[1], e.Cola[0]);
        ++n;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        Uso();
        return 2;
    }

    const std::string comando = argv[1];

    // `arbol` no trabaja sobre un paquete sino sobre un directorio entero, asi
    // que se atiende ANTES de intentar abrir nada: si no, intentaria abrir la
    // carpeta como si fuese un paquete y fallaria con un error que no explica
    // nada.
    if (comando == "hierarchy") {
        if (argc < 4) {
            std::fprintf(stderr,
                "uso: ue3kismet jerarquia <directorio> <salida.html> "
                "[ext] [clase-raiz] [max]\n");
            return 2;
        }
        return CmdJerarquia(argv[2], argv[3], argc > 4 ? argv[4] : ".u",
                            argc > 5 ? argv[5] : "", Entero(argc > 6 ? argv[6] : nullptr, 0));
    }

    if (comando == "tree") {
        if (argc < 4) {
            std::fprintf(stderr,
                "uso: ue3kismet arbol <directorio> <salida> [extension] [maximo]\n");
            return 2;
        }
        return CmdArbol(argv[2], argv[3], argc > 4 ? argv[4] : ".ccmap",
                        Entero(argc > 5 ? argv[5] : nullptr, 0));
    }

    if (argc < 3) {
        Uso();
        return 2;
    }

    const std::string ruta = argv[2];
    const int limite = Entero(argc > 3 ? argv[3] : nullptr, 0);

    ue3::Paquete p;
    try {
        p = ue3::Paquete::Abrir(ruta);
    } catch (const ue3::Error& e) {
        std::fprintf(stderr, "error leyendo %s\n  %s\n", ruta.c_str(),
                     e.Completo().c_str());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error inesperado leyendo %s\n  %s\n", ruta.c_str(),
                     e.what());
        return 1;
    }

    if (comando == "info") return CmdInfo(p);
    if (comando == "classes") return CmdClases(p, limite);
    if (comando == "exports") return CmdExportaciones(p, limite);
    if (comando == "imports") return CmdImportaciones(p, limite);
    if (comando == "names") return CmdNombres(p, limite);
    if (comando == "props") return CmdPropiedades(p, Entero(argv[3], 0));
    if (comando == "flow") return CmdFlujo(p, limite);
    if (comando == "refs") return CmdRefs(p, Entero(argv[3], 0));
    if (comando == "graph") return CmdGrafo(p, Entero(argv[3], 0), argc, argv);
    if (comando == "search") {
        // buscar <paquete> <texto> [n] -- argv[3] es el texto, argv[4] el tope.
        if (argc < 4) {
            std::fprintf(stderr, "falta el texto a buscar\n\n");
            Uso();
            return 2;
        }
        return CmdBuscar(p, argv[3], Entero(argc > 4 ? argv[4] : nullptr, 0));
    }
    if (comando == "data") {
        // datos <paquete> <indice> [n] -- argv[3] es el indice, argv[4] el tope.
        return CmdDatos(p, Entero(argv[3], 0), Entero(argc > 4 ? argv[4] : nullptr, 0));
    }

    std::fprintf(stderr, "comando desconocido: %s\n\n", comando.c_str());
    Uso();
    return 2;
}
