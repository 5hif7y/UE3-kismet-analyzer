// ue3package.h -- lector de paquetes de Unreal Engine 3, version 576.
//
// Esto es la mitad "UE3" del port de kismet-analyzer. La otra mitad, la que
// analiza el bytecode y dibuja el grafo, se apoya en esto.
//
// POR QUE UN LECTOR PROPIO
// ------------------------
// A UE3 engine's own linker knows how to read packages, and it in fact reads the
// header, the name table, the import table and the export table of a real cooked
// package correctly. It fails later, while building the objects. But
// es que ademas no puede leer los .ccmap del juego, que necesitan el motor de
// Vogster.
//
// Un lector propio se puede apuntar a cualquier cosa, y cuando falla dice
// donde. Ese es todo el argumento.
//
// LA ESPECIFICACION ESTA MEDIDA, NO COPIADA
// -----------------------------------------
// El SDK es una rama tardia de UE3 y ya no conserva las puertas de version de
// la epoca de 576, asi que su codigo no sirve como fuente. Los formatos de
// abajo se midieron contra CrimeCraft.u (366.986.751 bytes) y se verificaron
// por cierre: cada tabla tiene que terminar exactamente donde el encabezado
// says the next one begins. That is what every check below verifies.
//
//   encabezado   109 bytes hasta NameOffset, con FolderName="None"
//   nombres      [i32 len][len bytes][8 de cola]            56.719 entradas
//   importacion  28 bytes = FName(8) FName(8) i32 FName(8)   1.992 entradas
//   exportacion  68 bytes + 4 por objeto de red            185.659 entradas
//
// Y el cierre que lo vuelve concluyente: los datos de las exportaciones empiezan
// en 15.252.613 (= TotalHeaderSize) y terminan en 366.986.751 (= tamano del
// fichero). Sin huecos y sin desbordes, en 367 MB.

#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace ue3 {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using i32 = int32_t;
using u64 = uint64_t;
using i64 = int64_t;

// ---------------------------------------------------------------------------
// Un fallo de lectura, con el offset donde ocurrio.
//
// Importa que lleve el offset: leer un formato binario sin saber DONDE se
// desincronizo convierte cada fallo en una caza. El proyecto ya pago ese precio
// una vez con el desincronizado de CrimeCraft.u.
// ---------------------------------------------------------------------------
class Error {
public:
    Error(std::string mensaje, u64 offset)
        : Mensaje_(std::move(mensaje)), Offset_(offset) {}

    const std::string& Mensaje() const { return Mensaje_; }
    u64 Offset() const { return Offset_; }

    std::string Completo() const;

private:
    std::string Mensaje_;
    u64 Offset_;
};

// ---------------------------------------------------------------------------
// Lector secuencial sobre el fichero entero en memoria.
//
// Todo es little-endian. UE3 admite ficheros con el magic invertido
// (PACKAGE_FILE_TAG_SWAPPED) y en ese caso habria que invertir; se detecta y se
// dice, en vez de devolver numeros plausibles y falsos.
// ---------------------------------------------------------------------------
class Lector {
public:
    Lector(const u8* datos, u64 tamano)
        : Datos_(datos), Tamano_(tamano), Pos_(0) {}

    u64 Pos() const { return Pos_; }
    void Ir(u64 pos);
    u64 Tamano() const { return Tamano_; }

    u8 LeeU8();
    u32 LeeU32();
    i32 LeeI32();
    // Lee un FString: [i32 n][n bytes]. Si el ultimo byte es NUL se quita,
    // porque n cuenta el terminador. Verificado en la tabla de nombres: una
    // entrada con n=5 da "+180".
    std::string LeeFString();
    void Salta(u64 n);
    const u8* Ventana(u64 n);

private:
    void Exige(u64 n) const;

    const u8* Datos_;
    u64 Tamano_;
    u64 Pos_;
};

// ---------------------------------------------------------------------------
// Un nombre de la tabla.
//
// Los 8 bytes de cola no estan identificados. Se midieron porque sin ellos la
// tabla no cierra, y se sabe que no son cero (la primera entrada lleva
// 0x00070010), pero no se ha establecido que significan. Se conservan crudos
// para no perder el dato.
// ---------------------------------------------------------------------------
struct EntradaNombre {
    std::string Texto;
    u32 Cola[2] = {0, 0};
};

// FName en disco: indice y numero. Ocho bytes, no cuatro.
//
// Esto es lo que costo mas caro de ver. Con FName de 4 bytes la tabla de
// importaciones mide 16 y no cuadra: mide 28. Los dos enteros que acompanan a
// cada indice valen siempre 0, y eso los delata como el campo "numero" de un
// FName, no como campos sueltos.
struct Nombre {
    i32 Indice = 0;
    i32 Numero = 0;

    bool Valido(i32 total) const { return Indice >= 0 && Indice < total; }
};

struct Importacion {
    Nombre PaqueteClase;
    Nombre NombreClase;
    i32 IndiceExterno = 0;   // negativo = otra importacion; positivo = exportacion
    Nombre NombreObjeto;
};

struct Exportacion {
    i32 IndiceClase = 0;
    i32 IndiceSuper = 0;
    i32 IndiceExterno = 0;
    Nombre NombreObjeto;
    i32 IndiceArquetipo = 0;
    i32 Desconocido1 = 0;    // +24, siempre 0 en lo medido
    i32 Desconocido2 = 0;    // +28, constante 0x00070004 en lo medido
    i32 TamanoSerializado = 0;
    i32 OffsetSerializado = 0;
    i32 BanderasExport = 0;
    std::vector<i32> ObjetosRed;
    u8 Guid[16] = {0};
    u32 BanderasPaquete = 0;
};

// ---------------------------------------------------------------------------
// El paquete.
// ---------------------------------------------------------------------------
class Paquete {
public:
    // Carga el fichero entero y analiza el encabezado y las tres tablas.
    // Lanza Error si algo no cuadra.
    static Paquete Abrir(const std::string& ruta);

    // --- Encabezado ---
    u32 FileVersion = 0;
    u32 Version() const { return FileVersion & 0xffff; }
    u32 Licencia() const { return (FileVersion >> 16) & 0xffff; }
    i32 TamanoEncabezado = 0;
    std::string Carpeta;
    u32 BanderasPaquete = 0;
    i32 OffsetNombres = 0, OffsetExportaciones = 0, OffsetImportaciones = 0;
    i32 OffsetDependencias = 0;
    i32 VersionMotor = 0;
    i32 VersionContenidoCocinado = 0;
    u32 BanderasCompresion = 0;
    i32 TamanoObjetosRed = 0;

    // --- Tablas ---
    std::vector<EntradaNombre> Nombres;
    std::vector<Importacion> Importaciones;
    std::vector<Exportacion> Exportaciones;

    // Indice de la entrada "None" en la tabla de nombres.
    //
    // NO es el cero. El flujo de propiedades termina cuando el nombre del tag es
    // NAME_None, y NAME_None es la entrada cuyo TEXTO es "None": en
    // EntryLevel.ccmap esta en el 936, y el indice 0 es '3_blend_dirt_map'. En
    // CrimeCraft.u el 0 es un nombre de nivel. Suponerlo cero da a la vez cierres
    // donde no toca y no-cierres donde toca.
    i32 IndiceNone = -1;

    // Texto de un nombre por indice, o "<N>" si esta fuera de rango. No lanza:
    // sirve justo para depurar los casos en que el indice no cuadra.
    std::string Texto(i32 indice) const;

    // Ruta completa de un objeto a partir de su indice de paquete, subiendo por
    // la cadena de IndiceExterno. Vale para exportaciones (positivo) y para
    // importaciones (negativo).
    std::string RutaObjeto(i32 indice) const;

    const std::vector<u8>& Datos() const { return Datos_; }
    const std::string& Ruta() const { return Ruta_; }
    u64 Tamano() const { return Datos_.size(); }

    // Comprobaciones que se hicieron al abrir y salieron bien. Se guardan para
    // poder imprimirlas: en este proyecto, una verificacion que no se cuenta es
    // una verificacion que nadie puede auditar.
    const std::vector<std::string>& Verificaciones() const { return Verificaciones_; }

    // Avisos: cosas que se pudieron leer pero que no cuadran del todo.
    const std::vector<std::string>& Avisos() const { return Avisos_; }

private:
    void AnalizaEncabezado(Lector& r);
    void AnalizaNombres(Lector& r);
    void AnalizaImportaciones(Lector& r);
    void AnalizaExportaciones(Lector& r);

    std::vector<u8> Datos_;
    std::string Ruta_;
    std::vector<std::string> Verificaciones_;
    std::vector<std::string> Avisos_;

    // Los contadores se leen en el encabezado y los consumen las tablas, que
    // van despues. Se guardan aqui en vez de releerlos de los offsets.
    i32 CuentaNombres_ = 0;
    i32 CuentaImportaciones_ = 0;
    i32 CuentaExportaciones_ = 0;
};

// Nombre de clase de una exportacion o importacion, resuelto a "Paquete.Clase".
// Los indices negativos son importaciones; los positivos, exportaciones.
std::string NombreClaseDe(const Paquete& p, i32 indice);

// ---------------------------------------------------------------------------
// El flujo de propiedades taggeadas de una exportacion.
//
// Formato, de Development/Src/Core/Inc/UnPropertyTag.h:58:
//
//   FName Name         (8)   indice + numero
//   FName Type         (8)
//   INT   Size         (4)
//   INT   ArrayIndex   (4)
//   [FName StructName]  solo si Type == StructProperty
//   [BoolVal]           solo si Type == BoolProperty; 4 bytes bajo 673, 1 sobre
//   [FName EnumName]    solo si Type == ByteProperty y version >= 633
//
// y despues, Size bytes de datos del valor.
// ---------------------------------------------------------------------------
struct Etiqueta {
    std::string Nombre;
    std::string Tipo;
    i32 Tamano = 0;
    i32 IndiceArray = 0;
    u64 OffsetDatos = 0;      // absoluto en el fichero
    u64 OffsetCampos = 0;     // donde empiezan los campos del tag
};

struct Flujo {
    std::vector<Etiqueta> Etiquetas;
    u64 BytesConsumidos = 0;
    std::string Error;        // vacio = el flujo se leyo entero

    bool Cierra() const { return Error.empty(); }
};

// Lee el flujo de una exportacion. No lanza: un flujo mal formado es un
// resultado, no una excepcion, porque se espera encontrarlos.
Flujo LeerFlujo(const Paquete& p, const Exportacion& e);

// Lee un flujo de tags entre dos offsets cualesquiera, SIN el prefijo de cuatro
// bytes que llevan las exportaciones.
//
// Es la forma ANIDADA, y es la que hace falta para el Kismet: los elementos de
// `OutputLinks` e `InputLinks` no son un bloque binario, son un flujo de tags
// otra vez. Un `FSeqOpInputLink` sale asi, y cierra exacto:
//
//   LinkDesc           StrProperty    tam=18   ("Default Input")
//   bHasImpulse        BoolProperty   tam=0
//   QueuedActivations  IntProperty    tam=4
//   bDisabled          BoolProperty   tam=0
//   bDisabledPIE       BoolProperty   tam=0
//   LinkedOp           ObjectProperty tam=4    <- la arista
//   DrawY              IntProperty    tam=4
//   bHidden            BoolProperty   tam=0
//   ActivateDelay      FloatProperty  tam=4
//
// Son los nueve campos que declara EngineSequenceClasses.h:395, en su orden.
Flujo LeerFlujoEntre(const Paquete& p, u64 inicio, u64 fin);

// Cuenta cuantas exportaciones de cada clase hay, por nombre de clase resuelto.
// Es el primer dato util para saber que hay dentro de un paquete.
struct RecuentoClase {
    std::string Clase;
    int Cuenta = 0;
};

std::vector<RecuentoClase> RecuentarPorClase(const Paquete& p);

}  // namespace ue3
