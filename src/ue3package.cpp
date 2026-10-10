#include "ue3package.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <sstream>

namespace ue3 {

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

static std::string Hex(u64 v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string Error::Completo() const {
    std::ostringstream os;
    os << Mensaje_ << " (en el offset " << Offset_ << " = " << Hex(Offset_) << ")";
    return os.str();
}

// ---------------------------------------------------------------------------
// Lector
// ---------------------------------------------------------------------------

void Lector::Exige(u64 n) const {
    if (Pos_ + n > Tamano_) {
        std::ostringstream os;
        os << "se piden " << n << " bytes y solo quedan " << (Tamano_ - Pos_);
        throw Error(os.str(), Pos_);
    }
}

void Lector::Ir(u64 pos) {
    if (pos > Tamano_) throw Error("posicion mas alla del final", pos);
    Pos_ = pos;
}

u8 Lector::LeeU8() {
    Exige(1);
    return Datos_[Pos_++];
}

u32 Lector::LeeU32() {
    Exige(4);
    u32 v = static_cast<u32>(Datos_[Pos_]) |
            (static_cast<u32>(Datos_[Pos_ + 1]) << 8) |
            (static_cast<u32>(Datos_[Pos_ + 2]) << 16) |
            (static_cast<u32>(Datos_[Pos_ + 3]) << 24);
    Pos_ += 4;
    return v;
}

i32 Lector::LeeI32() { return static_cast<i32>(LeeU32()); }

std::string Lector::LeeFString() {
    const u64 origen = Pos_;
    i32 n = LeeI32();

    if (n < 0) {
        // Longitud negativa = UTF-16. No se ha observado en este paquete, pero
        // la tabla de nombres lo admite y conviene no tratarlo como corrupcion.
        u64 bytes = static_cast<u64>(-static_cast<int64_t>(n)) * 2;
        Exige(bytes);
        std::string s;
        for (u64 i = 0; i < bytes; i += 2) {
            u16 c = static_cast<u16>(Datos_[Pos_ + i]) |
                    (static_cast<u16>(Datos_[Pos_ + i + 1]) << 8);
            s.push_back(c < 0x80 ? static_cast<char>(c) : '?');
        }
        Pos_ += bytes;
        return s;
    }

    if (n > 65536) {
        std::ostringstream os;
        os << "longitud de cadena absurda: " << n;
        throw Error(os.str(), origen);
    }

    Exige(static_cast<u64>(n));
    std::string s(reinterpret_cast<const char*>(Datos_ + Pos_),
                  static_cast<size_t>(n));
    Pos_ += static_cast<u64>(n);
    // n incluye el terminador; se quita si esta.
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

void Lector::Salta(u64 n) {
    Exige(n);
    Pos_ += n;
}

const u8* Lector::Ventana(u64 n) {
    Exige(n);
    const u8* p = Datos_ + Pos_;
    Pos_ += n;
    return p;
}

// ---------------------------------------------------------------------------
// Paquete
// ---------------------------------------------------------------------------

static const u32 PACKAGE_FILE_TAG = 0x9E2A83C1;
static const u32 PACKAGE_FILE_TAG_SWAPPED = 0xC1832A9E;

// Puertas de version que importan para 576. Se toman de la linea de UE3, no del
// SDK: la rama del SDK ya las podo, y por eso su FGenerationInfo lee un campo
// que 576 si tiene pero 500 no.
static const u32 VER_ADDITIONAL_COOK_PACKAGE_SUMMARY = 516;

Paquete Paquete::Abrir(const std::string& ruta) {
    Paquete p;
    p.Ruta_ = ruta;

    std::FILE* f = std::fopen(ruta.c_str(), "rb");
    if (!f) throw Error("no se puede abrir el fichero: " + ruta, 0);

    std::fseek(f, 0, SEEK_END);
    long largo = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (largo <= 0) {
        std::fclose(f);
        throw Error("fichero vacio o no legible", 0);
    }

    p.Datos_.resize(static_cast<size_t>(largo));
    size_t leido = std::fread(p.Datos_.data(), 1, p.Datos_.size(), f);
    std::fclose(f);
    if (leido != p.Datos_.size()) throw Error("lectura incompleta", leido);

    Lector r(p.Datos_.data(), p.Datos_.size());
    p.AnalizaEncabezado(r);

    if (p.BanderasCompresion != 0) {
        std::ostringstream os;
        os << "el paquete esta comprimido por trozos (CompressionFlags="
           << Hex(p.BanderasCompresion)
           << "). El encabezado se lee, pero el cuerpo no: hace falta inflar.";
        p.Avisos_.push_back(os.str());
    }

    p.AnalizaNombres(r);
    p.AnalizaImportaciones(r);
    p.AnalizaExportaciones(r);
    return p;
}

void Paquete::AnalizaEncabezado(Lector& r) {
    const u64 inicio = r.Pos();
    u32 tag = r.LeeU32();

    if (tag == PACKAGE_FILE_TAG_SWAPPED) {
        throw Error("el paquete esta en el otro orden de bytes "
                    "(PACKAGE_FILE_TAG_SWAPPED); no se lee a medias", inicio);
    }
    if (tag != PACKAGE_FILE_TAG) {
        std::ostringstream os;
        os << "no es un paquete de UE3: el magic es " << Hex(tag)
           << " y deberia ser " << Hex(PACKAGE_FILE_TAG);
        throw Error(os.str(), inicio);
    }

    FileVersion = r.LeeU32();
    TamanoEncabezado = r.LeeI32();
    Carpeta = r.LeeFString();
    BanderasPaquete = r.LeeU32();

    i32 cuentaNombres = r.LeeI32();  OffsetNombres = r.LeeI32();
    i32 cuentaExports = r.LeeI32();  OffsetExportaciones = r.LeeI32();
    i32 cuentaImports = r.LeeI32();  OffsetImportaciones = r.LeeI32();
    OffsetDependencias = r.LeeI32();

    r.Salta(16);                                     // Guid del paquete

    i32 generaciones = r.LeeI32();
    if (generaciones < 0 || generaciones > 64) {
        throw Error("numero de generaciones absurdo", r.Pos() - 4);
    }
    // FGenerationInfo en 576 mide 12 bytes, no 8: lleva ExportCount, NameCount
    // y NetObjectCount. Con 8 el encabezado no llega a NameOffset, y ademas
    // EngineVersion sale 96.161 en vez de 4.701. Ese es el discriminante.
    r.Salta(static_cast<u64>(generaciones) * 12);

    VersionMotor = r.LeeI32();
    VersionContenidoCocinado = r.LeeI32();
    BanderasCompresion = r.LeeU32();

    i32 trozos = r.LeeI32();
    if (trozos < 0 || trozos > 100000) throw Error("numero de trozos absurdo", r.Pos() - 4);
    r.Salta(static_cast<u64>(trozos) * 16);          // FCompressedChunk

    r.Salta(4);                                      // PackageSource

    if (Version() >= VER_ADDITIONAL_COOK_PACKAGE_SUMMARY) {
        i32 extra = r.LeeI32();
        if (extra < 0 || extra > 100000) {
            throw Error("AdditionalPackagesToCook absurdo", r.Pos() - 4);
        }
        for (i32 i = 0; i < extra; ++i) r.LeeFString();
    }

    // La comprobacion que ancla todo lo demas: los campos tienen que haber
    // consumido exactamente hasta donde dice OffsetNombres.
    if (static_cast<i64>(r.Pos()) != OffsetNombres) {
        std::ostringstream os;
        os << "el encabezado termina en " << r.Pos()
           << " pero NameOffset dice " << OffsetNombres;
        throw Error(os.str(), r.Pos());
    }

    {
        std::ostringstream os;
        os << "encabezado: " << r.Pos() << " bytes hasta NameOffset="
           << OffsetNombres;
        Verificaciones_.push_back(os.str());
    }

    // Los contadores se guardan para las funciones siguientes, que van a
    // recorrer las tres tablas.
    CuentaNombres_ = cuentaNombres;
    CuentaImportaciones_ = cuentaImports;
    CuentaExportaciones_ = cuentaExports;
}

void Paquete::AnalizaNombres(Lector& r) {
    r.Ir(static_cast<u64>(OffsetNombres));
    Nombres.clear();
    Nombres.reserve(static_cast<size_t>(CuentaNombres_));

    for (i32 i = 0; i < CuentaNombres_; ++i) {
        EntradaNombre e;
        const u64 origen = r.Pos();
        e.Texto = r.LeeFString();
        // Los 8 bytes de cola. Sin ellos la tabla no cierra: con 4 bytes se
        // desincroniza en la PRIMERA entrada. Se conservan crudos.
        e.Cola[0] = r.LeeU32();
        e.Cola[1] = r.LeeU32();
        if (Nombres.size() > 100000000u) throw Error("tabla de nombres absurda", origen);
        Nombres.push_back(std::move(e));
    }

    if (static_cast<i64>(r.Pos()) != OffsetImportaciones) {
        std::ostringstream os;
        os << "la tabla de nombres termina en " << r.Pos()
           << " pero ImportOffset dice " << OffsetImportaciones;
        throw Error(os.str(), r.Pos());
    }

    std::ostringstream os;
    os << "nombres: " << CuentaNombres_ << " entradas, cierran exactas en "
       << r.Pos() << " = ImportOffset";
    Verificaciones_.push_back(os.str());

    // NAME_None se localiza por su texto, no por su posicion. Ver la nota del
    // encabezado: suponerlo cero rompe el flujo de propiedades de dos maneras
    // opuestas a la vez.
    for (size_t i = 0; i < Nombres.size(); ++i) {
        if (Nombres[i].Texto == "None") { IndiceNone = static_cast<i32>(i); break; }
    }
    if (IndiceNone < 0) Avisos_.push_back("no hay ninguna entrada \"None\" en la tabla de nombres");
}

void Paquete::AnalizaImportaciones(Lector& r) {
    r.Ir(static_cast<u64>(OffsetImportaciones));
    Importaciones.clear();
    Importaciones.reserve(static_cast<size_t>(CuentaImportaciones_));

    for (i32 i = 0; i < CuentaImportaciones_; ++i) {
        Importacion imp;
        imp.PaqueteClase.Indice = r.LeeI32();
        imp.PaqueteClase.Numero = r.LeeI32();
        imp.NombreClase.Indice = r.LeeI32();
        imp.NombreClase.Numero = r.LeeI32();
        imp.IndiceExterno = r.LeeI32();
        imp.NombreObjeto.Indice = r.LeeI32();
        imp.NombreObjeto.Numero = r.LeeI32();
        Importaciones.push_back(imp);
    }

    if (static_cast<i64>(r.Pos()) != OffsetExportaciones) {
        std::ostringstream os;
        os << "la tabla de importaciones termina en " << r.Pos()
           << " pero ExportOffset dice " << OffsetExportaciones;
        throw Error(os.str(), r.Pos());
    }

    // Un indice fuera de rango significa que la entrada mide otra cosa. Se
    // avisa en vez de reventar: el dato sigue siendo util si son pocos.
    int malos = 0;
    for (const auto& imp : Importaciones) {
        if (!imp.NombreObjeto.Valido(CuentaNombres_) ||
            !imp.NombreClase.Valido(CuentaNombres_) ||
            !imp.PaqueteClase.Valido(CuentaNombres_)) {
            ++malos;
        }
    }
    if (malos) {
        std::ostringstream os;
        os << malos << " de " << CuentaImportaciones_
           << " importaciones tienen indices de nombre fuera de rango";
        Avisos_.push_back(os.str());
    }

    std::ostringstream os;
    os << "importaciones: " << CuentaImportaciones_ << " entradas de 28 bytes, "
       << "cierran exactas en " << r.Pos() << " = ExportOffset";
    Verificaciones_.push_back(os.str());
}

void Paquete::AnalizaExportaciones(Lector& r) {
    r.Ir(static_cast<u64>(OffsetExportaciones));
    Exportaciones.clear();
    Exportaciones.reserve(static_cast<size_t>(CuentaExportaciones_));

    int objetosRedTotal = 0;
    int tamanoCero = 0;
    int fueraDelFichero = 0;
    int dentroDelEncabezado = 0;
    int encadenan = 0, conDatos = 0;
    i64 anteriorOffset = -1, anteriorTamano = 0;
    i64 menorDato = -1, mayorFin = 0;

    for (i32 i = 0; i < CuentaExportaciones_; ++i) {
        const u64 origen = r.Pos();
        Exportacion e;
        e.IndiceClase = r.LeeI32();
        e.IndiceSuper = r.LeeI32();
        e.IndiceExterno = r.LeeI32();
        e.NombreObjeto.Indice = r.LeeI32();
        e.NombreObjeto.Numero = r.LeeI32();
        e.IndiceArquetipo = r.LeeI32();
        e.Desconocido1 = r.LeeI32();
        e.Desconocido2 = r.LeeI32();
        e.TamanoSerializado = r.LeeI32();
        e.OffsetSerializado = r.LeeI32();
        e.BanderasExport = r.LeeI32();

        i32 objetosRed = r.LeeI32();
        if (objetosRed < 0 || objetosRed > 4096) {
            std::ostringstream os;
            os << "la exportacion " << i << " declara " << objetosRed
               << " objetos de red; la tabla se ha desincronizado";
            throw Error(os.str(), origen);
        }
        e.ObjetosRed.resize(static_cast<size_t>(objetosRed));
        for (i32 j = 0; j < objetosRed; ++j) e.ObjetosRed[j] = r.LeeI32();
        objetosRedTotal += objetosRed;

        std::memcpy(e.Guid, r.Ventana(16), 16);
        e.BanderasPaquete = r.LeeU32();

        // Encadenado: los datos de una exportacion empiezan donde terminan los
        // de la anterior. Es lo que valida que +32 sea el tamano y +36 el
        // desplazamiento, y no dos campos cualesquiera que casualmente crecen.
        if (e.TamanoSerializado > 0) {
            ++conDatos;
            if (e.OffsetSerializado < OffsetDependencias) ++dentroDelEncabezado;
            if (e.OffsetSerializado < 0 ||
                static_cast<i64>(e.OffsetSerializado) + e.TamanoSerializado >
                    static_cast<i64>(Tamano())) {
                ++fueraDelFichero;
            }
            if (anteriorOffset >= 0 &&
                e.OffsetSerializado == anteriorOffset + anteriorTamano) {
                ++encadenan;
            }
            anteriorOffset = e.OffsetSerializado;
            anteriorTamano = e.TamanoSerializado;
            if (menorDato < 0 || e.OffsetSerializado < menorDato) menorDato = e.OffsetSerializado;
            mayorFin = std::max<i64>(mayorFin, static_cast<i64>(e.OffsetSerializado) + e.TamanoSerializado);
        } else {
            ++tamanoCero;
        }

        Exportaciones.push_back(std::move(e));
    }

    if (static_cast<i64>(r.Pos()) != OffsetDependencias) {
        std::ostringstream os;
        os << "la tabla de exportaciones termina en " << r.Pos()
           << " pero DependsOffset dice " << OffsetDependencias;
        throw Error(os.str(), r.Pos());
    }

    TamanoObjetosRed = objetosRedTotal;
    {
        std::ostringstream os;
        os << "exportaciones: " << CuentaExportaciones_ << " entradas ("
           << objetosRedTotal << " objetos de red repartidos), cierran exactas en "
           << r.Pos() << " = DependsOffset";
        Verificaciones_.push_back(os.str());
    }
    {
        std::ostringstream os;
        os << "datos: " << conDatos << " exportaciones con contenido, de "
           << menorDato << " a " << mayorFin << "; el fichero mide " << Tamano()
           << " y el encabezado acaba en " << OffsetDependencias;
        Verificaciones_.push_back(os.str());
    }
    {
        std::ostringstream os;
        os << "encadenado de desplazamientos: " << encadenan << " de "
           << (conDatos - 1) << " parejas consecutivas";
        Verificaciones_.push_back(os.str());
    }
    if (dentroDelEncabezado || fueraDelFichero) {
        std::ostringstream os;
        os << "exportaciones con datos mal situados: " << dentroDelEncabezado
           << " dentro del encabezado, " << fueraDelFichero << " fuera del fichero";
        Avisos_.push_back(os.str());
    }
    (void)tamanoCero;
}

// ---------------------------------------------------------------------------
// Consultas
// ---------------------------------------------------------------------------

std::string Paquete::Texto(i32 indice) const {
    if (indice < 0 || indice >= static_cast<i32>(Nombres.size())) {
        std::ostringstream os;
        os << "<nombre " << indice << " fuera de rango>";
        return os.str();
    }
    return Nombres[static_cast<size_t>(indice)].Texto;
}

std::string Paquete::RutaObjeto(i32 indice) const {
    // Las exportaciones se numeran desde 1 en los indices; 0 es "nada".
    std::string ruta;
    int saltos = 0;
    i32 actual = indice;

    while (actual != 0 && saltos++ < 64) {
        if (actual > 0) {
            size_t k = static_cast<size_t>(actual - 1);
            if (k >= Exportaciones.size()) break;
            const Exportacion& e = Exportaciones[k];
            ruta = Texto(e.NombreObjeto.Indice) +
                   (ruta.empty() ? "" : "." + ruta);
            actual = e.IndiceExterno;
        } else {
            size_t k = static_cast<size_t>(-actual - 1);
            if (k >= Importaciones.size()) break;
            const Importacion& im = Importaciones[k];
            ruta = Texto(im.NombreObjeto.Indice) +
                   (ruta.empty() ? "" : "." + ruta);
            actual = im.IndiceExterno;
        }
    }
    return ruta;
}

// El nombre de la clase de un objeto es LA RUTA DEL OBJETO QUE ES LA CLASE.
//
// Esto estuvo mal, y de la manera que este proyecto ya tiene fichada: los
// cierres de tabla pasaban todos, porque validan el TAMANO de las tablas, no
// el SIGNIFICADO de cada campo. Y el campo estaba bien; lo que estaba mal era
// como lo leia.
//
// En UE3 la clase Engine.AmbientSound se importa como una entrada cuyo
// ClassName es "Class" y cuyo ObjectName es "AmbientSound". Leer
// (ClassPackage, ClassName) de esa entrada devuelve "Core.Class" -- que es
// cierto: dice que la clase es una clase. Y como todas las clases lo son,
// las 1.711 exportaciones del mapa salian con la misma "clase".
//
// El nombre util es el camino del objeto -- ObjectName encadenado por
// OuterIndex --, que da "Engine.AmbientSound".
std::string NombreClaseDe(const Paquete& p, i32 indice) {
    if (indice == 0) return "(ninguna)";
    return p.RutaObjeto(indice);
}

// ---------------------------------------------------------------------------
// Flujo de propiedades taggeadas
// ---------------------------------------------------------------------------

// Puertas de version, de UnObjVer.h. El paquete de CrimeCraft es 576, asi que
// las dos estan POR DEBAJO y las dos ramas viejas son las que aplican.
static const u32 VER_BYTEPROP_SERIALIZE_ENUM = 633;
static const u32 VER_PROPERTYTAG_BOOL_OPTIMIZATION = 673;

// Los datos de cada exportacion empiezan con cuatro bytes que no son parte de
// ningun tag.
//
// NO ESTA IDENTIFICADO. Es un contador que incrementa de uno en uno dentro de
// tramos -- 2..9, luego 4124..4132, luego 184..199, y 682 tramos en un mapa de
// 1.711 exportaciones -- y no es un indice de nombre, porque 4.124 excede las
// 1.511 entradas de la tabla.
//
// No hace falta entenderlo para leer, y eso esta comprobado: saltando estos
// cuatro bytes, 1.280 de 1.711 exportaciones cierran exactamente en su
// frontera. Pero queda anotado como desconocido, no barrido debajo de la
// alfombra.
static const u64 PREFIJO_EXPORTACION = 4;

Flujo LeerFlujo(const Paquete& p, const Exportacion& e) {
    Flujo f;
    const u64 inicio = static_cast<u64>(e.OffsetSerializado);
    const u64 fin = inicio + static_cast<u64>(e.TamanoSerializado);

    if (fin > p.Datos().size()) {
        f.Error = "la exportacion se sale del fichero";
        return f;
    }
    if (e.TamanoSerializado < static_cast<i32>(PREFIJO_EXPORTACION)) {
        f.Error = "la exportacion es mas corta que el prefijo";
        return f;
    }

    f = LeerFlujoEntre(p, inicio + PREFIJO_EXPORTACION, fin);
    // `BytesConsumidos` vuelve relativo al inicio del flujo; se reexpresa
    // respecto al principio de la exportacion, que es lo que compara quien
    // llama para saber si el terminador cayo en la frontera.
    if (f.Cierra()) f.BytesConsumidos += PREFIJO_EXPORTACION;
    return f;
}

Flujo LeerFlujoEntre(const Paquete& p, u64 inicio, u64 fin) {
    Flujo f;
    Lector r(p.Datos().data(), p.Datos().size());

    if (fin > p.Datos().size()) {
        f.Error = "el flujo se sale del fichero";
        return f;
    }
    r.Ir(inicio);

    for (;;) {
        const u64 offsetCampos = r.Pos();
        if (offsetCampos + 8 > fin) { f.Error = "sin espacio para el nombre del tag"; return f; }

        const i32 iNombre = r.LeeI32();
        r.LeeI32();                                     // numero del FName

        // El terminador es NAME_None, localizado por TEXTO en la tabla.
        if (iNombre == p.IndiceNone) {
            f.BytesConsumidos = r.Pos() - inicio;
            return f;
        }
        if (iNombre < 0 || iNombre >= static_cast<i32>(p.Nombres.size())) {
            f.Error = "indice de nombre fuera de rango";
            return f;
        }

        if (r.Pos() + 16 > fin) { f.Error = "sin espacio para el tipo del tag"; return f; }
        const i32 iTipo = r.LeeI32();
        r.LeeI32();
        if (iTipo < 0 || iTipo >= static_cast<i32>(p.Nombres.size())) {
            f.Error = "indice de tipo fuera de rango";
            return f;
        }

        const i32 tamano = r.LeeI32();
        const i32 indiceArray = r.LeeI32();
        if (tamano < 0) { f.Error = "tamano negativo"; return f; }

        const std::string& tipo = p.Nombres[static_cast<size_t>(iTipo)].Texto;

        if (tipo == "StructProperty") {
            if (r.Pos() + 8 > fin) { f.Error = "sin espacio para StructName"; return f; }
            r.Salta(8);
        } else if (tipo == "BoolProperty") {
            // PUERTA. Bajo 673 el tag lleva un UBOOL de cuatro bytes; a partir
            // de ahi, un BYTE. Con el tamano equivocado el flujo se desalinea
            // exactamente tres, y el tag siguiente sale con un nombre imposible.
            const u64 cuantos = (p.Version() >= VER_PROPERTYTAG_BOOL_OPTIMIZATION) ? 1 : 4;
            if (r.Pos() + cuantos > fin) { f.Error = "sin espacio para BoolVal"; return f; }
            r.Salta(cuantos);
        } else if (tipo == "ByteProperty") {
            if (p.Version() >= VER_BYTEPROP_SERIALIZE_ENUM) {
                if (r.Pos() + 8 > fin) { f.Error = "sin espacio para EnumName"; return f; }
                r.Salta(8);
            }
        }

        if (r.Pos() + static_cast<u64>(tamano) > fin) {
            f.Error = "los datos del tag se salen de la exportacion";
            return f;
        }

        Etiqueta et;
        et.Nombre = p.Nombres[static_cast<size_t>(iNombre)].Texto;
        et.Tipo = tipo;
        et.Tamano = tamano;
        et.IndiceArray = indiceArray;
        et.OffsetCampos = offsetCampos;
        et.OffsetDatos = r.Pos();
        f.Etiquetas.push_back(std::move(et));

        r.Salta(static_cast<u64>(tamano));
    }
}

std::vector<RecuentoClase> RecuentarPorClase(const Paquete& p) {
    std::map<std::string, int> cuenta;
    for (const auto& e : p.Exportaciones) {
        cuenta[NombreClaseDe(p, e.IndiceClase)]++;
    }

    std::vector<RecuentoClase> v;
    v.reserve(cuenta.size());
    for (const auto& par : cuenta) v.push_back({par.first, par.second});
    std::sort(v.begin(), v.end(), [](const RecuentoClase& a, const RecuentoClase& b) {
        if (a.Cuenta != b.Cuenta) return a.Cuenta > b.Cuenta;
        return a.Clase < b.Clase;
    });
    return v;
}

}  // namespace ue3
