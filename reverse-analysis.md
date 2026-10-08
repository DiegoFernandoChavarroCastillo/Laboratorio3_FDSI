# Laboratorio 4 — Parte 2: Reverse Engineering Challenge

**Equipo:** E07 — Diego Fernando Chavarro Castillo · Juan Pablo Caballero Castellanos
**Asignatura:** FDSI — Fundamentos de Seguridad / Secure Product Challenge
**Docente:** Fabián Eduardo Sierra Sánchez
**Ruta:** alternativa local (CTF de ingeniería inversa, sin publicar servicios)

> **Estado del documento:** completo. Cubre **0. Preparación**, **1. Baseline forense**, **2. Level 1**, **3. Level 2**, **4. Confirmación con GDB**, **5. Boss Level (stripped)**, las **preguntas de análisis** de la guía y el guion de sustentación de 3 minutos.

---

## 📑 Índice

| Sección | Contenido | Estado |
| :--- | :--- | :--- |
| [0. Preparación](#0-preparación) | Entorno, herramientas y estructura de evidencias | ✅ Completado |
| [1. Baseline forense](#1-baseline-forense) | `file`, `sha256sum`, `readelf -h` sobre los tres binarios | ✅ Completado |
| [2. Level 1 — Recon](#2-level-1--recon-strings-are-evidence) | `strings`, `objdump`, primera FLAG → detalle en [`level1.md`](evidence/reverse/level1.md) | ✅ Completado |
| [3. Level 2 — Ghidra](#3-level-2--ghidra-reconstruir-la-validación) | Reconstrucción de la función de validación → detalle en [`level2.md`](evidence/reverse/level2.md) | ✅ Completado |
| [4. Confirmación con GDB](#4-confirmación-dinámica-con-gdb) | Validación dinámica de la hipótesis → detalle en [`gdb.md`](evidence/reverse/gdb.md) | ✅ Completado |
| [5. Boss Level — Stripped](#5-boss-level--binario-sin-símbolos) | Análisis sin símbolos → detalle en [`boss.md`](evidence/reverse/boss.md) | ✅ Completado |
| [6. Preguntas de análisis](#6-preguntas-de-análisis) | Las siete preguntas de la guía, respondidas con la evidencia del laboratorio | ✅ Completado |
| [7. Sustentación de 3 minutos](#7-guion-de-sustentación-de-3-minutos) | Guion de las cinco preguntas del cierre | ✅ Completado |
| [8. Cierre de la entrega](#8-cierre-de-la-entrega) | Checklist de la guía (sección 6) y etiquetado | ✅ Completado (con limitaciones declaradas) |

---

## 🎯 Alcance y reglas

- Los binarios son **crackmes académicos** entregados por el docente para ser analizados. No se analizó ningún otro ejecutable.
- **No se abrió ni se solicitó el código fuente.** Todo lo que aquí se afirma sale de la inspección del binario.
- El ejercicio es **completamente local**: no usa Nginx, Tailscale, UFW ni el API del Incident Hub del Laboratorio 3. Esa infraestructura queda en reposo.

---

## 0. Preparación

### Entorno

| Dato | Valor |
| :--- | :--- |
| Analista | Juan Pablo Caballero Castellanos |
| Sistema | Kali Linux (x86-64) |
| Formato esperado de los binarios | ELF Linux x86-64 |
| Herramientas | `file`, `sha256sum`, `readelf`, `strings`, `objdump` (binutils), `gdb`, Ghidra |

La arquitectura del equipo de análisis coincide con la de los binarios (x86-64), por lo que pueden **ejecutarse de forma nativa**, sin emulación. Esto es requisito para la fase dinámica con GDB.

### Instalación de herramientas

```bash
sudo apt update
sudo apt install -y binutils gdb file
# Ghidra: distribución oficial (NSA / ghidra-sre.org)
```

### Material recibido

El paquete `FDSI_Guia2_Reverse_Engineering_ESTUDIANTES.zip` contiene únicamente:

```text
crackme_level1
crackme_level2
crackme_level2_stripped
Guia_2_FDSI_Reverse_Engineering_CTF.html
README_ESTUDIANTE.md
```

### Estructura de evidencias

Las evidencias de este laboratorio se guardan dentro del mismo repositorio, bajo `evidence/reverse/`:

```text
evidence/
└── reverse/
    ├── baseline.txt        # salida cruda de file, sha256sum y readelf
    ├── level1.md
    ├── level2.md
    ├── gdb.md
    ├── boss.md             # Boss Level (binario stripped)
    ├── boss-evidence.sh    # reproduce los comandos del Boss Level
    ├── boss-output.txt     # salida cruda generada por boss-evidence.sh
    └── screenshots/        # capturas de cada comando
```

> **Nota sobre la ruta.** El enunciado propone `docs/evidence/reverse/`. En este repositorio se mantiene la convención ya establecida en el Laboratorio 3, donde `evidence/` agrupa las salidas técnicas (`red/`, `blue/`, `retest/`, `mejoras/`). Se agregó `reverse/` como una carpeta hermana para no mezclar dos convenciones en el mismo proyecto. El contenido es exactamente el que pide la guía.

---

## 1. Baseline forense

**Objetivo:** antes de ejecutar o desensamblar nada, fijar qué es cada archivo (formato, arquitectura, enlazado, símbolos) y demostrar que es el mismo material que entregó el docente.

Comandos ejecutados, en este orden:

```bash
file crackme_level1
file crackme_level2
file crackme_level2_stripped

sha256sum crackme_level1 crackme_level2 crackme_level2_stripped

readelf -h crackme_level1
readelf -h crackme_level2
readelf -h crackme_level2_stripped   # complementario
```

Cada comando tiene su captura en `evidence/reverse/screenshots/`, numerada de `1.1` a `1.7` (ver tabla de evidencias en la sección 1.7).

### 1.1 Identificación del formato con `file`

`file` no confía en la extensión del archivo (los tres binarios no tienen ninguna). Lee los primeros bytes —el *magic number*— y la cabecera, y a partir de ellos describe el tipo real del archivo.

**`crackme_level1`**

*Captura 1.1*

![1.1 — file crackme_level1](evidence/reverse/screenshots/1.1.jpeg)

**`crackme_level2`**

*Captura 1.2*

![1.2 — file crackme_level2](evidence/reverse/screenshots/1.2.jpeg)

**`crackme_level2_stripped`**

*Captura 1.3*

![1.3 — file crackme_level2_stripped](evidence/reverse/screenshots/1.3.jpeg)

**Salida resumida:**

```text
crackme_level1:          ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
                         interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=01c8816f...,
                         for GNU/Linux 3.2.0, with debug_info, not stripped
crackme_level2:          ELF 64-bit LSB executable, x86-64, ... BuildID[sha1]=3eb5b89d...,
                         for GNU/Linux 3.2.0, with debug_info, not stripped
crackme_level2_stripped: ELF 64-bit LSB executable, x86-64, ... BuildID[sha1]=df25a1fa...,
                         for GNU/Linux 3.2.0, stripped
```

**Interpretación campo por campo:**

| Campo | Valor observado | Qué significa para el análisis |
| :--- | :--- | :--- |
| Formato | `ELF 64-bit` | Ejecutable nativo de Linux, formato de 64 bits |
| Orden de bytes | `LSB` | *Little endian*: los valores multibyte se almacenan con el byte menos significativo primero. Hay que tenerlo presente al leer constantes en el volcado hexadecimal |
| Arquitectura | `x86-64` | Se desensambla con el juego de instrucciones AMD64; se ejecuta de forma nativa en Kali |
| Tipo | `executable` | Ejecutable de direcciones fijas (no PIE). Se confirma en `readelf` más abajo |
| Enlazado | `dynamically linked` | Depende de bibliotecas compartidas (`libc.so.6`) cargadas en tiempo de ejecución por el intérprete `/lib64/ld-linux-x86-64.so.2`. Las llamadas a funciones de la libc (p. ej., `strlen`, `printf`, `puts`) aparecen por su nombre en la tabla de importaciones, **incluso en la versión stripped** |
| `BuildID` | distinto en los tres | Identificador único de cada compilación. Que `level2` y `level2_stripped` tengan BuildID distinto indica que no son byte a byte el mismo archivo con una sección borrada, sino artefactos generados por separado |
| Depuración | `with debug_info` (level1, level2) | Contienen secciones DWARF (`.debug_info`, `.debug_line`, etc.): nombres de funciones, variables locales, tipos y hasta líneas de código fuente. Esto facilita mucho el trabajo en Ghidra y GDB |
| Símbolos | `not stripped` / `stripped` | **Diferencia clave del reto.** Los dos primeros conservan la tabla de símbolos (`.symtab`); el tercero no |

**Primera conclusión:** los tres son del mismo tipo y arquitectura. Lo único que cambia es **cuánta información de ayuda trae cada uno**. `crackme_level2_stripped` es el caso realista: el software comercial y el malware casi nunca se distribuyen con símbolos ni información de depuración. Esto anticipa el Boss Level: allí habrá que identificar las funciones por su comportamiento, no por su nombre.

### 1.2 Integridad con `sha256sum`

*Captura 1.4*

![1.4 — sha256sum de los tres binarios](evidence/reverse/screenshots/1.4.jpeg)

**Comparación contra los hashes publicados por el docente** (guía, sección 1, y `README_ESTUDIANTE.md`):

| Archivo | SHA-256 obtenido | SHA-256 esperado | Coincide |
| :--- | :--- | :--- | :---: |
| `crackme_level1` | `61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c` | `61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c` | ✅ |
| `crackme_level2` | `8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5` | `8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5` | ✅ |
| `crackme_level2_stripped` | `c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3` | `c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3` | ✅ |

Los tres coinciden: **el material analizado es exactamente el entregado**.

**¿Por qué un hash garantiza que todos analizan el mismo binario?**

SHA-256 produce una huella de 256 bits que cambia por completo si se altera **un solo bit** del archivo (efecto avalancha). Además, es computacionalmente inviable fabricar otro archivo distinto con el mismo hash (resistencia a colisiones y a segunda preimagen). En la práctica esto aporta tres garantías:

1. **Integridad.** El archivo no se corrompió al descargarlo ni al descomprimirlo, ni fue modificado por nadie en el camino.
2. **Comparabilidad entre equipos.** Si dos grupos reportan resultados distintos pero sus hashes coinciden, la diferencia está en el análisis, no en el material. Sin hash no se podría descartar que alguien trabajara sobre una versión alterada.
3. **Cadena de custodia.** Es la misma práctica que se usa en análisis forense y de malware: registrar el hash **antes** de tocar la muestra permite demostrar después que las conclusiones se refieren a ese artefacto concreto. Por eso este paso se hace primero, antes de ejecutar nada.

> Un hash demuestra *integridad*, no *autenticidad*: prueba que el archivo es igual al de referencia, pero no quién lo produjo. La confianza en el hash de referencia depende de que provenga de una fuente fiable (en este caso, la guía oficial del docente). Para autenticidad haría falta una firma digital.

### 1.3 Cabecera ELF con `readelf -h`

`readelf -h` muestra la cabecera ELF: los primeros 64 bytes del archivo, que le indican al sistema operativo cómo cargar y arrancar el programa.

**`crackme_level1`**

*Captura 1.5*

![1.5 — readelf -h crackme_level1](evidence/reverse/screenshots/1.5.jpeg)

**`crackme_level2`**

*Captura 1.6*

![1.6 — readelf -h crackme_level2](evidence/reverse/screenshots/1.6.jpeg)

**Comparación de ambas cabeceras:**

| Campo | `crackme_level1` | `crackme_level2` | Interpretación |
| :--- | :--- | :--- | :--- |
| Magic | `7f 45 4c 46 02 01 01 …` | igual | `7f 'E' 'L' 'F'` identifica el formato; `02` = 64 bits; `01` = little endian; `01` = versión ELF actual |
| Class | `ELF64` | `ELF64` | Confirma lo reportado por `file` |
| Data | `2's complement, little endian` | igual | Confirma el orden de bytes |
| OS/ABI | `UNIX - System V` | igual | ABI estándar de Linux |
| **Type** | **`EXEC (Executable file)`** | **`EXEC`** | **No es PIE.** Las direcciones son fijas y no cambian entre ejecuciones (ver abajo) |
| Machine | `Advanced Micro Devices X86-64` | igual | Arquitectura AMD64 |
| **Entry point** | **`0x401070`** | **`0x401070`** | Dirección de la primera instrucción ejecutada (`_start`, no `main`) |
| Start of section headers | `15456` bytes | `15896` bytes | `level2` es algo más grande: tiene más código/datos antes de la tabla de secciones |
| Number of program headers | `14` | `14` | Mismos segmentos de carga |
| Number of section headers | `36` | `36` | Mismo número de secciones |

**Observaciones relevantes para las siguientes fases:**

- **`Type: EXEC` (sin PIE).** Un ejecutable PIE (`DYN`) se carga en una dirección aleatoria en cada ejecución por ASLR. Aquí no ocurre: la dirección que se vea en Ghidra (`0x401…`) será **exactamente** la misma en GDB. Esto simplifica poner *breakpoints* y relacionar el análisis estático con el dinámico. Desde el punto de vista defensivo, es una protección de hardening **desactivada**, algo razonable en un crackme didáctico pero no deseable en software de producción.
- **El punto de entrada no es `main`.** `0x401070` corresponde a `_start`, el código de arranque que añade el compilador. Éste prepara el entorno y llama a `__libc_start_main`, que a su vez invoca `main`. En el binario stripped, donde `main` no tendrá nombre, este es precisamente el camino para encontrarlo: seguir desde el *entry point* el primer argumento que recibe `__libc_start_main`.
- **Mismo entry point en ambos.** Los dos binarios comparten el mismo esqueleto de compilación (mismo compilador y mismas opciones); la diferencia está en la lógica de `main` y de sus funciones auxiliares.

**Contraste con el binario stripped** (verificación complementaria, fuera de la lista mínima de la guía):

*Captura 1.7*

![1.7 — readelf -h crackme_level2_stripped](evidence/reverse/screenshots/1.7.jpeg)

```text
readelf -h crackme_level2_stripped
  Type:                       EXEC (Executable file)
  Entry point address:        0x401070
  Number of section headers:  28
```

Pasa de **36 a 28 secciones**: las 8 que desaparecen son las de depuración DWARF (`.debug_*`), la tabla de símbolos `.symtab` y su tabla de cadenas `.strtab`. El código ejecutable y el punto de entrada no cambian, por lo que **el programa se comporta igual; solo se pierde la información que ayuda a entenderlo.**

### 1.4 Resumen del baseline

| Criterio de la guía | `crackme_level1` | `crackme_level2` | `crackme_level2_stripped` |
| :--- | :--- | :--- | :--- |
| Formato | ELF64 | ELF64 | ELF64 |
| Arquitectura | x86-64 | x86-64 | x86-64 |
| Endianness | Little endian | Little endian | Little endian |
| Linking | Dinámico (`libc.so.6`) | Dinámico (`libc.so.6`) | Dinámico (`libc.so.6`) |
| PIE | No (`EXEC`) | No (`EXEC`) | No (`EXEC`) |
| Símbolos | ✅ Presentes | ✅ Presentes | ❌ Eliminados |
| Info. de depuración | ✅ DWARF | ✅ DWARF | ❌ No |
| Hash verificado | ✅ | ✅ | ✅ |

### 1.5 Hipótesis de trabajo tras el baseline

Sin ejecutar todavía ningún binario, el baseline ya permite plantear hipótesis que las siguientes fases deberán confirmar o descartar:

1. **H-R1.** Como `level1` y `level2` conservan símbolos y DWARF, las funciones deberían tener **nombres descriptivos**; es probable que la lógica de validación esté aislada en una función propia, fácil de localizar desde `main`.
2. **H-R2.** Al estar enlazados dinámicamente, las funciones de la libc que use la validación serán **visibles por nombre en los tres binarios**, incluido el stripped, porque viven en la tabla dinámica (`.dynsym`), que el strip no elimina. Verificación rápida: `nm -D crackme_level2_stripped` lista `__libc_start_main`, `strlen`, `printf`, `puts` y `putchar`. Esas importaciones servirán como punto de anclaje en el Boss Level.
3. **H-R3.** Al no ser PIE, las direcciones observadas en el análisis estático podrán usarse **directamente** como *breakpoints* en GDB.

### 1.6 Enseñanza de desarrollo seguro

Tres comandos que cualquiera puede ejecutar, sin privilegios y sin ejecutar el programa, ya revelan la plataforma, el compilador, si hay símbolos, si hay información de depuración y qué protecciones de hardening están activas. **Publicar un binario con `debug_info` y sin strip equivale a entregar un mapa de su código fuente.** En un proceso de release seguro, los símbolos de depuración se separan del ejecutable distribuido (y se guardan internamente para analizar fallos) y se activan protecciones como PIE, RELRO completo y *stack canaries*.

Aun así, el *strip* **no es un control de seguridad por sí mismo**: dificulta el análisis, pero no lo impide. Lo que protege un secreto no es esconderlo en el binario, sino no ponerlo ahí. Esto es lo que se pondrá a prueba en los niveles siguientes.

### 1.7 Evidencias del baseline

| Captura | Comando | Qué demuestra |
| :--- | :--- | :--- |
| [`1.1`](evidence/reverse/screenshots/1.1.jpeg) | `file crackme_level1` | ELF64 x86-64, dinámico, con `debug_info`, not stripped |
| [`1.2`](evidence/reverse/screenshots/1.2.jpeg) | `file crackme_level2` | Igual que level1, con otro BuildID |
| [`1.3`](evidence/reverse/screenshots/1.3.jpeg) | `file crackme_level2_stripped` | Mismo formato, pero **stripped** y sin `debug_info` |
| [`1.4`](evidence/reverse/screenshots/1.4.jpeg) | `sha256sum crackme_level1 crackme_level2 crackme_level2_stripped` | Los tres hashes coinciden con los de la guía |
| [`1.5`](evidence/reverse/screenshots/1.5.jpeg) | `readelf -h crackme_level1` | `Type: EXEC`, entry point `0x401070`, 36 secciones |
| [`1.6`](evidence/reverse/screenshots/1.6.jpeg) | `readelf -h crackme_level2` | Misma cabecera; tabla de secciones más adelante (binario más grande) |
| [`1.7`](evidence/reverse/screenshots/1.7.jpeg) | `readelf -h crackme_level2_stripped` | Mismo entry point; 28 secciones en vez de 36 |

Salida en texto de todos los comandos: [`evidence/reverse/baseline.txt`](evidence/reverse/baseline.txt).

---

## 2. Level 1 — Recon: "Strings are evidence"

> 📄 **Documento completo:** [`evidence/reverse/level1.md`](evidence/reverse/level1.md). Contiene las capturas `2.1` a `2.4`, el desensamblado comentado, el pseudocódigo reconstruido y la lección de desarrollo seguro.

**Resultado:** ✅ `FLAG{strings_are_evidence}`, obtenida sin código fuente y sin modificar el binario.

| Captura | Comando | Resultado |
| :--- | :--- | :--- |
| [`2.1`](evidence/reverse/screenshots/2.1.jpeg) | `chmod +x crackme_level1`, `./crackme_level1`, `./crackme_level1 prueba` | Mensaje de uso y `Access denied.` |
| [`2.2`](evidence/reverse/screenshots/2.2.jpeg) | `strings -n 5 crackme_level1 \| less` | `strcmp`, mensajes y `REDTEAM-101` |
| [`2.3`](evidence/reverse/screenshots/2.3.jpeg) | `objdump -d -M intel crackme_level1 \| less` | `strcmp(argv[1], password)` en `main` |
| [`2.4`](evidence/reverse/screenshots/2.4.jpeg) | `./crackme_level1 REDTEAM-101` | `Access granted.` + FLAG |

### Resumen para la sustentación

| Pregunta | Respuesta |
| :--- | :--- |
| **1. ¿Qué observamos?** | El programa recibe la clave por `argv[1]` y responde `Access denied.` sin más detalle. `strings -n 5` mostró la importación de `strcmp`, los mensajes `Access granted.` / `Access denied.` y una cadena aislada que nunca se imprime: **`REDTEAM-101`**. No había ninguna cadena `FLAG{…}`. |
| **2. ¿Qué hipótesis formulamos?** | **H-L1:** `main` compara `argv[1]` con `REDTEAM-101` mediante `strcmp` y, si coinciden, llama a `print_flag`, que construye la bandera en tiempo de ejecución (de ahí la importación de `putchar`). |
| **3. ¿Qué función o condición encontramos?** | Con `objdump`, en `main` (`0x4011d8`): `strcmp(argv[1], password)`, con `password` apuntando a `.rodata:0x402004` = `"REDTEAM-101"`. Un único `test eax,eax` / `jne` decide entre la denegación (`return 2`) y `print_flag()` (`return 0`). |
| **4. ¿Cómo lo confirmamos?** | `./crackme_level1 REDTEAM-101` → `Access granted.` + `FLAG{strings_are_evidence}`. El desensamblado de `print_flag` explica por qué la FLAG no aparecía en `strings`: está cifrada con **XOR `0x5a`** y guardada como valores inmediatos dentro de las instrucciones. |
| **5. ¿Qué enseñanza de desarrollo seguro obtuvimos?** | Todo lo que se compila dentro de un binario es público para quien lo tenga. Una contraseña literal se extrae con `strings`, y ofuscar con XOR no protege si la clave viaja en el mismo archivo. Los secretos no van en el cliente: se valida en el servidor o contra un hash con sal. |

---

## 3. Level 2 — Ghidra: reconstruir la validación

> 📄 **Documento completo:** [`evidence/reverse/level2.md`](evidence/reverse/level2.md). Contiene las capturas `3.1` a `3.9`, el análisis de `main` y `validate_key`, el pseudocódigo propio, la tabla de reconstrucción byte a byte y la lección de desarrollo seguro.

**Resultado:** ✅ clave `FDSI-REVERSE-2026` → `FLAG{ghidra_plus_gdb}`.

| Captura | Contenido | Resultado |
| :--- | :--- | :--- |
| [`3.1`](evidence/reverse/screenshots/3.1.jpeg) | `strings -n 5 crackme_level2` | Sin clave en claro; ya no se importa `strcmp`, sí `strlen` |
| [`3.2`](evidence/reverse/screenshots/3.2.jpeg) | `objdump -s -j .rodata crackme_level2` | 21 bytes no imprimibles tras los mensajes |
| [`3.3`](evidence/reverse/screenshots/3.3.jpeg) | Ghidra: resumen de importación | x86-64 LE, gcc, base `0x400000`, mismo SHA-256 |
| [`3.4`](evidence/reverse/screenshots/3.4.jpeg) | Ghidra: `main` | La decisión depende de `validate_key(argv[1])` |
| [`3.5`](evidence/reverse/screenshots/3.5.jpeg) | Ghidra: `validate_key` | Longitud exacta `0x11` = 17 |
| [`3.6`](evidence/reverse/screenshots/3.6.jpeg) | Ghidra: detalle del bucle | `candidate[i] ^ k[i & 3]` comparado con `expected[i]` |
| [`3.7`](evidence/reverse/screenshots/3.7.jpeg) | Ghidra: `.rodata` | `k` = `23 51 17 6a`, `expected` = 17 bytes |
| [`3.8`](evidence/reverse/screenshots/3.8.jpeg) | Script Python | `expected[i] ^ k[i % 4]` → `FDSI-REVERSE-2026` |
| [`3.9`](evidence/reverse/screenshots/3.9.jpeg) | `./crackme_level2 FDSI-REVERSE-2026` | `License accepted.` + FLAG |

### Resumen para la sustentación

| Pregunta | Respuesta |
| :--- | :--- |
| **1. ¿Qué observamos?** | `strings` ya no mostraba ninguna clave y el binario dejó de importar `strcmp`; en cambio importa `strlen`. En `.rodata`, después de los mensajes, aparecían 21 bytes no imprimibles. La pista del programa decía `static + dynamic analysis`. |
| **2. ¿Qué hipótesis formulamos?** | La clave no se guarda en claro: se compara contra datos **transformados** guardados en `.rodata`. Si la transformación es reversible, la clave se puede reconstruir a partir de esos datos sin fuerza bruta. |
| **3. ¿Qué función o condición encontramos?** | En Ghidra, `main` delega todo en `validate_key(argv[1])`. Esa función exige `strlen == 0x11` (17) y, para cada byte, comprueba `candidate[i] ^ k[i & 3] == expected[i]`, con `k` = 4 bytes reutilizados cíclicamente. Acumula las diferencias con `OR` y devuelve `score == 0`. |
| **4. ¿Cómo lo confirmamos?** | Como XOR es su propia inversa, `candidate[i] = expected[i] ^ k[i % 4]`. Un script de Python dio `FDSI-REVERSE-2026`, y el binario la aceptó: `License accepted.` + `FLAG{ghidra_plus_gdb}`. La confirmación paso a paso con GDB está en la sección 4 y en [`gdb.md`](evidence/reverse/gdb.md). |
| **5. ¿Qué enseñanza de desarrollo seguro obtuvimos?** | Ocultar la clave con XOR no la protege: si el binario puede validarla solo, contiene todo lo necesario para recuperarla. Lo correcto es validar en un servidor, comparar contra un hash de un solo sentido o verificar licencias firmadas con clave pública. |

---

## 4. Confirmación dinámica con GDB

> 📄 **Documento completo:** [`evidence/reverse/gdb.md`](evidence/reverse/gdb.md). Contiene las capturas `4.1` y `4.2`, la relación entre el ensamblador y el pseudocódigo de Ghidra, y la comparación entre una clave fallida y la válida.

**Resultado:** ✅ La hipótesis del Level 2 se confirma en ejecución: GDB se detiene en `validate_key` (`0x401162`), `AAAA` se rechaza con código de salida 3 y `FDSI-REVERSE-2026` se acepta e imprime la FLAG.

| Captura | Comando | Resultado |
| :--- | :--- | :--- |
| [`4.1`](evidence/reverse/screenshots/4.1.jpeg) | `break validate_key`, `run AAAA`, `disassemble validate_key` | Parada en `0x401162`; el prólogo coincide línea a línea con el decompilado de Ghidra |
| [`4.2`](evidence/reverse/screenshots/4.2.jpeg) | `info registers`, `continue`, `run FDSI-REVERSE-2026` | `rip = validate_key+12`, `rdi` → `candidate`; `AAAA` → `Invalid license.` y código 3; la clave válida llega a `validate_key` |
| [`3.9`](evidence/reverse/screenshots/3.9.jpeg) | `./crackme_level2 FDSI-REVERSE-2026` | `License accepted.` + `FLAG{ghidra_plus_gdb}` |

### Resumen para la sustentación

| Pregunta | Respuesta |
| :--- | :--- |
| **1. ¿Qué observamos?** | Como el binario conserva símbolos, GDB resuelve `break validate_key` por nombre en `0x401162`, la misma dirección que Ghidra (el binario es `EXEC`, sin ASLR en el código). Al detenerse muestra `validate_key (candidate=… "AAAA")`: el DWARF le da nombre y tipo al argumento. |
| **2. ¿Qué hipótesis formulamos?** | `validate_key` exige exactamente 17 caracteres (`strlen == 0x11`) y devuelve 0 o distinto de 0; `main` convierte ese retorno en código de salida 3 (rechazo) o 0 (éxito). |
| **3. ¿Qué función o condición encontramos?** | `mov [rbp-0x18],0x11` ↔ `n = 0x11`; `call strlen` + `cmp [rbp-0x18],rax` + `je` ↔ `if (strlen(candidate) == 0x11)`. En `info registers`, `rdi` apunta a la clave, como indica la convención System V. |
| **4. ¿Cómo lo confirmamos?** | `AAAA` → `Invalid license.` y `exited with code 03`, el valor que `main` asigna al rechazo. `FDSI-REVERSE-2026` → GDB se detiene con `candidate = "FDSI-REVERSE-2026"` y la ejecución directa imprime `License accepted.` y la FLAG. La prueba con una clave incorrecta de 17 caracteres, que ejercita el bucle XOR, está en el Boss Level ([`boss.md`](evidence/reverse/boss.md) §3.1). |
| **5. ¿Qué enseñanza de desarrollo seguro obtuvimos?** | El análisis dinámico confirma al estático, no lo reemplaza. Una sola condición (`je` tras `cmp`/`test`) decide el acceso: quien tiene el binario puede parchearla, por eso la validación de secretos no debe vivir en el cliente. La falta de PIE y la presencia de símbolos hicieron trivial la correspondencia entre Ghidra y GDB. |

---

## 5. Boss Level — binario sin símbolos

> 📄 **Documento completo:** [`evidence/reverse/boss.md`](evidence/reverse/boss.md). Contiene la captura `5.1`, la comparación de secciones, las tres rutas para encontrar la validación sin nombres, el renombrado manual, la comparación de tres claves bajo GDB y la lección de desarrollo seguro. La salida cruda está en [`boss-output.txt`](evidence/reverse/boss-output.txt).

**Resultado:** ✅ La función de validación se recuperó sin símbolos: está en `0x401156` y es **idéntica** a `validate_key` de `crackme_level2`. Misma clave (`FDSI-REVERSE-2026`), misma FLAG (`FLAG{ghidra_plus_gdb}`).

| Evidencia | Contenido | Resultado |
| :--- | :--- | :--- |
| [captura `5.1`](evidence/reverse/screenshots/5.1.jpeg) | `file`, `nm`, `strings -n 5` | `stripped`, `no symbols`; los mensajes siguen, los nombres no |
| `boss-output.txt` §2 | `readelf -S` (36 vs 28), `diff` de secciones, `cmp` de `.text`/`.rodata`, `nm -D` | Desaparecen `.symtab`, `.strtab` y seis `.debug_*`; código y datos idénticos; sobreviven las importaciones |
| `boss-output.txt` §3 | `objdump -d` desde `0x401070` | `mov rdi,0x401267` + `call __libc_start_main` → `main` = `0x401267` |
| `boss-output.txt` §4–5 | `strings -t x`, referencias a `0x40207a`/`0x402068`, stubs de la PLT | `Invalid license.` se usa en `0x4012f1`; `strlen` sólo se llama en `0x401171` |
| `boss-output.txt` §6 | `objdump -d` de `0x401156`–`0x4011f3` | Longitud 17, XOR con `k[i & 3]`, `score \|= …` |
| `boss-output.txt` §7 | GDB: `break *0x401162`, `x/6i $pc`, `x/s $rdi`, tres claves | `0x401162 in ?? ()`; misma instrucción que en la captura 4.1; `score` = `0x3` / `0x0` |

### Resumen para la sustentación

| Pregunta | Respuesta |
| :--- | :--- |
| **1. ¿Qué observamos?** | `file` dice `stripped`, `nm` dice `no symbols` y `strings` ya no muestra `validate_key`, `candidate` ni el nombre del `.c`. Pasa de 36 a 28 secciones: se pierden `.symtab`, `.strtab` y seis `.debug_*`. Los mensajes, las importaciones de la libc y la versión del compilador (`.comment`) siguen visibles. |
| **2. ¿Qué hipótesis formulamos?** | `strip` sólo quita metadata, así que el código y los datos deben ser idénticos a los de `crackme_level2`. La lógica se recupera con anclas que `strip` no puede borrar: el punto de entrada, las cadenas y las importaciones. |
| **3. ¿Qué función o condición encontramos?** | `main` en `0x401267` (argumento de `__libc_start_main` en `_start`); dentro, `call 0x401156` seguido de `test eax,eax` / `je 0x4012f1`. La función `0x401156` llama a `strlen`, exige 17 caracteres y compara `candidate[i] ^ k[i & 3]` con `expected[i]`. Tres rutas independientes coinciden: entrada → `main`, cadena `Invalid license.` → referencia, y `strlen` → único llamador. |
| **4. ¿Cómo lo confirmamos?** | `.text` (663 B) y `.rodata` (161 B) son idénticos byte a byte a los de `crackme_level2` (`cmp`). En GDB, con `break *0x401162` y sin nombres: `AAAA` sale por la compuerta de longitud; `FDSI-REVERSE-2025` (17 caracteres, incorrecta) entra al bucle y termina con `score = 0x3`; `FDSI-REVERSE-2026` termina con `score = 0x0`, retorno 1 y la FLAG. |
| **5. ¿Qué enseñanza de desarrollo seguro obtuvimos?** | Quitar símbolos es higiene de release, no un control de seguridad: la validación se recuperó en minutos con `objdump` y GDB porque la lógica sigue intacta en las instrucciones. Lo que protege un secreto es no embeberlo: validar en servidor, comparar contra un hash lento con sal o verificar licencias firmadas. |

---

## 6. Preguntas de análisis

Las siete preguntas de la guía, respondidas con la evidencia del laboratorio.

### 6.1 ¿Qué información pudiste obtener sin ejecutar el binario?

Bastante más de lo que sugiere un programa que sólo dice `Access denied.`:

- **Del formato** (`file`, `readelf -h`, §1): ELF de 64 bits, x86-64, *little endian*, enlazado dinámicamente contra `libc.so.6`, sin PIE (`EXEC`, direcciones fijas), con información de depuración y sin strip (excepto el tercer binario).
- **Del Level 1** (`strings`, `objdump`): los mensajes de éxito y fallo, la importación de `strcmp`, la contraseña `REDTEAM-101` y su dirección en `.rodata` (`0x402004`). La FLAG no aparecía, pero el desensamblado de `print_flag` permitía recuperarla igualmente: son 26 bytes cifrados con XOR de un solo byte (`0x5a`), y la clave viaja con los datos.
- **Del Level 2** (Ghidra, `objdump -s`): la longitud exacta de la clave (17), el algoritmo (`candidate[i] ^ k[i & 3] == expected[i]`) y los 21 bytes de datos. Con eso se **reconstruyó la clave `FDSI-REVERSE-2026` sin ejecutar nada**; la ejecución sólo la confirmó.
- **Del entorno de compilación:** versión de GCC (`GCC: (Debian 14.2.0-19) 14.2.0`), opciones (`-g -O0 -fno-inline`), nombre del fuente y directorio donde se compiló.

### 6.2 ¿Por qué una contraseña compilada como string es un diseño inseguro?

Porque **compilar no oculta nada**: un literal de C se copia tal cual a `.rodata`, y `strings` lo extrae en segundos sin entender el programa ni necesitar símbolos (en el Level 1 apareció `REDTEAM-101` aislado entre los mensajes). Además, la contraseña es **la misma para todos los usuarios**, no se puede cambiar sin recompilar y redistribuir, y quien tenga el binario tiene todo lo necesario para validar y, por tanto, para saltarse la validación. El Level 2 muestra que cambiar el formato (texto → XOR con una clave de 4 bytes) sólo aumenta el tiempo de análisis: de segundos con `strings` a minutos con Ghidra. Ver [`level1.md`](evidence/reverse/level1.md) §6–7 y [`level2.md`](evidence/reverse/level2.md) §8.

### 6.3 ¿Qué cambió entre `crackme_level2` y `crackme_level2_stripped`?

| | `crackme_level2` | `crackme_level2_stripped` |
| :--- | :--- | :--- |
| `file` | `with debug_info, not stripped` | `stripped` |
| Secciones | 36 | 28 (sin `.symtab`, `.strtab` ni `.debug_*`) |
| `nm` | Lista `validate_key`, `reveal_flag`, `main`, `k.1`, `expected.0`… | `no symbols` |
| GDB | `break validate_key`; muestra `candidate=…` y la línea del fuente | `break *0x401162`; muestra `?? ()` |
| Ghidra | Nombres y tipos tomados del DWARF | `FUN_<dirección>`, `param_1` |
| **Código** (`.text`) y **datos** (`.rodata`) | — | **Idénticos byte a byte** |
| Direcciones y *entry point* | `0x401070`; `validate_key` = `0x401156` | `0x401070`; función sin nombre = `0x401156` |

Cambió la **metadata**, no la **lógica**. Detalle en [`boss.md`](evidence/reverse/boss.md) §1.

### 6.4 ¿Qué ventaja tuvo Ghidra sobre `objdump`?

- **Estructura en vez de instrucciones.** El decompilador devolvió `if (sVar2 == 0x11)`, un `for` y `score = score | …`. Con `objdump` hay que reconstruir a mano el significado de cada posición de la pila (`[rbp-0x4]` es `score`, `[rbp-0x10]` es `i`…), como se hizo en [`level2.md`](evidence/reverse/level2.md) §4.2.
- **Datos con tipo y referencias cruzadas.** Ghidra mostró `k` como `uchar[4]` en `0x40208b` y `expected` como `uchar[17]` en `0x402090`, con los `XREF` que apuntan a `validate_key` (captura 3.7).
- **Navegación y anotación.** Doble clic de `main` a `validate_key`; el renombrado de una variable se propaga a todos sus usos y se pueden dejar comentarios.

Una salvedad honesta: **Ghidra no aportó información que `objdump` no tuviera.** El Boss Level se resolvió con `objdump`, `strings` y GDB. La ventaja es velocidad y menor riesgo de leer mal un desplazamiento, no acceso a algo oculto.

### 6.5 ¿Qué confirmó GDB que el análisis estático por sí solo no demostraba?

El análisis estático dice qué **puede** pasar; GDB muestra qué **pasa**:

- Que el valor real de `rdi` al entrar a la función es el puntero a la clave del usuario (`info registers`, captura 4.2).
- **Qué camino toma realmente el programa:** con `AAAA` se alcanza la rama de longitud (`0x401181`); con `FDSI-REVERSE-2025` no, y se entra al bucle.
- **El valor de `score` y del retorno** en cada caso: `0x3` y 0 con la clave incorrecta de 17 caracteres, `0x0` y 1 con la válida (Boss, §3.1).
- Que el código de salida 3 de `main` corresponde, efectivamente, al retorno 0 de `validate_key`.
- Que **las direcciones del análisis estático son las del proceso en ejecución**, lo que valida usar `break *0x401162` sin símbolos.

### 6.6 ¿Por qué Burp Suite no es una herramienta de ingeniería inversa de binarios?

Burp Suite es un **proxy de interceptación HTTP/HTTPS**: se coloca entre un cliente y un servidor para observar y modificar peticiones y respuestas de la capa de aplicación (Proxy → Intercept → Repeater). Analiza **lo que viaja por la red**, no **lo que hace un programa por dentro**. El crackme ni siquiera usa la red: sus importaciones son `strlen`, `printf`, `puts`, `putchar` y `__libc_start_main` (sin ninguna función de *sockets*), y toda la validación ocurre en la CPU y la memoria del propio proceso, así que no habría tráfico que interceptar. Ghidra y GDB trabajan sobre el **código y el estado del proceso**: desensamblan, decompilan, detienen la ejecución y leen registros y memoria. Son complementarias: si un binario fuera cliente de un servicio web, Burp mostraría sus peticiones, pero no su lógica interna; y Ghidra mostraría su lógica, pero no el contenido de una sesión real. Esta misma separación entre capas se vio en el Laboratorio 3: `access.log` (capa de aplicación) no veía el escaneo de puertos (capa de red); cada capa necesita su propia herramienta.

> El módulo con Burp y PortSwigger Academy es una actividad complementaria; esta respuesta es conceptual y no incluye evidencia de esa práctica.

### 6.7 ¿Qué controles de desarrollo evitarían secretos embebidos de forma insegura en software real?

| Control | Qué previene | Dónde se vio |
| :--- | :--- | :--- |
| **Validar en el servidor** | El binario nunca conoce el valor correcto; no hay nada que extraer | `level2.md` §8 |
| **Comparar contra un hash lento con sal** (Argon2, bcrypt, PBKDF2) | Conocer el hash no permite reconstruir la clave, a diferencia de un XOR | `level1.md` §7 |
| **Licencias firmadas** (Ed25519, RSA) | El binario sólo contiene la **clave pública**: sirve para verificar, no para generar licencias | `level2.md` §8 |
| **Gestor de secretos y variables de entorno** | Que el secreto viva en el código fuente y, por tanto, en el binario | `level1.md` §7 |
| **Escáneres de secretos en el pipeline** (gitleaks, trufflehog) | Que un literal sensible llegue al repositorio | `level1.md` §7 (conecta con el Laboratorio 5) |
| **Comparaciones en tiempo constante** | Fugas por *timing* (el Level 2 ya lo hacía con `score \|= …`) | `level2.md` §4.2 |
| **Hardening de release**: strip, `-ffile-prefix-map`, PIE, RELRO, *stack canaries* | Fuga de nombres, rutas y versiones; facilidad de parcheo. **Es defensa en profundidad, no sustituye a no embeber el secreto** | `boss.md` §5 |

---

## 7. Guion de sustentación de 3 minutos

| Tiempo | Punto de la guía | Qué decir |
| :--- | :--- | :--- |
| 0:00–0:30 | **1. Qué observamos** | Tres binarios ELF x86-64 verificados por SHA-256. El programa sólo responde `Access denied.` / `Invalid license.`. Con `strings` en el Level 1 apareció `REDTEAM-101` y `strcmp`; en el Level 2 ya no había clave en claro, ni `strcmp`, pero sí `strlen`. En el stripped desaparecieron los nombres, no el código. |
| 0:30–1:00 | **2. Qué hipótesis formulamos** | Level 1: se compara `argv[1]` con la cadena embebida. Level 2: se compara contra datos *transformados* en `.rodata`; si la transformación es reversible, la clave se calcula sin fuerza bruta. Boss: `strip` sólo quita metadata, la lógica debe ser idéntica. |
| 1:00–1:50 | **3. Qué función o condición encontramos** | Level 1: `strcmp(argv[1], "REDTEAM-101")` y un `test eax,eax / jne`. Level 2: `validate_key` exige 17 caracteres y comprueba `candidate[i] ^ k[i & 3] == expected[i]` acumulando con `OR`. Boss: la misma función, sin nombre, en `0x401156`, hallada desde `_start` → `main` (`0x401267`), desde la cadena `Invalid license.` y desde el único llamador de `strlen`. |
| 1:50–2:30 | **4. Cómo lo confirmamos** | Level 1 y 2: ejecutar con la clave y ver la FLAG. Invertimos el XOR con Python: `expected[i] ^ k[i % 4]` = `FDSI-REVERSE-2026`. En GDB: `AAAA` sale con código 3 por la compuerta de longitud; `FDSI-REVERSE-2025` entra al bucle con `score = 0x3`; la válida da `score = 0x0` y retorno 1. En el stripped, el mismo `break *0x401162` y `cmp` byte a byte del `.text`. |
| 2:30–3:00 | **5. Qué enseñanza de desarrollo seguro** | Todo lo que se compila dentro de un binario es público para quien lo tenga. XOR y *strip* son ofuscación, no protección. Si el programa puede validar la clave solo, contiene la respuesta: hay que validar en un servidor, con hash lento y sal, o con licencias firmadas. |

---

## 8. Cierre de la entrega

Checklist de la guía (sección 6):

- [x] [`baseline.txt`](evidence/reverse/baseline.txt) contiene hashes, `file` y `readelf`.
- [x] [`level1.md`](evidence/reverse/level1.md) explica hipótesis → evidencia → resultado.
- [x] [`level2.md`](evidence/reverse/level2.md) contiene pseudocódigo propio, no código decompilado copiado sin explicación.
- [x] [`gdb.md`](evidence/reverse/gdb.md) demuestra la validación dinámica (y [`boss.md`](evidence/reverse/boss.md) §3 la repite sin símbolos).
- [x] [`boss.md`](evidence/reverse/boss.md) y [`boss-output.txt`](evidence/reverse/boss-output.txt) documentan el Boss Level.
- [x] Tag `lab-reverse-v1` sobre el commit de la entrega:

```bash
git add .
git commit -m "lab4-parte2: reverse engineering CTF (level1, level2, gdb, boss)"
git tag lab-reverse-v1
git push && git push origin lab-reverse-v1
```
