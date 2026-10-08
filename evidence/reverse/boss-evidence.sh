#!/usr/bin/env bash
# =============================================================================
# FDSI — Laboratorio 4 Parte 2 — Boss Level (binario stripped)
# Genera la salida CRUDA de todos los comandos citados en boss.md.
#
# Uso (desde la carpeta que contiene los binarios originales):
#     bash <ruta>/boss-evidence.sh                      # usa crackme_level2 y crackme_level2_stripped
#     bash <ruta>/boss-evidence.sh <level2> <stripped>  # rutas explícitas a los binarios
#
# Resultado: boss-output.txt, escrito junto al script (evidence/reverse/).
# Requiere: file, nm, readelf, objdump, objcopy, strings, sha256sum, gdb, cmp, diff.
# No modifica los binarios: sólo los lee (y los ejecuta bajo GDB).
# =============================================================================
set -u
L2="${1:-crackme_level2}"
ST="${2:-crackme_level2_stripped}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${3:-$HERE/boss-output.txt}"     # por defecto, junto al script (evidence/reverse/)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

EXPECTED_ST="c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3"
GOT_ST="$(sha256sum "$ST" | awk '{print $1}')"
if [ "$GOT_ST" != "$EXPECTED_ST" ]; then
  echo "ADVERTENCIA: el SHA-256 de $ST no coincide con el de la guía." >&2
  echo "  esperado: $EXPECTED_ST" >&2
  echo "  obtenido: $GOT_ST" >&2
  echo "Las direcciones citadas en boss.md (0x401156, 0x401267...) sólo valen para el binario original." >&2
fi

sec()  { printf '\n==============================================================\n## %s\n==============================================================\n' "$1"; }
run()  { printf '\n$ %s\n' "$*"; "$@" 2>&1; }
runsh(){ printf '\n$ %s\n' "$1"; bash -c "$1" 2>&1; }

# Script de GDB: breakpoints POR DIRECCIÓN (no existen nombres en el stripped).
cat > "$TMP/boss.gdb" <<'EOF'
set pagination off
set confirm off
break *0x401162
break *0x401181
break *0x4011e7
break *0x4011f1
break *0x4012d2
commands 1
  silent
  printf "[bp 0x401162] entrada a la validacion   rdi -> \"%s\"\n", (char*)$rdi
  continue
end
commands 2
  silent
  printf "[bp 0x401181] puerta de longitud FALLA (strlen != 17)\n"
  continue
end
commands 3
  silent
  printf "[bp 0x4011e7] fin del bucle             score = 0x%x\n", *(unsigned int*)($rbp-4)
  continue
end
commands 4
  silent
  printf "[bp 0x4011f1] retorno de la funcion     eax = %d\n", (int)$eax
  continue
end
commands 5
  silent
  printf "[bp 0x4012d2] main: test eax,eax        eax = %d\n", (int)$eax
  continue
end
run
EOF

{
echo "================================================================"
echo " FDSI — Laboratorio 4 Parte 2 — Boss Level (binario stripped)"
echo " Salida cruda de los comandos de boss.md"
echo " Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)   Equipo: $(uname -srm)"
echo "================================================================"

sec "1. Identidad del binario"
run sha256sum "$ST"
run file "$ST"

sec "2. Qué desapareció al hacer strip"
run nm "$ST"
echo; echo "# Secciones: level2 (con símbolos) vs stripped"
runsh "readelf -S -W '$L2'  | grep -c -E '^ +\[ *[0-9]+\]'"
runsh "readelf -S -W '$ST'  | grep -c -E '^ +\[ *[0-9]+\]'"
runsh "diff <(readelf -S -W '$L2' | sed -n 's/^ *\[ *[0-9]*\] \(\.[^ ]*\).*/\1/p') <(readelf -S -W '$ST' | sed -n 's/^ *\[ *[0-9]*\] \(\.[^ ]*\).*/\1/p')"
echo; echo "# strings que existían con símbolos y ya no están (marcadas con <)"
runsh "diff <(strings -n 5 '$L2' | sort -u) <(strings -n 5 '$ST' | sort -u) | grep -E '^<' | grep -E 'validate_key|reveal_flag|expected|transformed|score|candidate|crackme_level2\.c|reverse_fsi_lab|GNU C17|frame_dummy|deregister_tm_clones'"
echo; echo "# strings que SIGUEN en el stripped (mensajes y compilador)"
runsh "strings -n 5 '$ST' | grep -E 'FDSI|Hint|Uso|License|Invalid|GCC:'"
echo; echo "# Lo que NO cambia: .text y .rodata byte a byte"
for s in .text .rodata; do
  objcopy -O binary --only-section=$s "$L2" "$TMP/l2$s.bin"
  objcopy -O binary --only-section=$s "$ST" "$TMP/st$s.bin"
  if cmp -s "$TMP/l2$s.bin" "$TMP/st$s.bin"; then
    echo "$s: IDENTICO ($(wc -c < "$TMP/st$s.bin") bytes)"
  else
    echo "$s: DIFERENTE"
  fi
done
echo; echo "# Lo que SOBREVIVE: importaciones dinámicas (.dynsym)"
run nm -D "$ST"

sec "3. Del punto de entrada a main (flujo de control)"
runsh "readelf -h '$ST' | grep -E 'Type|Entry'"
run objdump -d -M intel --start-address=0x401070 --stop-address=0x401092 "$ST"

sec "4. Referencias desde las cadenas hacia el código (datos -> código)"
runsh "strings -t x -n 5 '$ST' | grep -E 'FDSI|Hint|Uso|License|Invalid'"
runsh "readelf -S -W '$ST' | grep -E '\.rodata'"
echo; echo "# .rodata: offset 0x2000 <-> dirección 0x402000 (no PIE) => 0x207a -> 0x40207a"
runsh "objdump -d -M intel '$ST' | grep -nE '# (402068|40207a)'"
run objdump -d -M intel --start-address=0x4012bf --stop-address=0x401307 "$ST"

sec "5. Referencias por comportamiento: quién llama a cada función de libc"
runsh "objdump -d -M intel -j .plt '$ST' | grep -E '^[0-9a-f]+ <'"
runsh "objdump -d -M intel '$ST' | grep -E 'call +(401030|401040|401050|401060)'"

sec "6. La función de validación sin nombre (0x401156 - 0x4011f2)"
run objdump -d -M intel --start-address=0x401156 --stop-address=0x4011f3 "$ST"
echo; echo "# Datos que usa (k en 0x40208b, expected en 0x402090)"
run objdump -s -j .rodata --start-address=0x40208b --stop-address=0x4020a1 "$ST"

sec "7. GDB sobre el stripped"
echo; echo "# Sin símbolos no se puede poner un breakpoint por nombre:"
run gdb -nx -batch -ex 'break validate_key' "$ST"
echo; echo "# GDB sólo conoce los stubs PLT (info functions):"
run gdb -nx -batch -ex 'info functions' "$ST"
echo; echo "# Breakpoint por dirección, instrucciones en rip y clave en rdi (sesión de boss.md §3):"
run gdb -nx -batch -ex 'set disassembly-flavor intel' -ex 'break *0x401162' -ex 'run FDSI-REVERSE-2025' -ex 'x/6i $pc' -ex 'x/s $rdi' "$ST"
for key in AAAA FDSI-REVERSE-2025 FDSI-REVERSE-2026; do
  echo; echo "---------------- clave: $key ----------------"
  gdb -nx -batch -x "$TMP/boss.gdb" --args "$ST" "$key" 2>&1 \
    | grep -vE 'libthread_db|Thread debugging|^Breakpoint [0-9]+ at|^$'
done
} > "$OUT" 2>&1

echo "Listo: $OUT ($(wc -l < "$OUT") líneas)"
