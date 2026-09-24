#!/usr/bin/env bash
# Detección M6: 3+ respuestas 404 por IP y minuto
sudo awk '{
  if ($4 ~ /^\[[0-9]{4}-[0-9]{2}-[0-9]{2}T/) {
    status = $8; ts = $4
    gsub(/^\[|\]$/, "", ts); split(ts, a, "T"); split(a[2], h, ":")
    clave = $1 " " a[1] " " h[1] ":" h[2]
  } else {
    status = $9; ts = $4
    gsub(/^\[/, "", ts); split(ts, a, ":")
    clave = $1 " " a[1] " " a[2] ":" a[3]
  }
  if (status == 404) { conteo[clave]++; if (conteo[clave] >= 3) alerta[clave] = conteo[clave] }
}
END {
  if (length(alerta) == 0) print "Sin señales en la ventana analizada."
  else { print "SEÑAL - 3+ respuestas 404 por minuto:"; for (k in alerta) printf "  %s -> %d eventos\n", k, alerta[k] }
}' /var/log/nginx/access.log
