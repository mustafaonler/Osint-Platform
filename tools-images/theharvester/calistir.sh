#!/bin/sh
# theHarvester'i kosturur ve JSON ciktiyi stdout'a verir.
# Argumanlar adapter'in komut() metodundan gelir.
set -u

CIKTI="/tmp/hasat_$$"

# stderr'i bastirmiyoruz: runner onu hata_mesaji'na aliyor. stdout'u ise
# KIRLETMIYORUZ - theHarvester'in insan icin bastigi metin /dev/null'a gider,
# stdout'ta yalnizca JSON kalir.
theHarvester "$@" -f "$CIKTI" >/dev/null 2>&1
KOD=$?

if [ -f "${CIKTI}.json" ]; then
  cat "${CIKTI}.json"
  exit 0
fi

# Dosya yoksa: sonuc bulunamamis ya da tool dusmus olabilir. Bos JSON nesnesi
# basilir ki parse() ayni sozlesmeyi gorsun; cikis kodu gercegi soyler.
echo '{}'
exit $KOD
