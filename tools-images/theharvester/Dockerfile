# theHarvester - pasif e-posta ve subdomain kesfi (P0)
#
# Runner bu imaji read_only, cap_drop=ALL, user=1000:1000 ve tmpfs /tmp ile
# calistirir. Buradaki her ayar o kisitlarla UYUMLU olmak zorundadir.

FROM python:3.12-slim

# PYPI'DAN KURULMAZ. Olctuk: PyPI'daki `theHarvester` paketi surum 0.0.1'de
# BOS BIR TASLAK - hicbir calistirilabilir dosya icermiyor. Gercek proje
# yalnizca kendi deposunda yayinlaniyor. Bagimlilik adina guvenip
# dogrulamamak, calismayan bir tool'u calisiyor sanmakla sonuclanirdi.
#
# Surum SABITLENIR: bir tool'un ciktisi sessizce degisirse fixture testi
# kirilmali; hareketli hedefe (main dali) baglanmak o guvenceyi bozar.
ARG THEHARVESTER_SURUM=4.6.0
RUN apt-get update  && apt-get install -y --no-install-recommends git  && pip install --no-cache-dir       "git+https://github.com/laramies/theHarvester.git@${THEHARVESTER_SURUM}"  && apt-get purge -y git && apt-get autoremove -y  && rm -rf /var/lib/apt/lists/*

# ROOT DEGIL. Runner zaten user=1000:1000 veriyor; imajda da sabitlemek
# runner bayragi unutulsa bile kok ayricaligini engeller (savunma derinligi).
RUN useradd -u 1000 -m hasat

# read_only=True altinda yazilabilir TEK yer tmpfs /tmp'tir.
# theHarvester HOME'a yapilandirma ve onbellek yazar; yonlendirilmezse
# acilista "read-only file system" ile duser (subfinder'da XDG_* ile ayni desen).
ENV HOME=/tmp \
    XDG_CONFIG_HOME=/tmp \
    XDG_CACHE_HOME=/tmp \
    XDG_DATA_HOME=/tmp \
    TMPDIR=/tmp \
    PYTHONDONTWRITEBYTECODE=1

# ------------------------------------------------------------------------- #
# CIKTI KARARI: -f ile JSON dosyaya yazdirilip stdout'a basilir.
#
# theHarvester sonuclari stdout'a INSAN ICIN bicimlendirilmis olarak yazar
# (banner, renk kodlari, hizalama). Onu ayristirmak, tam da whois-rdap'ta
# WHOIS'ten kacinma gerekcesiyle ayni sorunu yaratirdi: bicim degisince
# parse() sessizce bozulur.
#
# -f JSON dosyasi deterministiktir. Dosya tmpfs /tmp'e yazilir (read_only
# altinda yazilabilen tek yer), sonra cat ile stdout'a verilir; runner
# stdout'u zaten arsivliyor, ek mount gerekmez.
# ------------------------------------------------------------------------- #
COPY calistir.sh /usr/local/bin/calistir.sh
RUN chmod +x /usr/local/bin/calistir.sh

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/calistir.sh"]
