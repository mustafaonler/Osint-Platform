# subfinder — pasif subdomain kesfi (P0)
# Runner bu imaji `osint-tools` agina bagli, read_only, cap_drop=ALL ve
# user=1000:1000 ile calistirir. Buradaki ayarlar o kisitlarla UYUMLU olmak
# zorundadir; imaj tek basina "calisiyor" olmasi yetmez.

FROM projectdiscovery/subfinder:latest

# ROOT DEGIL. Runner zaten user="1000:1000" veriyor; imajda da sabitlemek,
# runner bayragi bir gun unutulsa bile kok ayricaligini engeller (savunma
# derinligi).
USER 1000:1000

# read_only=True altinda yazilabilir TEK yer tmpfs /tmp'tir. subfinder
# yapilandirmasini ve provider anahtarlarini XDG dizinlerine yazmaya calisir;
# bunlar /tmp'e yonlendirilmezse acilista "read-only file system" ile duser.
ENV HOME=/tmp \
    XDG_CONFIG_HOME=/tmp \
    XDG_CACHE_HOME=/tmp

# Runner komutu `[hedef]` olarak gecirir; adapter kendi bayraklarini ekler.
ENTRYPOINT ["subfinder"]
