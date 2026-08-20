# Uygulama imaji: api, worker ve host'tan calistirilamayan her sey
# (alembic migration'lari, veritabanina dokunan testler).
#
# NEDEN GEREKLI: db ve redis `osint-data` internal agindadir; internal agda
# yayinlanan portlar CALISMAZ (olculdu). Dolayisiyla veritabanina erisen her
# komut bu imajdan, o aga bagli bir container icinde kosar.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ROOT DEGIL. Tool container'larindaki kural burada da gecerli.
RUN useradd -u 1000 -m osint && chown -R osint:osint /app
USER 1000:1000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
