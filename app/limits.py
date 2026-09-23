"""Redis üzerinde atomik tool hızı ve UTC takvim ayı kotası."""
import hashlib
import time
from datetime import datetime, timezone

from redis import Redis
from redis.exceptions import RedisError


class LimitEngeli(Exception):
    def __init__(self, mesaj: str, durum: str):
        super().__init__(mesaj)
        self.durum = durum


# İzin verilmeden ne hız slotu ne kota tüketilir. Saat bütün süreçler için
# Redis TIME'dır. Ay sınırındaki iki TIME çağrısı arasında yarış yeniden denenir.
_IZIN = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local start = tonumber(ARGV[1])
local finish = tonumber(ARGV[2])
local interval = tonumber(ARGV[3])
local quota = tonumber(ARGV[4])
if now < start or now >= finish then return {4, 0} end
local count = 0
if redis.call('HGET', KEYS[2], 'month') == ARGV[1] then
  count = tonumber(redis.call('HGET', KEYS[2], 'count') or '0')
end
if quota >= 0 and count >= quota then return {2, 0} end
local last = tonumber(redis.call('GET', KEYS[1]) or '0')
local wait = math.max(0, last + interval - now)
if interval > 0 and wait > 0 then return {1, math.ceil(wait * 1000)} end
if interval > 0 then
  redis.call('SET', KEYS[1], string.format('%.6f', now), 'PX', math.ceil(interval * 1000) + 1000)
end
if quota >= 0 then
  redis.call('HSET', KEYS[2], 'month', ARGV[1], 'count', count + 1)
  redis.call('EXPIREAT', KEYS[2], finish + 60)
end
return {0, 0}
"""


def ay_araligi(saniye: float) -> tuple[int, int]:
    now = datetime.fromtimestamp(saniye, timezone.utc)
    start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    end = datetime(now.year + (now.month == 12), 1 if now.month == 12 else now.month + 1,
                   1, tzinfo=timezone.utc)
    return int(start.timestamp()), int(end.timestamp())


class RedisLimitleri:
    def __init__(self, client: Redis, prefix: str = "osint:limits:v1"):
        self.client = client
        self.prefix = prefix
        self.script = client.register_script(_IZIN)

    @classmethod
    def from_url(cls, url: str):
        return cls(Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2))

    def anahtarlar(self, tool: str):
        digest = hashlib.sha256(tool.encode()).hexdigest()
        # Aynı tool iki anahtarı Redis Cluster'da da aynı slotta tutar.
        base = f"{self.prefix}:{{{digest}}}"
        return [base + ":rate", base + ":month"]

    def izin_al(self, spec, son_tarih: float):
        interval = 60.0 / spec.dakikalik_istek if spec.dakikalik_istek and spec.dakikalik_istek > 0 else 0
        quota = spec.aylik_kota if spec.aylik_kota is not None else -1
        if quota < -1:
            raise LimitEngeli("Geçersiz aylık kota", "failed")
        if not interval and quota == -1:
            return
        try:
            while True:
                if time.monotonic() >= son_tarih:
                    raise LimitEngeli("Hız sınırı beklenirken çalışma bütçesi doldu", "timeout")
                seconds, _ = self.client.time()
                start, end = ay_araligi(seconds)
                code, wait_ms = self.script(keys=self.anahtarlar(spec.name), args=[start, end, interval, quota])
                if code == 0:
                    return
                if code == 2:
                    raise LimitEngeli(f"{spec.name}: aylık kota doldu ({quota}); UTC takvim ayı", "skipped")
                if code == 4:
                    continue
                wait = wait_ms / 1000
                if time.monotonic() + wait >= son_tarih:
                    raise LimitEngeli("Hız sınırı beklemesi çalışma bütçesini aşıyor", "timeout")
                time.sleep(wait)
        except RedisError:
            # Bağlantı URL'si/şifresi hata metnine taşınmaz. Yerel sayaca
            # düşmek limitleri sessizce çoğaltacağından izin verilmez.
            raise LimitEngeli("Redis limit servisine erişilemiyor; tool başlatılmadı", "failed") from None
