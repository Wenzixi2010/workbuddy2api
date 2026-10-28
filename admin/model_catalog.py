"""Short-lived catalog cache for discovery and automatic model selection."""
from collections import OrderedDict
import hashlib
import json
import threading
import time

_cache = OrderedDict()
_lock = threading.Lock()
TTL_SECONDS = 300


def account_region(auth_json: str) -> str:
    """账号属于哪个上游版本：`cn`（国内版）或 `intl`（国际版）。

    国内版与国际版是**两套并存的站点**，各自的模型目录不同：同一份代码、
    不同的主机名，token 只在签发它的域有效（见 `converter.INTL_DOMAINS`）。

    上游基址由 `CredentialManager.api_base()` 按 `auth.domain` 决定，所以这里
    读同一个字段做分区键 —— 判定口径必须与真正发请求的地方一致，否则会出现
    「按国际版缓存、按国内版请求」的错配。

    读不出 domain 时按国内版处理：老数据与 CN 账号都没有 intl 域，
    与 `api_base()` 的兜底（返回 BACKEND）保持同一语义。
    """
    try:
        data = json.loads(auth_json) if isinstance(auth_json, str) else (auth_json or {})
        domain = str(((data or {}).get("auth") or {}).get("domain") or "")
    except Exception:
        return "cn"
    from converter import INTL_DOMAINS
    return "intl" if any(d in domain for d in INTL_DOMAINS) else "cn"


def get_models(auth_json, backend_url, fetch):
    # Scope by credential/backend, without retaining raw credentials in memory.
    key = (backend_url, hashlib.sha256(auth_json.encode()).digest())
    now = time.monotonic()
    with _lock:
        cached = _cache.get(key)
        if cached and now < cached[0]:
            _cache.move_to_end(key)
            return cached[1]
    rows = fetch()
    if not rows:
        return rows
    with _lock:
        _cache[key] = (time.monotonic() + TTL_SECONDS, rows)
        _cache.move_to_end(key)
        while len(_cache) > 128:
            _cache.popitem(last=False)
    return rows


def auto_model(auth_json, backend_url, fetch):
    rows = get_models(auth_json, backend_url, fetch)
    models = [row for row in rows if row.get('id') and row['id'].lower() != 'auto']
    if not models:
        return None
    free = [row for row in models if not row.get('credits') or
            'x0.00' in str(row['credits']) or 'free' in str(row['credits']).lower()]
    return (free or models)[0]['id']
