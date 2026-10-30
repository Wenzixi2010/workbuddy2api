"""API Key 管理：创建（带积分限额）/ 列表 / 查看 / 调整 / 吊销 / 用量。"""
import base64
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from admin.account_binding import validate_binding, validate_binding_multi, sync_key_bindings
from admin.db import get_db
from admin.models import Account, ApiKey, ApiKeyAccount, ModelGroup
from admin.security import hash_key, require_admin

router = APIRouter(prefix="/api/keys", tags=["keys"])


class KeyIn(BaseModel):
    name: str = ""
    credit_limit: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    unlimited: bool | None = None
    note: str = ""
    group_id: int = 0  # 0 = 不绑定分组（可用全部启用模型）
    account_id: int | None = None  # 0 / NULL = 公共池（单账号主绑定，兼容老客户端）
    # 单 Key 独占多账号：完整绑定集合（含主绑定）。缺省 = 只用 account_id。
    account_ids: list[int] | None = None
    # 绑定模式：exclusive（独占，默认）/ restricted（限定账户 —— Key 只在选中
    # 账号内选号，但不独占它们：账号仍留在公共池、可被多个 Key 同时选中）。
    bind_mode: str | None = None
    # 该 Key 并发上限：None=跟随全局；0=不限；N=最多 N 路在途
    max_concurrent: int | None = None
    rate_per_minute: int | None = None


def _gen_key() -> str:
    # sk- 前缀 + 256-bit 密码学安全随机（secrets，无时间戳/序号/可推断规律）
    return "sk-" + secrets.token_hex(32)


def _mask(key: str) -> str:
    return key[:10] + "****" + key[-4:] if len(key) > 16 else key[:6] + "****"


def _encode_key(raw: str) -> str:
    """简单编码存储完整 key（base64，非加密；管理后台已有 JWT 保护）。"""
    return base64.b64encode(raw.encode()).decode()


def _decode_key(encoded: str) -> str:
    try:
        return base64.b64decode(encoded.encode()).decode()
    except Exception:
        return ""


@router.get("")
def list_keys(_: bool = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).order_by(ApiKey.id.desc()).all()
    group_names = {g.id: g.name for g in db.query(ModelGroup).all()}
    account_names = {a.id: a.name or a.uid for a in db.query(Account).all()}
    multi = {}
    for m in db.query(ApiKeyAccount).order_by(ApiKeyAccount.id).all():
        multi.setdefault(m.key_id, []).append(int(m.account_id))
    items = [
        {
            "id": k.id,
            "name": k.name,
            "key_prefix": k.key_prefix,
            "masked": _mask(k.key_prefix + "****************"),
            "credit_limit": k.credit_limit,
            "credit_used": k.credit_used,
            "unlimited": bool(k.unlimited),
            "max_concurrent": k.max_concurrent,
            "rate_per_minute": k.rate_per_minute,
            "status": k.status,
            "note": k.note,
            "group_id": int(k.group_id or 0),
            "group_name": group_names.get(int(k.group_id or 0), ""),
            "account_id": k.account_id,
            "account_name": account_names.get(k.account_id, ""),
            # 绑定模式：老数据 bind_mode 为空 → 按独占（exclusive）返回
            "bind_mode": ("restricted" if (k.bind_mode == "restricted") else "exclusive"),
            # 单 Key 独占多账号：完整绑定集合（主绑定在前）+ 可读名称列表
            "account_ids": ([int(k.account_id)] if k.account_id else [])
                           + [aid for aid in multi.get(k.id, []) if aid != k.account_id],
            "account_names": [account_names.get(aid, f"#{aid}")
                              for aid in ([int(k.account_id)] if k.account_id else [])
                              + [aid for aid in multi.get(k.id, []) if aid != k.account_id]],
            "created_at": k.created_at.isoformat() if k.created_at else None,
        }
        for k in rows
    ]
    return {"items": items}


def _normalize_max_concurrent(value) -> int | None:
    """规范化流量上限：None=跟随全局；0=不限；N>=1=该项上限。"""
    if value is None or value == "":
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def _validate_group(db: Session, group_id: int) -> int:
    """校验分组存在；0 表示不绑定（允许）。返回规范化后的 group_id。"""
    gid = int(group_id or 0)
    if gid and not db.query(ModelGroup).filter(ModelGroup.id == gid).first():
        raise HTTPException(status_code=400, detail=f"分组 #{gid} 不存在")
    return gid


@router.post("")
def create_key(body: KeyIn, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    raw = _gen_key()
    gid = _validate_group(db, body.group_id)
    # 单 Key 独占多账号：优先用 account_ids（完整集合）；缺省退回单账号 account_id。
    account_ids = body.account_ids if body.account_ids is not None else (
        [body.account_id] if body.account_id else [])
    # 限定账户模式只锁「用哪些号」，不占用账号：跳过独占冲突校验
    mode = "restricted" if body.bind_mode == "restricted" else "exclusive"
    ids = validate_binding_multi(db, account_ids, exclusive=(mode == "exclusive"))
    # 限定账户模式：只用关联表记录「选中了哪些号」，主绑定 `account_id` 留空。
    #
    # 为什么必须留空：`api_keys.account_id` 历史上带唯一索引（老的独占语义库级
    # 兜底），老库升级后仍可能存在；即便索引已降级，独占 Key 的主绑定与限定 Key
    # 的主绑定指向同一账号也会让 `_conflicting_keys` 的语义变浑。统一约定：
    # **主绑定只属于独占模式**，限定模式只用关联表 —— 读取侧
    # （scope_accounts / _bound_account_ids / list_keys）都是两种来源的并集。
    primary = ids[0] if (ids and mode == "exclusive") else None
    k = ApiKey(
        name=body.name or "未命名",
        key_hash=hash_key(raw),
        key_prefix=raw[:14],
        key_full=_encode_key(raw),
        credit_limit=body.credit_limit if body.credit_limit is not None else 0,
        unlimited=int(body.credit_limit is None or body.unlimited is True),
        max_concurrent=_normalize_max_concurrent(body.max_concurrent),
        rate_per_minute=_normalize_max_concurrent(body.rate_per_minute),
        note=body.note,
        group_id=gid,
        account_id=primary,
        bind_mode=mode,
    )
    db.add(k)
    _commit_key(db)
    db.refresh(k)
    if ids and (len(ids) > 1 or mode == "restricted"):
        from admin.account_binding import sync_key_bindings
        sync_key_bindings(db, k.id, ids, exclusive=(mode == "exclusive"))
    # 明文 key 仅此返回一次
    return {
        "id": k.id,
        "name": k.name,
        "key": raw,
        "key_prefix": k.key_prefix,
        "credit_limit": k.credit_limit,
        "unlimited": bool(k.unlimited),
        "max_concurrent": k.max_concurrent,
        "rate_per_minute": k.rate_per_minute,
        "group_id": int(k.group_id or 0),
        "account_id": k.account_id,
        "account_ids": ids,
        "bind_mode": mode,
    }


@router.get("/{key_id}/view")
def view_key(key_id: int, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    """查看 Key 完整值（创建后可再次查看）。"""
    k = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not k:
        raise HTTPException(status_code=404, detail="Key 不存在")
    raw = _decode_key(k.key_full)
    if not raw:
        raise HTTPException(status_code=410, detail="该 Key 创建于「查看功能」上线前，完整值未存储。建议重新生成一个新 Key。")
    return {
        "id": k.id,
        "name": k.name,
        "key": raw,
        "key_prefix": k.key_prefix,
        "created_at": k.created_at.isoformat() if k.created_at else None,
    }


@router.get("/{key_id}/usage")
def key_usage(key_id: int, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    """查看 Key 的积分额度消耗情况。"""
    k = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not k:
        raise HTTPException(status_code=404, detail="Key 不存在")
    pct = ((k.credit_used / k.credit_limit) * 100) if k.credit_limit > 0 and not k.unlimited else None
    return {
        "id": k.id,
        "name": k.name,
        "credit_limit": k.credit_limit,
        "credit_used": round(k.credit_used, 2),
        "credit_remaining": (round(max(0, k.credit_limit - k.credit_used), 2) if not k.unlimited else None),
        "usage_percent": round(pct, 1) if pct is not None else None,
        "unlimited": bool(k.unlimited),
        "status": k.status,
        "created_at": k.created_at.isoformat() if k.created_at else None,
    }


@router.patch("/{key_id}")
def patch_key(key_id: int, body: dict, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not k:
        raise HTTPException(status_code=404, detail="Key 不存在")
    if "bind_mode" in body and body["bind_mode"] in ("exclusive", "restricted"):
        k.bind_mode = body["bind_mode"]
    if "account_ids" in body or "account_id" in body:
        # 单 Key 独占多账号：account_ids（完整集合）优先；缺省退回单账号语义。
        # 限定账户模式下不校验独占冲突（账号允许被多个 Key 选中）。
        exclusive = (k.bind_mode != "restricted")
        if "account_ids" in body and body["account_ids"] is not None:
            sync_key_bindings(db, key_id, body["account_ids"], exclusive=exclusive)
            db.refresh(k)
        else:
            from admin.account_binding import validate_binding_multi
            ids = validate_binding_multi(db, [body["account_id"]], key_id, exclusive=exclusive)
            k.account_id = ids[0] if ids else None
    if "name" in body:
        k.name = body["name"]
    if "credit_limit" in body:
        value = body["credit_limit"]
        if value is None or value == "":
            k.credit_limit = 0
            k.unlimited = 1
        else:
            import math
            try:
                value = float(value)
                if not math.isfinite(value) or value < 0:
                    raise ValueError()
            except (ValueError, TypeError):
                raise HTTPException(400, "Key 额度必须为空或大于等于 0 的有限数字") from None
            k.credit_limit = value
            k.unlimited = 0
    if "unlimited" in body:
        if body["unlimited"]:
            k.unlimited = 1
        elif "credit_limit" not in body or body["credit_limit"] not in (None, ""):
            k.unlimited = 0
    if "max_concurrent" in body:
        k.max_concurrent = _normalize_max_concurrent(body["max_concurrent"])
    if "rate_per_minute" in body:
        k.rate_per_minute = _normalize_max_concurrent(body["rate_per_minute"])
    if "status" in body and body["status"] in ("active", "revoked"):
        k.status = body["status"]
    if "note" in body:
        k.note = body["note"]
    if "group_id" in body:
        k.group_id = _validate_group(db, body["group_id"])
    if body.get("reset_used"):
        k.credit_used = 0
    _commit_key(db)
    return {"id": k.id, "ok": True}


def _commit_key(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "该账号已被其他 API Key 独占绑定，请刷新后重试") from None


@router.delete("/{key_id}")
def delete_key(key_id: int, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not k:
        raise HTTPException(status_code=404, detail="Key 不存在")
    # 必须先删关联表里的独占绑定，否则会留下孤儿记录：
    # `scope_accounts` 按 `ApiKeyAccount.key_id` 判独占，不校验 Key 是否还存在，
    # 于是这些账号会被永久视为「已被某个 Key 独占」，从此再也选不出来 ——
    # 表现就是「删了 Key 之后，某些账号凭空从公共池消失」。
    db.query(ApiKeyAccount).filter(ApiKeyAccount.key_id == key_id).delete(synchronize_session=False)
    db.delete(k)
    db.commit()
    return {"id": key_id, "ok": True}
