"""Account ownership shared by key management and every gateway selection path.

绑定语义：一个 API Key 可以独占一个（ApiKey.account_id 主绑定，兼容老数据）
或多个账号（ApiKeyAccount 关联表）。同一个账号同时最多被一个 Key 独占。
"""
from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import aliased

from admin.models import Account, ApiKey, ApiKeyAccount


def _is_exclusive(key_col):
    """SQL 侧「该 Key 是独占模式」的条件。

    历史数据 bind_mode 可能为 NULL（老库）或空串 —— 都按 exclusive 处理，
    保证升级后老 Key 的独占语义**一字不变**（公共池照旧跳过它们的绑定账号）。
    """
    return or_(key_col.bind_mode.is_(None), key_col.bind_mode != "restricted")


def scope_accounts(query, account_id=None, key_id=None):
    """Apply ownership before health, sticky routing or fallback selection.

    account_id + key_id：账号必须属于该 Key（主绑定或关联绑定），且 Key 活跃。
    仅 key_id：Key 有独占绑定时限定到它的**全部**绑定账号（单 Key 独占多账号，
    在绑定集合内正常轮换，而不是钉死主绑定）；没有绑定则回退公共池。
    都没有：排除所有被任何活跃 Key 独占的账号（主绑定 / 关联绑定 / uid 镜像）。
    """
    key_bind_account = select(ApiKeyAccount.account_id).where(
        ApiKeyAccount.key_id == ApiKey.id).scalar_subquery()
    if account_id and key_id:
        legacy = select(ApiKey.id).where(
            ApiKey.id == key_id, ApiKey.account_id == account_id,
            ApiKey.status == "active").exists()
        extra = select(ApiKey.id).where(
            ApiKey.id == key_id, ApiKey.status == "active",
            key_bind_account == account_id).exists()
        return query.filter(Account.id == account_id, or_(legacy, extra))
    if account_id:
        owner = select(ApiKey.id).where(
            ApiKey.id == key_id, ApiKey.account_id == account_id,
            ApiKey.status == "active").exists()
        return query.filter(Account.id == account_id, owner)
    if key_id:
        # Key 的完整绑定集合：主绑定 + 关联表。Key 活跃且至少有一个绑定时，
        # 把选号限定到这个集合内（多账号可正常轮换，而不是钉死主绑定）；
        # Key 没有任何绑定则保持公共池语义。
        bound_ids = [int(r[0]) for r in query.session.query(ApiKeyAccount.account_id).filter(
            ApiKeyAccount.key_id == key_id).all() if r[0]]
        key = query.session.query(ApiKey).filter(ApiKey.id == key_id).first()
        if key is not None and key.account_id and int(key.account_id) not in bound_ids:
            bound_ids.insert(0, int(key.account_id))
        if key is not None and key.status == "active" and bound_ids:
            uid = query.session.query(Account.uid).filter(
                Account.id.in_(bound_ids), Account.uid != "").all()
            uids = [r for (r,) in uid]
            cond = Account.id.in_(bound_ids)
            if uids:
                cond = or_(cond, Account.uid.in_(uids))
            return query.filter(cond)
    reserved = aliased(Account)
    legacy_owned = select(ApiKey.id).select_from(ApiKey).outerjoin(
        reserved, reserved.id == ApiKey.account_id).where(
            ApiKey.status == "active",
            _is_exclusive(ApiKey),
            ApiKey.account_id.is_not(None),
            or_(ApiKey.account_id == Account.id,
                (reserved.uid != "") & (reserved.uid == Account.uid))).exists()
    # ⚠️ `reserved` 必须**显式 join** 到 ApiKeyAccount.account_id 上。
    #
    # 原来这里只 `join(ApiKey, ...)` 就把 `reserved` 写进了 where，SQLAlchemy 于是
    # 生成 `FROM api_key_accounts JOIN api_keys ..., accounts AS accounts_1` ——
    # 一个**没有 ON 条件的交叉连接**。结果 `accounts_1.uid != ''` 这句对整张
    # accounts 表恒成立，`multi_owned` 恒为真，所有账号被一并排除出公共池：
    # 现象就是「所有账号凭空消失，选号返回 None，测速提示没有可检测账号」。
    reserved_multi = aliased(Account)
    multi_owned = select(ApiKeyAccount.id).select_from(ApiKeyAccount).join(
        ApiKey, ApiKey.id == ApiKeyAccount.key_id).outerjoin(
        reserved_multi, reserved_multi.id == ApiKeyAccount.account_id).where(
        ApiKey.status == "active",
        _is_exclusive(ApiKey),
        or_(ApiKeyAccount.account_id == Account.id,
            (reserved_multi.uid != "") & (reserved_multi.uid == Account.uid))).exists()
    return query.filter(~legacy_owned, ~multi_owned)


def _bound_account_ids(db, key_id):
    """一个 Key 的全部独占账号 id（主绑定 + 关联表），去重保序。"""
    ids = []
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if key is not None and key.account_id:
        ids.append(int(key.account_id))
    for row in db.query(ApiKeyAccount).filter(
            ApiKeyAccount.key_id == key_id).order_by(ApiKeyAccount.id).all():
        aid = int(row.account_id)
        if aid not in ids:
            ids.append(aid)
    return ids


def _conflicting_keys(db, account_ids, exclude_key_id=None):
    """这些账号已被其他 Key 独占时，返回冲突的 ApiKey 主键集合。"""
    if not account_ids:
        return set()
    peers = db.query(Account).filter(
        or_(Account.id.in_(account_ids),
            (Account.uid != "") & Account.uid.in_(
                select(Account.uid).where(Account.id.in_(account_ids)).scalar_subquery()))
    ).order_by(Account.id).with_for_update().all()
    peer_ids = [a.id for a in peers]
    peer_uids = [a.uid for a in peers if a.uid]
    conflict_keys = set()
    # 查询范围：目标账号本身 + 同 uid 的镜像记录（重复导入会产生多行同 uid）
    all_ids = list(peer_ids)
    if peer_uids:
        all_ids += [a.id for a in db.query(Account).filter(
            Account.uid.in_(peer_uids), ~Account.id.in_(peer_ids)).all()]
    all_ids = sorted(set(all_ids))
    if not all_ids:
        return conflict_keys
    # 只有**独占** Key 才占用账号；限定账户 Key 不占用（不构成冲突）。
    # `_is_exclusive` 把 bind_mode 为 NULL/空串的历史数据按独占处理，
    # 保证升级后老 Key 的独占语义不变。
    legacy = db.query(ApiKey).filter(
        ApiKey.account_id.in_(all_ids), _is_exclusive(ApiKey))
    if exclude_key_id:
        legacy = legacy.filter(ApiKey.id != exclude_key_id)
    conflict_keys |= {k.id for k in legacy.with_for_update().all()}
    multi = db.query(ApiKeyAccount).join(
        ApiKey, ApiKey.id == ApiKeyAccount.key_id).filter(
        ApiKeyAccount.account_id.in_(all_ids), _is_exclusive(ApiKey))
    if exclude_key_id:
        multi = multi.filter(ApiKeyAccount.key_id != exclude_key_id)
    conflict_keys |= {m.key_id for m in multi.with_for_update().all()}
    return conflict_keys


def validate_binding(db, account_id, key_id=None):
    """校验单个账号绑定（保持既有行为），供单账号入口复用。"""
    ids = validate_binding_multi(db, [account_id], key_id)
    return ids[0] if ids else None


def validate_binding_multi(db, account_ids, key_id=None, exclusive=True):
    """校验并返回一个 Key 可以绑定的账号 id 列表。

    规则：
      * 空列表 / [0] / [None] → 不绑定（清空全部绑定）；
      * 每个账号必须存在；
      * exclusive=True：账号不能已被其他 Key 独占（主绑定或关联绑定，含同 uid 镜像）；
      * exclusive=False（限定账户模式）：只校验存在性，不占用账号 ——
        同一账号可以被多个限定 Key 选中，也仍留在公共池；
      * 全程行锁（with_for_update）串行化并发绑定。
    """
    if account_ids is None:
        return []
    if not isinstance(account_ids, (list, tuple)):
        raise HTTPException(400, "account_ids 必须是数组")
    cleaned = []
    for aid in account_ids:
        if aid in (None, 0, "0", ""):
            continue
        try:
            n = int(aid)
            if isinstance(aid, bool) or str(n) != str(aid).strip() or n < 1:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise HTTPException(400, "账号 ID 必须是正整数或 0（不绑定）") from None
        if n not in cleaned:
            cleaned.append(n)
    if not cleaned:
        return []
    rows = db.query(Account).filter(Account.id.in_(cleaned)).all()
    found = {a.id for a in rows}
    missing = [aid for aid in cleaned if aid not in found]
    if missing:
        raise HTTPException(400, f"账号 #{missing[0]} 不存在")
    if not exclusive:
        # 限定账户模式：不查独占冲突（账号允许被多个 Key 共享选中）
        return cleaned
    # 独占冲突判定统一走 `_conflicting_keys`（它按 `_is_exclusive` 过滤，
    # 只把**独占** Key 视为占用；限定 Key 的绑定不占账号）。
    # 这里曾内联过一份旧逻辑，没有按 bind_mode 过滤，导致限定 Key 选中的账号
    # 被误判为「已被独占」，独占 Key 反而拿不到该账号。
    conflicts = _conflicting_keys(db, cleaned, exclude_key_id=key_id)
    if conflicts:
        raise HTTPException(
            409, f"账号已被其他 API Key（#{sorted(conflicts)[0]}）独占绑定，请先解除原绑定")
    return cleaned


def sync_key_bindings(db, key_id, account_ids, exclusive=True):
    """把 Key 的绑定集合同步为 account_ids。

    独占模式：第一个账号写主绑定 `account_id`，其余进关联表（兼容老数据与
    既有查询）。限定账户模式：**主绑定一律留空，全部走关联表** —— 主绑定
    语义上代表「独占占用」，限定 Key 不该占用账号。
    """
    ids = validate_binding_multi(db, account_ids, key_id, exclusive=exclusive)
    primary = ids[0] if (ids and exclusive) else None
    rest = ids[1:] if exclusive else list(ids)
    key = db.query(ApiKey).filter(ApiKey.id == key_id).with_for_update().first()
    if key is None:
        raise HTTPException(404, "API Key 不存在")
    key.account_id = primary
    existing = {int(r.account_id): r for r in db.query(ApiKeyAccount).filter(
        ApiKeyAccount.key_id == key_id).all()}
    for aid, row in existing.items():
        if aid == primary or aid not in ids:
            db.delete(row)
    for aid in rest:
        if aid not in existing:
            db.add(ApiKeyAccount(key_id=key_id, account_id=aid))
    db.commit()
    return ids


def binding_owners(db):
    """Map duplicate account records to the same visible reservation."""
    rows = db.query(Account).all()
    keys = {k.account_id: k for k in db.query(ApiKey).filter(ApiKey.account_id.is_not(None)).all()}
    multi_rows = db.query(ApiKeyAccount).all()
    multi_keys = {m.account_id: m.key_id for m in multi_rows}
    key_by_id = {k.id: k for k in db.query(ApiKey).all()}
    for m in multi_rows:
        if m.account_id not in keys and m.key_id in key_by_id:
            keys[m.account_id] = key_by_id[m.key_id]
    by_uid = {a.uid: keys[a.id] for a in rows if a.uid and a.id in keys}
    return {a.id: keys.get(a.id) or by_uid.get(a.uid) for a in rows}
