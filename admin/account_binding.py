"""Account ownership shared by key management and every gateway selection path.

绑定语义（两种方式，二选一）：

  * **独占（exclusive）** —— 账号被这把 Key 选中后，**只**归选中它的那些 Key
    使用，永不进公共池。一个账号可以被多把独占 Key 同时选中（叠加占用，
    互不抢占）；要解除只能各自解绑。
  * **白名单（whitelist）** —— 只限制「这把 Key 能用哪些号」，账号本身
    **不受任何影响**，照常留在公共池供其它 Key 使用。

历史说明：早期只有互斥独占（一个账号至多一把 Key）；后来尝试过
「多 Key 共享同一账号且账号留池」，但那让独占失去意义，故拆成上面两种。
"""
from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import aliased

from admin.models import Account, ApiKey, ApiKeyAccount


def _is_exclusive(key_col):
    """SQL 侧「该 Key 是独占模式」的条件。

    bind_mode 为 NULL / 空串的历史数据一律按 exclusive 处理 —— 老 Key 的
    独占语义在升级后保持不变。
    """
    return or_(key_col.bind_mode.is_(None), key_col.bind_mode != "whitelist")


def scope_accounts(query, account_id=None, key_id=None):
    """Apply ownership before health, sticky routing or fallback selection.

    account_id + key_id：账号必须属于该 Key（主绑定或关联绑定），且 Key 活跃。
    仅 key_id：Key 有绑定时限定到它的**全部**绑定账号（单 Key 绑定多账号，
    在绑定集合内正常轮换，而不是钉死主绑定）；没有绑定则回退公共池。
    都没有：公共池 —— 排除所有被任何活跃 Key 绑定的账号（归属语义不变）。
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
    # 公共池：排除**被任何活跃「独占」Key 选中的账号**。
    #
    # 两种绑定方式的区别正在这里：
    #   * exclusive（独占）：账号被选走后**只归绑定它的这些 Key 使用**，
    #     永不进公共池。一个账号可以被多把独占 Key 同时选中（叠加，不抢占），
    #     但公共池始终看不到它。
    #   * whitelist（白名单）：只限制「这把 Key 能用哪些号」，账号**不受影响**，
    #     照常留在公共池供其它 Key 使用。
    #
    # ⚠️ `reserved` / `reserved_multi` 必须**显式 join** 到对应的
    # `ApiKey.account_id` / `ApiKeyAccount.account_id` 上。
    # 早年这里只 `join(ApiKey, ...)` 就把别名写进了 where，SQLAlchemy 于是
    # 生成一个**没有 ON 条件的交叉连接** —— `accounts_1.uid != ''` 对整张表
    # 恒成立，所有账号被一并排除出公共池（现象：账号凭空消失、选号返回 None）。
    reserved = aliased(Account)
    legacy_owned = select(ApiKey.id).select_from(ApiKey).outerjoin(
        reserved, reserved.id == ApiKey.account_id).where(
            ApiKey.status == "active",
            _is_exclusive(ApiKey),
            ApiKey.account_id.is_not(None),
            or_(ApiKey.account_id == Account.id,
                (reserved.uid != "") & (reserved.uid == Account.uid))).exists()
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
    """一个 Key 的全部绑定账号 id（主绑定 + 关联表），去重保序。"""
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


def validate_binding(db, account_id, key_id=None):
    """校验单个账号绑定（保持既有行为），供单账号入口复用。"""
    ids = validate_binding_multi(db, [account_id], key_id)
    return ids[0] if ids else None


def validate_binding_multi(db, account_ids, key_id=None):
    """校验并归一一个 Key 要绑定的账号 id 列表。

    规则：
      * 空列表 / [0] / [None] → 不绑定（清空全部绑定）；
      * 每个账号必须存在；
      * **不与其它 Key 冲突**：同一账号可被多把 Key 同时选中（独占是叠加，
        白名单只是各管各的），所以这里只校验存在性。
    返回去重后的 id 列表。
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
    return cleaned


def sync_key_bindings(db, key_id, account_ids):
    """把 Key 的绑定集合同步为 account_ids。

    第一个账号写主绑定 `account_id`（兼容老数据与既有查询），其余进关联表。
    两种绑定方式（独占 / 白名单）在这里做法一致 —— 差别只在「账号是否因此
    退出公共池」，那由 `scope_accounts` 按 Key 的 bind_mode 判定。
    多把 Key 可以选中同一账号，互不抢占。
    """
    ids = validate_binding_multi(db, account_ids, key_id)
    key = db.query(ApiKey).filter(ApiKey.id == key_id).with_for_update().first()
    if key is None:
        raise HTTPException(404, "API Key 不存在")
    primary = ids[0] if ids else None
    rest = ids[1:]
    key.account_id = primary
    existing = {int(r.account_id): r for r in db.query(ApiKeyAccount).filter(
        ApiKeyAccount.key_id == key_id).all()}
    for aid, row in existing.items():
        if aid == primary or aid not in ids:
            db.delete(row)
    for aid in rest:
        if aid not in existing:
            db.add(ApiKeyAccount(key_id=key_id, account_id=aid))
    # 只 flush 不 commit：让调用方把「模式 / 名称 / 限额」等改动与绑定一起提交，
    # 避免中途 commit 让会话对象过期、后续字段写不进去。
    db.flush()
    return ids


def binding_owners(db):
    """Map duplicate account records to a single visible binding label.

    一个账号可能被多把 Key 绑定（已非互斥），这里只挑一把用于界面展示
    （优先主绑定、其次关联表里最早的一条），供账号列表标注「被哪个 Key 使用」。
    """
    rows = db.query(Account).all()
    keys = {k.account_id: k for k in db.query(ApiKey).filter(ApiKey.account_id.is_not(None)).all()}
    multi_rows = db.query(ApiKeyAccount).order_by(ApiKeyAccount.id).all()
    key_by_id = {k.id: k for k in db.query(ApiKey).all()}
    for m in multi_rows:
        if m.account_id not in keys and m.key_id in key_by_id:
            keys[m.account_id] = key_by_id[m.key_id]
    by_uid = {a.uid: keys[a.id] for a in rows if a.uid and a.id in keys}
    return {a.id: keys.get(a.id) or by_uid.get(a.uid) for a in rows}
