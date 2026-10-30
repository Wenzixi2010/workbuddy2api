"""OpenAI 兼容中转站计费接口（OneAPI / New API 风格）。

为什么要有这两个端点
----------------
DSH 小鲸鱼挂件（dsh-whale-widget）的「自定义 API / 模型余额」功能内置了
**OpenAI 兼容中转站（OneAPI / New API）** 模板：

    balance: {
      url: '{base}/v1/dashboard/billing/subscription',
      json: { total: 'hard_limit_usd' },
      usage: { url: '{base}/v1/dashboard/billing/usage',
               json: { used: 'total_usage', scale: 0.01 } },
    }

挂件用「Authorization: Bearer <key>」请求这两个 GET，读出
`hard_limit_usd`（总额度，元）与 `total_usage`（已用，**美分**，挂件端
乘 0.01 折回元），然后 remaining = total - used 画到鲸鱼泡泡上。

本网关本身就是「OpenAI 兼容中转站」的形态，把这两个端点按同口径实现后，
用户在挂件里选该模板、填网关地址 + 任意一把 sk- 代理 Key，即可直接
看到账号池的积分余额与该 Key 的消费，零额外配置。

口径（单位换算要精确，错一位显示就差 100 倍）：
  * 网关积分以**元（credits）**记账；
  * OneAPI 模板语义里 total 是元、usage 是美分 → 返回时
    used_cents = round(used_credits * 100)；
  * unlimited Key：total 取全池当前可用积分总和（观测量，非硬上限），
    used 取该 Key 的 credit_used；
  * 有限额 Key：total 取该 Key 的 credit_limit。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from admin.models import Account, ApiKey
from admin.security import get_key_row
from admin.db import get_db

router = APIRouter(tags=["billing-compat"])


def _key_from_header(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> ApiKey:
    """与 /v1/chat/completions 同一把 sk- 代理 Key 鉴权（X-API-Key 优先）。"""
    api_key = (x_api_key or "").strip()
    if not api_key and authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:].strip()
    from fastapi import HTTPException
    if not api_key:
        raise HTTPException(status_code=401, detail="缺少 API Key")
    return api_key


def _pool_remaining_credits(db: Session) -> float:
    """全池当前可用积分：各账号 balance_remain 之和（只算启用账号）。"""
    rows = db.query(Account.balance_remain).filter(
        Account.status == "active").all()
    return float(sum((r[0] or 0) for r in rows))


def _key_scope_credits(db: Session, key: ApiKey) -> float:
    """这把 Key 能看到的**上游真实积分**。

    口径：Key 绑定了账号 → 只算被绑定的那些账号（这把 Key 的消耗只落在
    这些号上，看全池总额反而误导），多个 Key 绑定同一账号时各自显示同一份
    账号积分是正常的；未绑定任何账号（共享 Key）→ 全池启用账号之和。
    注意这与 credit_limit（本地计费限额）是两个维度 —— 有限额的 Key 在
    subscription 端点仍显示其限额。
    """
    from admin.account_binding import _bound_account_ids
    bound = _bound_account_ids(db, key.id)
    if bound:
        rows = db.query(Account.balance_remain).filter(
            Account.id.in_(bound)).all()
        return float(sum((r[0] or 0) for r in rows))
    return _pool_remaining_credits(db)


@router.get("/v1/dashboard/billing/subscription")
def billing_subscription(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    """总额度：OneAPI 口径的 hard_limit_usd（单位 = 元/积分）。

    unlimited Key → 这把 Key **对应账号**的上游积分（有绑定算绑定号，
    共享 Key 算全池）；有限额 Key → 其本地限额 credit_limit。
    """
    api_key = _key_from_header(authorization, x_api_key)
    key = get_key_row(db, api_key)
    if key is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="无效 API Key")
    if key.unlimited:
        total = _key_scope_credits(db, key)
    else:
        total = float(key.credit_limit or 0)
    return {
        # OneAPI/New API 字段名逐字对齐（挂件按 'hard_limit_usd' 取）
        "object": "billing_subscription",
        "has_payment_method": True,
        "soft_limit_usd": total,
        "hard_limit_usd": total,
        "system_hard_limit_usd": total,
        "access_until": 0,
    }


@router.get("/v1/dashboard/billing/usage")
def billing_usage(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    """已用额度：OneAPI 口径的 total_usage（单位 = **美分**）。"""
    api_key = _key_from_header(authorization, x_api_key)
    key = get_key_row(db, api_key)
    if key is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="无效 API Key")
    used_credits = float(key.credit_used or 0)
    return {
        "object": "list",
        # OneAPI/New API 字段名逐字对齐（挂件按 'total_usage' 取，单位美分）
        "total_usage": round(used_credits * 100, 2),
        # 顺带给一份元口径，便于人工核对（挂件不读这两个字段）
        "total_usage_credits": round(used_credits, 4),
        "daily_costs": [],
    }
