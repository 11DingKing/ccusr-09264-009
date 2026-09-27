"""发布法定人数的纯领域规则。

法定人数按【职责角色】统计，而非简单人头数：一个角色无论由多少人
确认，都只计一票；发布必须覆盖职责集合中的每一个角色。

替代确认人的有效职责取“自身角色 ∩ 发布职责集合”与“授权范围内角色”
的并集，且授权可限定到具体包——越权角色不在任何一集合中时，确认
被拒绝。
"""
from __future__ import annotations

from collections.abc import Iterable

from .models import ReleaseDelegation


def missing_roles(
    required_roles: Iterable[str],
    confirmed_roles: Iterable[str],
) -> list[str]:
    """按职责集合计算法定人数尚缺的角色（保持 required 的顺序）。"""
    confirmed = set(confirmed_roles)
    return [role for role in required_roles if role not in confirmed]


def delegated_roles_for(
    delegations: Iterable[ReleaseDelegation],
    package_id: str,
) -> set[str]:
    """汇总替代人在该包上被授予的角色（包级授权优先，否则全局授权）。"""
    roles: set[str] = set()
    for d in delegations:
        if d.package_id is None or d.package_id == package_id:
            roles.update(d.roles)
    return roles


def confirmable_roles(
    *,
    actor_roles: Iterable[str],
    required_roles: Iterable[str],
    delegations: Iterable[ReleaseDelegation],
    package_id: str,
) -> set[str]:
    """确认人本次可代表的发布职责：

    自身拥有、且属于发布职责集合的角色，加上针对该包有效授权内的角色。
    授权之外（越权）的角色不在结果中。
    """
    required = set(required_roles)
    own = set(actor_roles) & required
    granted = delegated_roles_for(delegations, package_id) & required
    return own | granted
