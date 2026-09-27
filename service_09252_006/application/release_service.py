"""发布服务：发布法定人数、职责范围替代授权与发布。

法定人数按【职责角色】统计：SQLite 的 release_roles 表是职责集合的唯一
依据，release_confirmations 对“包 × 角色”去重，因此多个人头不能凑出
同一个角色，缺哪个角色就由发布接口在 missing_roles 中返回。

替代（delegate）确认人持有质量权威签发的授权，授权限定到具体角色集合，
并可进一步限定到单个包；确认时实际可代表的职责为

    自身角色 ∩ 发布职责集合  ∪  授权角色 ∩ 发布职责集合（且包范围匹配）

授权之外的角色一律拒绝（PermissionDenied），替代只在授权范围内生效。
"""
from __future__ import annotations

from ..domain.enums import Decision, PackageStatus, Role
from ..domain.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    QuorumInsufficientError,
    ValidationError,
)
from ..domain.models import ReleaseConfirmation, ReleaseDelegation, User
from ..domain.quorum import confirmable_roles, missing_roles
from .base import Service, require_roles

_VALID_ROLES = {r.value for r in Role}


class ReleaseService(Service):
    # -------------------------------------------------------- 职责集合维护
    def configure_release_roles(
        self,
        actor: User,
        *,
        roles: list[str],
        idempotency_key: str | None = None,
    ) -> dict:
        """质量权威维护发布法定人数的职责集合（整体替换）。"""
        require_roles(actor, Role.QUALITY_AUTHORITY)
        cleaned = self._validate_roles(roles)

        def work() -> dict:
            self.repo.set_release_roles(cleaned, self.clock.now_iso())
            self.audit(
                actor.user_id, "release.roles_configured",
                detail={"roles": cleaned},
            )
            return {"release_roles": cleaned, "replayed": False}

        return self.idempotent(idempotency_key, work)

    def list_release_roles(self, actor: User) -> dict:
        require_roles(
            actor,
            Role.QUALITY_AUTHORITY,
            Role.INSTITUTION_ADMIN,
            Role.AUDITOR,
        )
        return {"release_roles": self.repo.list_release_roles()}

    # ------------------------------------------------------------ 替代授权
    def delegate_release(
        self,
        actor: User,
        *,
        substitute_id: str,
        roles: list[str],
        package_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """质量权威授权替代人在给定职责（可限包）范围内代为确认发布。"""
        require_roles(actor, Role.QUALITY_AUTHORITY)
        cleaned = self._validate_roles(roles)

        def work() -> dict:
            substitute = self.repo.get_user(substitute_id)
            if substitute is None:
                raise NotFoundError(
                    "替代人不存在", details={"substitute_id": substitute_id}
                )
            required = set(self.repo.list_release_roles())
            out_of_scope = [r for r in cleaned if r not in required]
            if out_of_scope:
                raise ValidationError(
                    "只能就发布职责集合内的角色授权",
                    details={"out_of_scope_roles": out_of_scope},
                )
            if package_id is not None and self.repo.get_package(package_id) is None:
                raise NotFoundError(
                    "授权限定的评审包不存在", details={"package_id": package_id}
                )
            delegation = ReleaseDelegation(
                delegation_id=self.ids.new_id("del"),
                substitute_id=substitute_id,
                roles=tuple(cleaned),
                package_id=package_id,
                granted_by=actor.user_id,
                granted_at=self.clock.now_iso(),
            )
            self.repo.insert_release_delegation(delegation)
            self.audit(
                actor.user_id, "release.delegated",
                package_id=package_id,
                detail={
                    "delegation_id": delegation.delegation_id,
                    "substitute_id": substitute_id,
                    "roles": cleaned,
                    "package_scoped": package_id is not None,
                },
            )
            return {
                "delegation_id": delegation.delegation_id,
                "substitute_id": substitute_id,
                "roles": list(delegation.roles),
                "package_id": package_id,
                "granted_by": actor.user_id,
                "granted_at": delegation.granted_at,
                "replayed": False,
            }

        return self.idempotent(idempotency_key, work)

    # -------------------------------------------------------------- 确认
    def confirm_release(
        self,
        actor: User,
        *,
        package_id: str,
        role: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """发布委员会成员以某个职责角色确认该包发布。

        未显式指定角色时，若确认人在该包上恰有一个可代表职责则自动采用。
        """
        def work() -> dict:
            package = self._require_decided_unreleased(package_id)
            required = self.repo.list_release_roles()
            delegations = self.repo.list_release_delegations(actor.user_id)
            allowed = confirmable_roles(
                actor_roles=actor.roles,
                required_roles=required,
                delegations=delegations,
                package_id=package_id,
            )
            if not allowed:
                raise PermissionDeniedError(
                    "当前身份不在发布委员会职责集合内，也无有效替代授权",
                )

            existing = {
                c.role: c for c in self.repo.list_release_confirmations(package_id)
            }
            chosen = role
            if chosen is None:
                if len(allowed) == 1:
                    chosen = next(iter(allowed))
                else:
                    raise ValidationError(
                        "可代表多个发布职责，必须显式指定本次确认的角色",
                        details={"confirmable_roles": sorted(allowed)},
                    )
            if chosen not in required:
                raise ValidationError(
                    "该角色不属于发布职责集合", details={"role": chosen}
                )
            if chosen not in allowed:
                # 替代人越权：自身不持有该角色，授权也未覆盖（或包范围不匹配）
                raise PermissionDeniedError(
                    "替代确认只能在授权范围内生效，无权代表该职责",
                    details={"role": chosen, "substitute_id": actor.user_id},
                )

            replayed = False
            if chosen in existing:
                replayed = True
                delegated = existing[chosen].delegated
            else:
                delegated = chosen not in set(actor.roles)
                confirmation = ReleaseConfirmation(
                    confirmation_id=self.ids.new_id("cnf"),
                    package_id=package_id,
                    role=chosen,
                    confirmer_id=actor.user_id,
                    delegated=delegated,
                    confirmed_at=self.clock.now_iso(),
                )
                self.repo.insert_release_confirmation(confirmation)
                # 并发下同角色确认可能被唯一约束静默忽略：以库中既存行为准
                stored = {
                    c.role: c
                    for c in self.repo.list_release_confirmations(package_id)
                }.get(chosen)
                if stored is not None and stored.confirmer_id != actor.user_id:
                    replayed = True
                    delegated = stored.delegated
                else:
                    self.audit(
                        actor.user_id, "release.confirmed",
                        package_id=package_id, institution_id=package.institution_id,
                        detail={"role": chosen, "delegated": delegated},
                    )

            confirmed_roles = {
                c.role for c in self.repo.list_release_confirmations(package_id)
            }
            return {
                "package_id": package_id,
                "role": chosen,
                "confirmer_id": actor.user_id,
                "delegated": delegated,
                "confirmed_roles": sorted(confirmed_roles),
                "missing_roles": missing_roles(required, confirmed_roles),
                "replayed": replayed,
            }

        return self.idempotent(idempotency_key, work)

    # -------------------------------------------------------------- 发布
    def release_package(
        self,
        actor: User,
        *,
        package_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.QUALITY_AUTHORITY, Role.INSTITUTION_ADMIN)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if package.released_at is not None:
                return self._release_view(package, replayed=True)
            if package.status != PackageStatus.DECIDED.value:
                raise ConflictError(
                    "仅已签发结论的评审包可发布",
                    details={"status": package.status},
                )
            if package.decision != Decision.APPROVED.value:
                raise ConflictError(
                    "只有通过（approved）的签发结论可发布",
                    details={"decision": package.decision},
                )

            required = self.repo.list_release_roles()
            confirmed_roles = {
                c.role for c in self.repo.list_release_confirmations(package_id)
            }
            absent = missing_roles(required, confirmed_roles)
            if absent:
                # 法定人数按角色统计：缺位角色随冲突响应返回
                raise QuorumInsufficientError(
                    "发布法定人数不足，缺少职责角色确认",
                    details={"missing_roles": absent},
                )

            released_at = self.clock.now_iso()
            moved = self.repo.mark_package_released(
                package_id, PackageStatus.DECIDED.value, released_at
            )
            if not moved:
                fresh = self.repo.get_package(package_id)
                if fresh is not None and fresh.released_at is not None:
                    return self._release_view(fresh, replayed=True)
                raise ConflictError("评审包状态已被其他操作改变，请重试")

            self.audit(
                actor.user_id, "release.published",
                package_id=package_id, institution_id=package.institution_id,
                detail={"released_at": released_at, "confirmed_roles": sorted(required)},
            )
            return self._release_view(self.repo.get_package(package_id))

        return self.idempotent(idempotency_key, work)

    # -------------------------------------------------------------- 查询
    def get_release_status(self, actor: User, package_id: str) -> dict:
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        is_party = (
            actor.institution_id == package.institution_id
            or actor.has_role(Role.QUALITY_AUTHORITY)
            or actor.has_role(Role.AUDITOR)
            or any(
                d.package_id is None or d.package_id == package_id
                for d in self.repo.list_release_delegations(actor.user_id)
            )
            or any(
                c.confirmer_id == actor.user_id
                for c in self.repo.list_release_confirmations(package_id)
            )
        )
        if not is_party:
            raise PermissionDeniedError("不能查看该评审包的发布状态")
        return self._release_view(package)

    # --------------------------------------------------------------- 内部
    def _require_decided_unreleased(self, package_id: str):
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        if package.released_at is not None:
            raise ConflictError("评审包已发布，不能再追加确认")
        if package.status != PackageStatus.DECIDED.value:
            raise ConflictError(
                "评审结论签发后才能进行发布确认",
                details={"status": package.status},
            )
        return package

    @staticmethod
    def _validate_roles(roles: list[str]) -> list[str]:
        if not roles:
            raise ValidationError("职责角色集合不能为空")
        cleaned: list[str] = []
        for r in roles:
            if not isinstance(r, str) or not r.strip():
                raise ValidationError("角色名不能为空")
            if r not in _VALID_ROLES:
                raise ValidationError("未知角色", details={"role": r})
            if r not in cleaned:
                cleaned.append(r)
        return cleaned

    def _release_view(self, package, *, replayed: bool = False) -> dict:
        required = self.repo.list_release_roles()
        confirmations = self.repo.list_release_confirmations(package.package_id)
        confirmed_roles = sorted({c.role for c in confirmations})
        return {
            "package_id": package.package_id,
            "status": package.status,
            "decision": package.decision,
            "released": package.released_at is not None,
            "released_at": package.released_at,
            "required_roles": list(required),
            "confirmed_roles": confirmed_roles,
            "missing_roles": missing_roles(required, confirmed_roles),
            "confirmations": [
                {
                    "role": c.role,
                    "confirmer_id": c.confirmer_id,
                    "delegated": c.delegated,
                    "confirmed_at": c.confirmed_at,
                }
                for c in confirmations
            ],
            "replayed": replayed,
        }
