"""发布服务：发布委员会的职责确认与发布法定人数。

规则要点：
- 发布法定人数按【角色】而非简单人数统计：只有职责集合中的每个角色都
  至少被一条确认覆盖，法定人数才齐备；同一角色被多人重复确认不推进
  法定人数；
- 职责集合存于 SQLite（release_committee_roles），角色确认始终按
  库中当前的职责集合统计，缺位角色随集合调整即时变化；
- 替代确认人只能在授权范围内生效：确认某职责时，本人须持有该角色，
  或存在针对该角色的替代授权（release_delegations），越权确认被拒绝；
- 发布接口返回缺少的角色：未达到法定人数时以 409 冲突回应，details
  中列出 missing_roles；查询与发布成功的响应同样携带缺位角色列表。

并发模型与评审服务一致：写用例在 BEGIN IMMEDIATE 事务内执行，发布
用条件 UPDATE 固定 released，并发双发布只有一方推进，另一方回放。
"""
from __future__ import annotations

from ..domain.enums import (
    ConfirmationVia,
    Decision,
    PackageStatus,
    ReleaseStatus,
    Role,
)
from ..domain.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.models import (
    Release,
    ReleaseConfirmation,
    ReleaseDelegation,
    User,
)
from .base import Service, require_roles, require_user


class ReleaseService(Service):
    # --------------------------------------------------------- 委员会
    def define_committee(
        self,
        actor: User,
        *,
        roles: list[str],
        idempotency_key: str | None = None,
    ) -> dict:
        """定义发布委员会的职责集合（整体替换）。仅权威机构可定义。"""
        require_roles(actor, Role.QUALITY_AUTHORITY)
        valid = {r.value for r in Role}
        cleaned: list[str] = []
        for raw in roles or []:
            role = (raw or "").strip()
            if not role:
                continue
            if role not in valid:
                raise ValidationError("未知职责角色", details={"role": role})
            if role not in cleaned:
                cleaned.append(role)
        if not cleaned:
            raise ValidationError("发布法定人数至少需要一个职责")

        def work() -> dict:
            self.repo.replace_committee_roles(cleaned)
            self.audit(
                actor.user_id, "committee.defined",
                detail={"required_roles": sorted(cleaned)},
            )
            return {"required_roles": sorted(cleaned)}

        return self.idempotent(idempotency_key, work)

    def get_committee(self, actor: User) -> dict:
        require_user(actor)
        return {"required_roles": sorted(self.repo.list_committee_roles())}

    def delegate_substitute(
        self,
        actor: User,
        *,
        delegate_user_id: str,
        role: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """授权替代确认人：允许其在指定职责上代为确认（授权范围）。"""
        require_roles(actor, Role.QUALITY_AUTHORITY)
        role = (role or "").strip()
        if role not in {r.value for r in Role}:
            raise ValidationError("未知职责角色", details={"role": role})

        def work() -> dict:
            delegate = self.repo.get_user(delegate_user_id)
            if delegate is None:
                raise NotFoundError("替代确认人不存在")
            existing = self.repo.find_delegation(delegate_user_id, role)
            if existing is not None:
                return self._delegation_dict(existing, replayed=True)
            delegation = ReleaseDelegation(
                delegation_id=self.ids.new_id("del"),
                delegate_user_id=delegate_user_id,
                role=role,
                created_by=actor.user_id,
                created_at=self.clock.now_iso(),
            )
            self.repo.insert_delegation(delegation)
            self.audit(
                actor.user_id, "delegation.created",
                detail={
                    "delegation_id": delegation.delegation_id,
                    "delegate_user_id": delegate_user_id,
                    "role": role,
                },
            )
            return self._delegation_dict(delegation)

        return self.idempotent(idempotency_key, work)

    # ----------------------------------------------------------- 发布
    def create_release(
        self,
        actor: User,
        *,
        package_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """为已签发通过的评审包创建发布，等待委员会按职责确认。"""
        require_roles(actor, Role.QUALITY_AUTHORITY, Role.INSTITUTION_ADMIN)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if (
                not actor.has_role(Role.QUALITY_AUTHORITY)
                and package.institution_id != actor.institution_id
            ):
                raise PermissionDeniedError("只能为本机构评审包创建发布")
            if package.status != PackageStatus.DECIDED.value:
                raise ConflictError(
                    "仅已签发的评审包可创建发布",
                    details={"status": package.status},
                )
            if package.decision != Decision.APPROVED.value:
                raise ConflictError(
                    "仅签发通过的评审包可发布",
                    details={"decision": package.decision},
                )
            existing = self.repo.get_release_by_package(package_id)
            if existing is not None:
                return self._release_dict(existing, replayed=True)
            release = Release(
                release_id=self.ids.new_id("rel"),
                package_id=package_id,
                institution_id=package.institution_id,
                status=ReleaseStatus.PENDING.value,
                created_by=actor.user_id,
                created_at=self.clock.now_iso(),
                released_at=None,
            )
            self.repo.insert_release(release)
            self.audit(
                actor.user_id, "release.created",
                package_id=package_id, institution_id=package.institution_id,
                detail={"release_id": release.release_id},
            )
            return self._release_dict(release)

        return self.idempotent(idempotency_key, work)

    def confirm_release(
        self,
        actor: User,
        *,
        release_id: str,
        role: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """确认发布的一个职责。

        确认人本人持有该角色时记为 direct；否则须存在针对该角色的
        替代授权才记为 substitute——替代确认人越权（授权范围之外的
        职责）一律拒绝。
        """
        require_user(actor)
        role = (role or "").strip()
        if not role:
            raise ValidationError("职责不能为空")

        def work() -> dict:
            release = self.repo.get_release(release_id)
            if release is None:
                raise NotFoundError("发布不存在")
            if release.status != ReleaseStatus.PENDING.value:
                raise ConflictError(
                    "发布已完成，不能再确认",
                    details={"status": release.status},
                )
            required = set(self.repo.list_committee_roles())
            if role not in required:
                raise ValidationError(
                    "该职责不在发布法定人数要求内",
                    details={"role": role, "required_roles": sorted(required)},
                )
            # 先鉴权再幂等：越权的替代确认即使落在已覆盖职责上也必须失败
            if actor.has_role(role):
                via = ConfirmationVia.DIRECT.value
            elif self.repo.find_delegation(actor.user_id, role) is not None:
                via = ConfirmationVia.SUBSTITUTE.value
            else:
                raise PermissionDeniedError(
                    "未持有该职责，且未被授权为替代确认人",
                    details={"role": role},
                )
            existing = self.repo.find_confirmation(release_id, role)
            if existing is not None:
                return self._confirmation_dict(existing, replayed=True)
            confirmation = ReleaseConfirmation(
                confirmation_id=self.ids.new_id("cfm"),
                release_id=release_id,
                user_id=actor.user_id,
                role=role,
                via=via,
                created_at=self.clock.now_iso(),
            )
            self.repo.insert_confirmation(confirmation)
            self.audit(
                actor.user_id, "release.confirmed",
                package_id=release.package_id,
                institution_id=release.institution_id,
                detail={
                    "confirmation_id": confirmation.confirmation_id,
                    "release_id": release_id,
                    "role": role,
                    "via": via,
                },
            )
            return self._confirmation_dict(confirmation)

        return self.idempotent(idempotency_key, work)

    def publish_release(
        self,
        actor: User,
        *,
        release_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """发布：法定人数（按职责统计）不齐时以冲突返回缺少的角色。"""
        require_roles(actor, Role.QUALITY_AUTHORITY)

        def work() -> dict:
            release = self.repo.get_release(release_id)
            if release is None:
                raise NotFoundError("发布不存在")
            if release.status == ReleaseStatus.RELEASED.value:
                return self._release_dict(release, replayed=True)
            view = self._quorum_view(release_id)
            if not view["required_roles"]:
                raise ConflictError("发布委员会职责集合为空，不能发布")
            if view["missing_roles"]:
                raise ConflictError(
                    "发布法定人数不足",
                    details={
                        "missing_roles": view["missing_roles"],
                        "required_roles": view["required_roles"],
                        "confirmed_roles": view["confirmed_roles"],
                    },
                )
            moved = self.repo.transition_release_status(
                release_id,
                ReleaseStatus.PENDING.value,
                ReleaseStatus.RELEASED.value,
                released_at=self.clock.now_iso(),
            )
            if not moved:
                fresh = self.repo.get_release(release_id)
                if fresh.status == ReleaseStatus.RELEASED.value:
                    return self._release_dict(fresh, replayed=True)
                raise ConflictError("发布状态已被其他操作改变，请重试")
            self.audit(
                actor.user_id, "release.published",
                package_id=release.package_id,
                institution_id=release.institution_id,
                detail={
                    "release_id": release_id,
                    "required_roles": view["required_roles"],
                    "confirmed_roles": view["confirmed_roles"],
                },
            )
            return self._release_dict(self.repo.get_release(release_id))

        return self.idempotent(idempotency_key, work)

    # ----------------------------------------------------------- 查询
    def get_release(self, actor: User, release_id: str) -> dict:
        require_user(actor)
        release = self.repo.get_release(release_id)
        if release is None:
            raise NotFoundError("发布不存在")
        if (
            actor.institution_id != release.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看该发布")
        return self._release_dict(release)

    # ----------------------------------------------------------- 内部
    def _quorum_view(self, release_id: str) -> dict:
        """按 SQLite 中的职责集合统计角色确认，得出缺位角色。"""
        required = set(self.repo.list_committee_roles())
        confirmed = {
            c.role for c in self.repo.list_confirmations(release_id)
        } & required
        missing = sorted(required - confirmed)
        return {
            "required_roles": sorted(required),
            "confirmed_roles": sorted(confirmed),
            "missing_roles": missing,
            "quorum_met": bool(required) and not missing,
        }

    def _release_dict(self, release: Release, *, replayed: bool = False) -> dict:
        return {
            "release_id": release.release_id,
            "package_id": release.package_id,
            "institution_id": release.institution_id,
            "status": release.status,
            "created_by": release.created_by,
            "created_at": release.created_at,
            "released_at": release.released_at,
            **self._quorum_view(release.release_id),
            "replayed": replayed,
        }

    @staticmethod
    def _confirmation_dict(
        c: ReleaseConfirmation, *, replayed: bool = False
    ) -> dict:
        return {
            "confirmation_id": c.confirmation_id,
            "release_id": c.release_id,
            "user_id": c.user_id,
            "role": c.role,
            "via": c.via,
            "created_at": c.created_at,
            "replayed": replayed,
        }

    @staticmethod
    def _delegation_dict(d: ReleaseDelegation, *, replayed: bool = False) -> dict:
        return {
            "delegation_id": d.delegation_id,
            "delegate_user_id": d.delegate_user_id,
            "role": d.role,
            "created_by": d.created_by,
            "created_at": d.created_at,
            "replayed": replayed,
        }
