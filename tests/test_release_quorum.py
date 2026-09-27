"""发布法定人数：按职责角色统计、缺位角色返回、替代授权越权失败。"""
import unittest

from service_09252_006.domain.enums import Decision, Role
from service_09252_006.domain.errors import (
    ConflictError,
    PermissionDeniedError,
    QuorumInsufficientError,
    ValidationError,
)
from tests.flow import complete_review, seal_new_package
from tests.support import Harness


class ReleaseQuorumTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.reviewer2 = self.h.user(
            "rev-2", Role.REVIEWER, institution_id="inst-ext2"
        )
        sealed = seal_new_package(self.h, self.admin)
        self.pid = sealed.package_id
        complete_review(self.h, self.authority, self.reviewer, self.pid)
        self.h.ctx.reviews.issue_decision(
            self.authority,
            package_id=self.pid,
            decision=Decision.APPROVED.value,
        )

    def tearDown(self) -> None:
        self.h.close()

    # ----------------------------------------------------------- 基本规则
    def test_release_roles_seeded_from_sqlite_duty_set(self) -> None:
        roles = self.h.repo.list_release_roles()
        self.assertEqual(
            sorted(roles),
            ["institution_admin", "quality_authority", "reviewer"],
        )

    def test_release_before_any_confirmation_lists_all_missing_roles(self) -> None:
        with self.assertRaises(QuorumInsufficientError) as ctx:
            self.h.ctx.release.release_package(
                self.authority, package_id=self.pid
            )
        self.assertEqual(
            ctx.exception.details["missing_roles"],
            ["institution_admin", "quality_authority", "reviewer"],
        )

    def test_headcount_does_not_satisfy_role_quorum(self) -> None:
        # 两名评审人都确认，评审职责仍只计一票；其余两个角色依旧缺位
        self.h.ctx.release.confirm_release(
            self.reviewer, package_id=self.pid, role=Role.REVIEWER.value
        )
        second = self.h.ctx.release.confirm_release(
            self.reviewer2, package_id=self.pid, role=Role.REVIEWER.value
        )
        self.assertTrue(second["replayed"])  # 同包同角色去重
        with self.assertRaises(QuorumInsufficientError) as ctx:
            self.h.ctx.release.release_package(
                self.authority, package_id=self.pid
            )
        self.assertEqual(
            ctx.exception.details["missing_roles"],
            ["institution_admin", "quality_authority"],
        )

    def test_full_role_quorum_releases_and_replays(self) -> None:
        missing = self._confirm_all()
        self.assertEqual(missing, [])

        result = self.h.ctx.release.release_package(
            self.authority, package_id=self.pid
        )
        self.assertTrue(result["released"])
        self.assertIsNotNone(result["released_at"])
        self.assertEqual(result["missing_roles"], [])

        # 重复发布回放既有结果
        again = self.h.ctx.release.release_package(
            self.admin, package_id=self.pid
        )
        self.assertTrue(again["replayed"])
        self.assertEqual(again["released_at"], result["released_at"])

        # 已发布后不能再追加确认
        with self.assertRaises(ConflictError):
            self.h.ctx.release.confirm_release(
                self.reviewer2, package_id=self.pid, role=Role.REVIEWER.value
            )

    def test_confirmation_response_progressively_lists_absent_roles(self) -> None:
        r = self.h.ctx.release.confirm_release(
            self.admin, package_id=self.pid, role=Role.INSTITUTION_ADMIN.value
        )
        self.assertEqual(r["confirmed_roles"], ["institution_admin"])
        self.assertEqual(
            r["missing_roles"], ["quality_authority", "reviewer"]
        )

    def test_only_approved_decision_can_be_released(self) -> None:
        sealed = seal_new_package(
            self.h, self.admin, title="需整改包"
        )
        complete_review(
            self.h, self.authority, self.reviewer, sealed.package_id,
            verdict="object",
            objection={"category": "依据", "detail": "缺评分标准"},
        )
        self.h.ctx.reviews.issue_decision(
            self.authority,
            package_id=sealed.package_id,
            decision=Decision.NEEDS_REVISION.value,
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.release.release_package(
                self.authority, package_id=sealed.package_id
            )

    def test_outsider_cannot_confirm(self) -> None:
        submitter = self.h.user(
            "sub-a", Role.INSTITUTION_SUBMITTER, institution_id="inst-a"
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.release.confirm_release(
                submitter, package_id=self.pid,
                role=Role.INSTITUTION_SUBMITTER.value,
            )

    # ------------------------------------------------------------- 替代授权
    def test_delegate_can_confirm_only_granted_role(self) -> None:
        # 替代人自身只有审计角色，经质量权威授权代行“机构管理员”职责
        substitute = self.h.user(
            "substitute", Role.AUDITOR, institution_id=None
        )
        self.h.ctx.release.delegate_release(
            self.authority,
            substitute_id=substitute.user_id,
            roles=[Role.INSTITUTION_ADMIN.value],
        )
        result = self.h.ctx.release.confirm_release(
            substitute, package_id=self.pid
        )  # 唯一可代表职责，自动识别
        self.assertEqual(result["role"], Role.INSTITUTION_ADMIN.value)
        self.assertTrue(result["delegated"])

        # 未获授权的质量权威职责仍不可代行
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.release.confirm_release(
                substitute, package_id=self.pid,
                role=Role.QUALITY_AUTHORITY.value,
            )

    def test_substitute_beyond_delegation_scope_fails(self) -> None:
        substitute = self.h.user(
            "substitute", Role.AUDITOR, institution_id=None
        )
        # 只授权评审职责
        self.h.ctx.release.delegate_release(
            self.authority,
            substitute_id=substitute.user_id,
            roles=[Role.REVIEWER.value],
        )
        # 越权确认机构管理员职责：必须失败（403），且不产生确认记录
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.release.confirm_release(
                substitute, package_id=self.pid,
                role=Role.INSTITUTION_ADMIN.value,
            )
        confirmed = {
            c.role for c in self.h.repo.list_release_confirmations(self.pid)
        }
        self.assertNotIn(Role.INSTITUTION_ADMIN.value, confirmed)

        # 越权尝试后法定人数仍不足，缺位角色如实返回
        with self.assertRaises(QuorumInsufficientError) as ctx:
            self.h.ctx.release.release_package(
                self.authority, package_id=self.pid
            )
        self.assertIn(Role.INSTITUTION_ADMIN.value, ctx.exception.details["missing_roles"])

    def test_package_scoped_delegation_does_not_apply_to_other_package(self) -> None:
        substitute = self.h.user(
            "substitute2", Role.AUDITOR, institution_id=None
        )
        # 授权仅限另一个包
        other = seal_new_package(self.h, self.admin, title="另一个包")
        complete_review(
            self.h, self.authority, self.reviewer2, other.package_id
        )
        self.h.ctx.reviews.issue_decision(
            self.authority, package_id=other.package_id,
            decision=Decision.APPROVED.value,
        )
        self.h.ctx.release.delegate_release(
            self.authority,
            substitute_id=substitute.user_id,
            roles=[Role.INSTITUTION_ADMIN.value],
            package_id=other.package_id,
        )
        # 对本包确认 -> 授权范围不匹配，拒绝
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.release.confirm_release(
                substitute, package_id=self.pid,
                role=Role.INSTITUTION_ADMIN.value,
            )
        # 在被授权的包上可以确认
        ok = self.h.ctx.release.confirm_release(
            substitute, package_id=other.package_id,
            role=Role.INSTITUTION_ADMIN.value,
        )
        self.assertTrue(ok["delegated"])

    def test_delegation_unknown_substitute_or_role_rejected(self) -> None:
        with self.assertRaises(Exception):
            self.h.ctx.release.delegate_release(
                self.authority, substitute_id="nobody",
                roles=[Role.REVIEWER.value],
            )
        submitter = self.h.user(
            "sub-x", Role.INSTITUTION_SUBMITTER, institution_id="inst-a"
        )
        # 提交人不在发布职责集合内，不能就该角色授权
        with self.assertRaises(ValidationError):
            self.h.ctx.release.delegate_release(
                self.authority, substitute_id=submitter.user_id,
                roles=[Role.INSTITUTION_SUBMITTER.value],
            )

    def test_only_quality_authority_may_delegate(self) -> None:
        substitute = self.h.user(
            "substitute3", Role.AUDITOR, institution_id=None
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.release.delegate_release(
                self.admin, substitute_id=substitute.user_id,
                roles=[Role.REVIEWER.value],
            )

    # ------------------------------------------------------------- 职责集合
    def test_quality_authority_can_change_duty_set(self) -> None:
        self.h.ctx.release.configure_release_roles(
            self.authority,
            roles=[Role.QUALITY_AUTHORITY.value, Role.REVIEWER.value],
        )
        self.h.ctx.release.confirm_release(
            self.authority, package_id=self.pid,
            role=Role.QUALITY_AUTHORITY.value,
        )
        self.h.ctx.release.confirm_release(
            self.reviewer, package_id=self.pid, role=Role.REVIEWER.value
        )
        # 机构管理员不再是必需职责：两角色即可发布
        result = self.h.ctx.release.release_package(
            self.authority, package_id=self.pid
        )
        self.assertTrue(result["released"])

    # ---------------------------------------------------------------- 辅助
    def _confirm_all(self) -> list[str]:
        self.h.ctx.release.confirm_release(
            self.admin, package_id=self.pid, role=Role.INSTITUTION_ADMIN.value
        )
        self.h.ctx.release.confirm_release(
            self.authority, package_id=self.pid,
            role=Role.QUALITY_AUTHORITY.value,
        )
        r = self.h.ctx.release.confirm_release(
            self.reviewer, package_id=self.pid, role=Role.REVIEWER.value
        )
        return r["missing_roles"]


if __name__ == "__main__":
    unittest.main()
