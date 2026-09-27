"""发布法定人数：按职责集合统计、替代确认人授权范围与缺位角色返回。"""
import unittest

from service_09252_006.domain.enums import (
    ConfirmationVia,
    Decision,
    ReleaseStatus,
    Role,
)
from service_09252_006.domain.errors import (
    ConflictError,
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import complete_review, seal_new_package
from tests.support import Harness

REQUIRED = [
    Role.QUALITY_AUTHORITY.value,
    Role.INSTITUTION_ADMIN.value,
    Role.AUDITOR.value,
]


class ReleaseQuorumTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.auditor = self.h.user("aud-1", Role.AUDITOR, institution_id=None)
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        # 已签发通过的评审包
        sealed = seal_new_package(self.h, self.admin)
        self.pid = sealed.package_id
        complete_review(self.h, self.authority, self.reviewer, self.pid)
        self.h.ctx.reviews.issue_decision(
            self.authority, package_id=self.pid, decision=Decision.APPROVED.value
        )
        # 发布委员会职责集合 + 待确认的发布
        self.h.ctx.releases.define_committee(self.authority, roles=REQUIRED)
        self.release = self.h.ctx.releases.create_release(
            self.authority, package_id=self.pid
        )
        self.rid = self.release["release_id"]

    def tearDown(self) -> None:
        self.h.close()

    def _confirm_all(self) -> None:
        self.h.ctx.releases.confirm_release(
            self.authority, release_id=self.rid, role=Role.QUALITY_AUTHORITY.value
        )
        self.h.ctx.releases.confirm_release(
            self.admin, release_id=self.rid, role=Role.INSTITUTION_ADMIN.value
        )
        self.h.ctx.releases.confirm_release(
            self.auditor, release_id=self.rid, role=Role.AUDITOR.value
        )

    # ------------------------------------------------ 法定人数按角色统计
    def test_quorum_counts_roles_not_headcount(self) -> None:
        # 同一职责被多人确认，法定人数不因此推进
        first = self.h.ctx.releases.confirm_release(
            self.authority, release_id=self.rid, role=Role.QUALITY_AUTHORITY.value
        )
        self.assertEqual(first["via"], ConfirmationVia.DIRECT.value)
        self.assertFalse(first["replayed"])
        second_auth = self.h.user(
            "auth-2", Role.QUALITY_AUTHORITY, institution_id=None
        )
        replay = self.h.ctx.releases.confirm_release(
            second_auth, release_id=self.rid, role=Role.QUALITY_AUTHORITY.value
        )
        self.assertTrue(replay["replayed"])

        view = self.h.ctx.releases.get_release(self.authority, self.rid)
        self.assertEqual(view["confirmed_roles"], [Role.QUALITY_AUTHORITY.value])
        self.assertEqual(
            view["missing_roles"],
            [Role.AUDITOR.value, Role.INSTITUTION_ADMIN.value],
        )
        self.assertFalse(view["quorum_met"])

    def test_publish_response_lists_missing_roles(self) -> None:
        self.h.ctx.releases.confirm_release(
            self.authority, release_id=self.rid, role=Role.QUALITY_AUTHORITY.value
        )
        with self.assertRaises(ConflictError) as ctx:
            self.h.ctx.releases.publish_release(self.authority, release_id=self.rid)
        details = ctx.exception.details
        self.assertEqual(
            details["missing_roles"],
            [Role.AUDITOR.value, Role.INSTITUTION_ADMIN.value],
        )
        self.assertEqual(details["required_roles"], sorted(REQUIRED))
        self.assertEqual(details["confirmed_roles"], [Role.QUALITY_AUTHORITY.value])

        self._confirm_all()
        published = self.h.ctx.releases.publish_release(
            self.authority, release_id=self.rid
        )
        self.assertEqual(published["status"], ReleaseStatus.RELEASED.value)
        self.assertEqual(published["missing_roles"], [])
        self.assertTrue(published["quorum_met"])
        self.assertIsNotNone(published["released_at"])

    def test_missing_roles_follow_committee_redefinition(self) -> None:
        # 角色确认按 SQLite 中的职责集合统计：集合调整后缺位角色即时变化
        self._confirm_all()
        self.h.ctx.releases.define_committee(
            self.authority,
            roles=[Role.QUALITY_AUTHORITY.value, Role.INSTITUTION_ADMIN.value],
        )
        view = self.h.ctx.releases.get_release(self.authority, self.rid)
        self.assertEqual(view["missing_roles"], [])
        self.assertTrue(view["quorum_met"])

    # ---------------------------------------------------- 替代确认人
    def test_substitute_confirm_within_scope(self) -> None:
        clerk = self.h.user("clerk", (), institution_id=None)  # 无任何角色
        self.h.ctx.releases.delegate_substitute(
            self.authority, delegate_user_id="clerk", role=Role.AUDITOR.value
        )
        confirmation = self.h.ctx.releases.confirm_release(
            clerk, release_id=self.rid, role=Role.AUDITOR.value
        )
        self.assertEqual(confirmation["via"], ConfirmationVia.SUBSTITUTE.value)
        view = self.h.ctx.releases.get_release(self.authority, self.rid)
        self.assertIn(Role.AUDITOR.value, view["confirmed_roles"])

    def test_substitute_overreach_fails(self) -> None:
        clerk = self.h.user("clerk", (), institution_id=None)
        # 仅被授权替代 auditor，越权确认其他职责必须失败
        self.h.ctx.releases.delegate_substitute(
            self.authority, delegate_user_id="clerk", role=Role.AUDITOR.value
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.releases.confirm_release(
                clerk, release_id=self.rid, role=Role.INSTITUTION_ADMIN.value
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.releases.confirm_release(
                clerk, release_id=self.rid, role=Role.QUALITY_AUTHORITY.value
            )
        # 授权范围外的确认不留下任何痕迹
        view = self.h.ctx.releases.get_release(self.authority, self.rid)
        self.assertEqual(view["confirmed_roles"], [])

    def test_unauthorized_user_cannot_confirm(self) -> None:
        nobody = self.h.user("nobody", (), institution_id=None)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.releases.confirm_release(
                nobody, release_id=self.rid, role=Role.AUDITOR.value
            )

    def test_confirm_role_outside_required_set_fails(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.releases.confirm_release(
                self.reviewer, release_id=self.rid, role=Role.REVIEWER.value
            )

    # ---------------------------------------------------------- 创建发布
    def test_create_release_requires_decided_approved_package(self) -> None:
        # 未签发的包不能创建发布
        pending = seal_new_package(self.h, self.admin, title="未签发包")
        with self.assertRaises(ConflictError):
            self.h.ctx.releases.create_release(
                self.authority, package_id=pending.package_id
            )
        # 签发未通过的包不能发布
        rejected = seal_new_package(self.h, self.admin, title="被拒包")
        complete_review(self.h, self.authority, self.reviewer, rejected.package_id)
        self.h.ctx.reviews.issue_decision(
            self.authority,
            package_id=rejected.package_id,
            decision=Decision.REJECTED.value,
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.releases.create_release(
                self.authority, package_id=rejected.package_id
            )

    def test_create_release_replays_for_same_package(self) -> None:
        again = self.h.ctx.releases.create_release(self.admin, package_id=self.pid)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["release_id"], self.rid)

    def test_create_release_permission(self) -> None:
        outsider = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        other = seal_new_package(self.h, self.admin, title="另一个包")
        complete_review(self.h, self.authority, self.reviewer, other.package_id)
        self.h.ctx.reviews.issue_decision(
            self.authority,
            package_id=other.package_id,
            decision=Decision.APPROVED.value,
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.releases.create_release(outsider, package_id=other.package_id)

    # ---------------------------------------------------------- 发布约束
    def test_publish_replays_after_release(self) -> None:
        self._confirm_all()
        first = self.h.ctx.releases.publish_release(
            self.authority, release_id=self.rid
        )
        second = self.h.ctx.releases.publish_release(
            self.authority, release_id=self.rid
        )
        self.assertTrue(second["replayed"])
        self.assertEqual(second["released_at"], first["released_at"])

    def test_confirm_after_release_fails(self) -> None:
        self._confirm_all()
        self.h.ctx.releases.publish_release(self.authority, release_id=self.rid)
        with self.assertRaises(ConflictError):
            self.h.ctx.releases.confirm_release(
                self.auditor, release_id=self.rid, role=Role.AUDITOR.value
            )

    def test_publish_requires_non_empty_committee(self) -> None:
        sealed = seal_new_package(self.h, self.admin, title="无委员会包")
        complete_review(self.h, self.authority, self.reviewer, sealed.package_id)
        self.h.ctx.reviews.issue_decision(
            self.authority,
            package_id=sealed.package_id,
            decision=Decision.APPROVED.value,
        )
        # 直接清空 SQLite 中的职责集合，模拟未定义委员会的环境
        with self.h.repo.transaction():
            self.h.repo.replace_committee_roles([])
        release = self.h.ctx.releases.create_release(
            self.authority, package_id=sealed.package_id
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.releases.publish_release(
                self.authority, release_id=release["release_id"]
            )

    # ---------------------------------------------------------- 委员会定义
    def test_define_committee_validates_roles(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.releases.define_committee(self.authority, roles=[])
        with self.assertRaises(ValidationError):
            self.h.ctx.releases.define_committee(
                self.authority, roles=["not-a-role"]
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.releases.define_committee(self.admin, roles=REQUIRED)

    def test_delegate_substitute_validates(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.releases.delegate_substitute(
                self.authority, delegate_user_id="clerk", role="not-a-role"
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.releases.delegate_substitute(
                self.admin, delegate_user_id="clerk", role=Role.AUDITOR.value
            )
        # 重复授权幂等回放
        self.h.user("clerk", (), institution_id=None)
        first = self.h.ctx.releases.delegate_substitute(
            self.authority, delegate_user_id="clerk", role=Role.AUDITOR.value
        )
        second = self.h.ctx.releases.delegate_substitute(
            self.authority, delegate_user_id="clerk", role=Role.AUDITOR.value
        )
        self.assertTrue(second["replayed"])
        self.assertEqual(second["delegation_id"], first["delegation_id"])


if __name__ == "__main__":
    unittest.main()
