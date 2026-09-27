"""发布法定人数 HTTP 端到端：缺位角色在响应中返回、越权替代 403。"""
import base64
import json
import unittest

from service_09252_006.api.http_api import HttpApiServer
from tests.support import Harness


class ApiClient:
    def __init__(self, base_url, token=None, bootstrap=None):
        self.base_url = base_url
        self.token = token
        self.bootstrap = bootstrap

    def request(self, method, path, body=None, idempotency_key=None):
        import urllib.error
        import urllib.request

        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.bootstrap:
            headers["X-Bootstrap-Token"] = self.bootstrap
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        req = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class ReleaseHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _user(self, uid, roles, institution_id=None, token=None):
        status, _ = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": uid, "roles": roles, "institution_id": institution_id},
        )
        self.assertEqual(status, 201)
        if token:
            status, _ = self.boot.request(
                "POST", "/v1/admin/tokens",
                {"user_id": uid, "token": token},
            )
            self.assertEqual(status, 201)
        return ApiClient(self.base, token=token)

    def _approved_package(self, admin, authority, reviewer):
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "大纲"},
        )
        self.assertEqual(status, 201)
        content = base64.b64encode(b"syllabus-v1").decode("ascii")
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": content},
        )
        self.assertEqual(status, 201)
        status, pkg = admin.request("POST", "/v1/packages", {"title": "发布包"})
        pid = pkg["package_id"]
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        status, _ = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        status, req = authority.request(
            "POST", f"/v1/packages/{pid}/assignments",
            {"reviewer_id": "rev-1"},
        )
        self.assertEqual(status, 201)
        rid = req["request_id"]
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/respond", {"accept": True}
        )
        self.assertEqual(status, 200)
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/verdict", {"verdict": "approve"}
        )
        self.assertEqual(status, 200)
        status, decision = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "approved"},
        )
        self.assertEqual(status, 200, decision)
        return pid

    def test_release_response_lists_missing_roles(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        authority = self._user(
            "auth", ["quality_authority"], None, "t-auth"
        )
        reviewer = self._user(
            "rev-1", ["reviewer"], "inst-ext", "t-rev"
        )
        pid = self._approved_package(admin, authority, reviewer)

        # 无任何确认：发布冲突响应带缺位角色
        status, body = authority.request("POST", f"/v1/packages/{pid}/release", {})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "quorum_insufficient")
        self.assertEqual(
            body["error"]["details"]["missing_roles"],
            ["institution_admin", "quality_authority", "reviewer"],
        )

        # 仅评审职责确认 -> 仍缺两个角色
        status, _ = reviewer.request(
            "POST", f"/v1/packages/{pid}/release/confirmations",
            {"role": "reviewer"},
        )
        self.assertEqual(status, 201)
        status, body = authority.request("POST", f"/v1/packages/{pid}/release", {})
        self.assertEqual(status, 409)
        self.assertEqual(
            body["error"]["details"]["missing_roles"],
            ["institution_admin", "quality_authority"],
        )

        # 凑齐角色后发布成功，响应不再缺位
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/release/confirmations",
            {"role": "institution_admin"},
        )
        self.assertEqual(status, 201)
        status, _ = authority.request(
            "POST", f"/v1/packages/{pid}/release/confirmations",
            {"role": "quality_authority"},
        )
        self.assertEqual(status, 201)
        status, released = authority.request(
            "POST", f"/v1/packages/{pid}/release", {}
        )
        self.assertEqual(status, 200, released)
        self.assertTrue(released["released"])
        self.assertEqual(released["missing_roles"], [])

    def test_substitute_beyond_scope_gets_403_over_http(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        authority = self._user(
            "auth", ["quality_authority"], None, "t-auth"
        )
        reviewer = self._user(
            "rev-1", ["reviewer"], "inst-ext", "t-rev"
        )
        sub = self._user("sub-1", ["auditor"], None, "t-sub")
        pid = self._approved_package(admin, authority, reviewer)

        # 仅授权评审职责
        status, _ = authority.request(
            "POST", "/v1/release/delegations",
            {"substitute_id": "sub-1", "roles": ["reviewer"]},
        )
        self.assertEqual(status, 201)

        # 越权确认机构管理员职责 -> 403
        status, body = sub.request(
            "POST", f"/v1/packages/{pid}/release/confirmations",
            {"role": "institution_admin"},
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "permission_denied")

        # 授权范围内的评审职责可确认
        status, ok = sub.request(
            "POST", f"/v1/packages/{pid}/release/confirmations",
            {"role": "reviewer"},
        )
        self.assertEqual(status, 201, ok)
        self.assertTrue(ok["delegated"])


if __name__ == "__main__":
    unittest.main()
