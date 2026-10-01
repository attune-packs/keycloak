from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs
import sys
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import keycloak_client as client  # noqa: E402


USER = "11111111-1111-4111-8111-111111111111"
CLIENT = "33333333-3333-4333-8333-333333333333"


class Response:
    def __init__(self, value=None, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.content = b"" if value is None else json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.content[:limit]


def credential(**changes):
    value = {
        "base_url": "https://keycloak.example.invalid/kc",
        "auth_realm": "control-plane",
        "allowed_realms": ["tenant-a", "team west"],
        "auth_method": "client_credentials",
        "client_id": "attune-admin",
        "client_secret": "TOP-SECRET",
        "verify_tls": True,
    }
    value.update(changes)
    return value


def keycloak(**changes):
    return client.KeycloakClient(credential(**changes), 15)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        self.assertEqual(
            {
                "realm_list", "realm_get",
                "user_search", "user_get", "user_create", "user_update", "user_set_enabled",
                "user_reset_password", "user_delete",
                "group_list", "group_get", "group_create", "group_update", "group_delete",
                "group_members", "group_member_add", "group_member_remove",
                "client_list", "client_get", "client_create", "client_update", "client_delete",
                "role_list", "role_get", "role_create", "role_update", "role_delete",
                "role_mapping_list", "role_mapping_add", "role_mapping_remove",
                "identity_provider_list", "identity_provider_get", "identity_provider_create",
                "identity_provider_update", "identity_provider_delete",
                "authentication_flow_list", "authentication_flow_get", "authentication_flow_executions",
            },
            set(self.actions),
        )

    def test_actions_use_flat_stdin_json_and_structured_output(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                for field, value in {
                    "ref": f"keycloak.{name}",
                    "runner_type": "python",
                    "runtime_version": '\">=3.10\"',
                    "entry_point": "keycloak_action.py",
                    "parameter_delivery": "stdin",
                    "parameter_format": "json",
                    "output_format": "json",
                }.items():
                    self.assertRegex(text, rf"(?m)^{field}: {value}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: pack\.keycloak\.credentials")
                for field in ("operation", "realm", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (?:password|client_secret|access_token):")

    def test_destructive_and_privilege_bearing_actions_require_confirmation(self):
        names = {
            "user_delete", "group_delete", "group_member_add", "group_member_remove",
            "client_delete", "role_delete", "role_mapping_add", "role_mapping_remove",
            "identity_provider_delete",
        }
        for name in names:
            with self.subTest(action=name):
                self.assertRegex(self.actions[name], r"(?m)^  confirm: \{type: string, required: true")

    def test_source_license_and_api_metadata(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn('source_revision: "f978f295fbdcf72d3bde62d73d3ea023ed45378f"', pack)
        self.assertIn('api_baseline: "Keycloak 26.7.1"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("f978f295fbdcf72d3bde62d73d3ea023ed45378f", (ROOT / "NOTICE").read_text(encoding="utf-8"))

    def test_client_has_no_legacy_auth_prefix_or_python_keycloak(self):
        source = (ROOT / "lib" / "keycloak_client.py").read_text(encoding="utf-8")
        self.assertNotIn('"/auth/', source)
        self.assertNotIn("python-keycloak", (ROOT / "requirements.txt").read_text(encoding="utf-8"))


class ClientTests(unittest.TestCase):
    def test_key_lookup_uses_current_sdk_signature(self):
        calls = {}
        get_key = types.ModuleType("attune.api_client.api.secrets.get_key")

        def sync_detailed(ref, *, client):
            calls.update(ref=ref, client=client)
            data = types.SimpleNamespace(value={"client_secret": "REDACTED"})
            return types.SimpleNamespace(status_code=200, parsed=types.SimpleNamespace(data=data))

        get_key.sync_detailed = sync_detailed
        secrets = types.ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        attune = types.ModuleType("attune")
        attune.context = types.SimpleNamespace(client="execution-client")
        modules = {
            "attune": attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            value = client._fetch_key("pack.keycloak.credentials")
        self.assertEqual(value["client_secret"], "REDACTED")
        self.assertEqual(calls, {"ref": "pack.keycloak.credentials", "client": "execution-client"})

    def test_credentials_require_https_explicit_realms_and_one_auth_method(self):
        bad = [
            credential(base_url="http://keycloak.invalid"),
            credential(base_url="https://user:secret@keycloak.invalid"),
            credential(base_url="https://keycloak.invalid/base/%2e%2e/admin"),
            credential(base_url="https://keycloak.invalid/base//admin"),
            credential(allowed_realms=[]),
            credential(allowed_realms=["*", "tenant-a"]),
            credential(allowed_realms=["tenant-a", "tenant-a"]),
            credential(verify_tls=False),
            credential(client_secret=None),
            credential(username="admin", password="secret"),
            credential(auth_method="password", username=None, password=None),
        ]
        for settings in bad:
            with self.subTest(settings=settings), self.assertRaises(client.KeycloakPackError):
                client.KeycloakClient(settings, 15)

    def test_client_credentials_uses_current_token_and_admin_paths(self):
        kc = keycloak()
        with mock.patch.object(kc, "_open", side_effect=[
            Response({"access_token": "ACCESS-SECRET", "expires_in": 300}),
            Response({"realm": "team west"}),
        ]) as opened:
            data, meta = kc.request("GET", client._admin("team west"))
        token_request, admin_request = [call.args[0] for call in opened.call_args_list]
        self.assertEqual(
            "https://keycloak.example.invalid/kc/realms/control-plane/protocol/openid-connect/token",
            token_request.full_url,
        )
        form = parse_qs(token_request.data.decode("ascii"))
        self.assertEqual(["client_credentials"], form["grant_type"])
        self.assertEqual(["TOP-SECRET"], form["client_secret"])
        self.assertEqual("https://keycloak.example.invalid/kc/admin/realms/team%20west", admin_request.full_url)
        self.assertEqual("Bearer ACCESS-SECRET", admin_request.get_header("Authorization"))
        self.assertEqual({"realm": "team west"}, data)
        self.assertEqual(200, meta["http_status"])

    def test_password_grant_refreshes_in_process_without_reusing_password(self):
        kc = keycloak(
            auth_method="password", client_secret=None, username="admin", password="PASSWORD-SECRET"
        )
        with mock.patch.object(kc, "_open", side_effect=[
            Response({"access_token": "one", "refresh_token": "REFRESH-SECRET", "expires_in": 300}),
            Response({"access_token": "two", "refresh_token": "next", "expires_in": 300}),
        ]) as opened:
            self.assertEqual("one", kc._token())
            kc._token_expires_at = 0
            self.assertEqual("two", kc._token())
        first = parse_qs(opened.call_args_list[0].args[0].data.decode("ascii"))
        second = parse_qs(opened.call_args_list[1].args[0].data.decode("ascii"))
        self.assertEqual(["password"], first["grant_type"])
        self.assertEqual(["PASSWORD-SECRET"], first["password"])
        self.assertEqual(["refresh_token"], second["grant_type"])
        self.assertEqual(["REFRESH-SECRET"], second["refresh_token"])
        self.assertNotIn("password", second)

    def test_custom_ca_is_loaded_without_disabling_verification(self):
        context = object()
        with mock.patch("ssl.create_default_context", return_value=context) as create, mock.patch(
            "lib.keycloak_client.HTTPSHandler"
        ) as handler:
            keycloak(ca_cert="CA PEM")
        create.assert_called_once_with(cadata="CA PEM")
        handler.assert_called_once_with(context=context)

    def test_http_errors_and_transport_errors_never_include_bodies_or_secrets(self):
        kc = keycloak()
        kc._access_token = "ACCESS-SECRET"
        kc._token_expires_at = 10**12
        error = HTTPError("https://keycloak.invalid", 403, "TOP-SECRET", {}, io.BytesIO(b"PASSWORD-SECRET"))
        with mock.patch.object(kc, "_open", side_effect=error):
            with self.assertRaises(client.KeycloakPackError) as caught:
                kc.request("GET", "/admin/realms/tenant-a")
        error.close()
        self.assertEqual("Keycloak authorization failed (HTTP 403)", str(caught.exception))

    def test_mutations_are_not_retried_after_unauthorized_response(self):
        kc = keycloak()
        unauthorized = HTTPError("https://keycloak.invalid", 401, "unauthorized", {}, None)
        with mock.patch.object(kc, "_open", side_effect=[
            Response({"access_token": "token", "expires_in": 300}), unauthorized,
        ]) as opened:
            with self.assertRaisesRegex(client.KeycloakPackError, "authentication failed"):
                kc.request("DELETE", "/admin/realms/tenant-a/users/id", expected={204})
        unauthorized.close()
        self.assertEqual(2, opened.call_count)

    def test_target_realm_allowlist_prevents_cross_realm_requests(self):
        kc = keycloak()
        with mock.patch.object(kc, "request") as request:
            with self.assertRaisesRegex(client.KeycloakPackError, "not allowed"):
                client._execute(kc, "realm_get", {"realm": "tenant-b"})
        request.assert_not_called()

    def test_realm_list_is_filtered_to_credential_allowlist(self):
        kc = keycloak()
        with mock.patch.object(kc, "request", return_value=([
            {"realm": "tenant-a"}, {"realm": "tenant-b"}, {"realm": "team west"}
        ], {"http_status": 200})):
            data, meta, realm = client._execute(kc, "realm_list", {})
        self.assertEqual([{"realm": "tenant-a"}, {"realm": "team west"}], data)
        self.assertEqual(2, meta["count"])
        self.assertIsNone(realm)

    def test_pagination_is_bounded_and_advances_first(self):
        kc = keycloak()
        pages = [([{"id": 1}, {"id": 2}], {"http_status": 200}), ([{"id": 3}], {"http_status": 200})]
        with mock.patch.object(kc, "request", side_effect=pages) as request:
            data, meta = client._paginate(kc, "/users", {
                "first": 5, "max_results": 2, "all_pages": True, "max_total": 5
            })
        self.assertEqual([{"id": 1}, {"id": 2}, {"id": 3}], data)
        self.assertEqual([5, 7], [call.kwargs["query"]["first"] for call in request.call_args_list])
        self.assertEqual(2, meta["pages"])
        self.assertFalse(meta["truncated"])
        with self.assertRaises(client.KeycloakPackError):
            client._paginate(kc, "/users", {"max_total": 10001})

    def test_ids_and_display_names_are_distinct_and_encoded(self):
        kc = keycloak()
        kc.assert_realm("tenant-a")
        with self.assertRaisesRegex(client.KeycloakPackError, "UUID-formatted"):
            client._execute(kc, "client_get", {"realm": "tenant-a", "client_uuid": "display-client"})
        with mock.patch.object(kc, "request", return_value=({"name": "billing/admin"}, {"http_status": 200})) as request:
            client._execute(kc, "role_get", {
                "realm": "tenant-a", "scope": "client", "client_uuid": CLIENT,
                "role_name": "billing/admin",
            })
        self.assertEqual(
            f"/admin/realms/tenant-a/clients/{CLIENT}/roles/billing%2Fadmin",
            request.call_args.args[1],
        )

    def test_representations_reject_privilege_expanding_fields(self):
        for name, allowed, body in [
            ("user", client.USER_FIELDS, {"username": "a", "credentials": []}),
            ("client", client.CLIENT_FIELDS, {"clientId": "a", "serviceAccountsEnabled": True}),
            ("role", client.ROLE_FIELDS, {"name": "a", "composite": True}),
        ]:
            with self.subTest(name=name), self.assertRaisesRegex(client.KeycloakPackError, "unsupported fields"):
                client._representation({name: body}, name, allowed)

    def test_role_assignment_requires_exact_confirmation_before_mutation(self):
        kc = keycloak()
        role = {"id": "role-id", "name": "realm-admin"}
        with mock.patch.object(kc, "request", return_value=(role, {"http_status": 200})) as request:
            params = {
                "realm": "tenant-a", "principal_type": "user", "principal_id": USER,
                "scope": "realm", "role_names": ["realm-admin"], "confirm": "wrong",
            }
            with self.assertRaisesRegex(client.KeycloakPackError, "confirm exactly"):
                client._execute(kc, "role_mapping_add", params)
        self.assertEqual(1, request.call_count)
        self.assertEqual("GET", request.call_args.args[0])

    def test_delete_confirmation_occurs_before_delete_request(self):
        kc = keycloak()
        with mock.patch.object(kc, "request") as request:
            with self.assertRaisesRegex(client.KeycloakPackError, "confirm exactly"):
                client._execute(kc, "user_delete", {
                    "realm": "tenant-a", "user_id": USER, "confirm": "delete:other:user:" + USER
                })
        request.assert_not_called()

    def test_identity_provider_secrets_use_key_and_outputs_are_redacted(self):
        body = {"alias": "oidc", "providerId": "oidc", "config": {"clientSecret": "INLINE"}}
        with self.assertRaisesRegex(client.KeycloakPackError, "secret_config_key"):
            client._merge_secret_config(body, {})
        safe = {"alias": "oidc", "providerId": "oidc", "config": {"clientId": "example"}}
        with mock.patch.object(client, "_fetch_key", return_value={"clientSecret": "TOP-SECRET"}):
            merged = client._merge_secret_config(safe, {"secret_config_key": "pack.keycloak.idp_oidc"})
        self.assertEqual("TOP-SECRET", merged["config"]["clientSecret"])
        redacted = client._redact({"config": merged["config"], "access_token": "TOKEN"})
        self.assertEqual("[REDACTED]", redacted["config"]["clientSecret"])
        self.assertEqual("[REDACTED]", redacted["access_token"])

    def test_password_reset_reads_password_from_key_only(self):
        kc = keycloak()
        with mock.patch.object(client, "_fetch_key", return_value={"password": "NEW-SECRET"}), mock.patch.object(
            kc, "request", return_value=({"success": True}, {"http_status": 204})
        ) as request:
            client._execute(kc, "user_reset_password", {
                "realm": "tenant-a", "user_id": USER, "password_key": "pack.keycloak.user_password",
                "temporary": False,
            })
        self.assertEqual("NEW-SECRET", request.call_args.kwargs["body"]["value"])
        self.assertNotIn("NEW-SECRET", str(request.call_args.args))


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("keycloak_action_test", ROOT / "actions" / "keycloak_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        for raw, error in (("[]", None), ('{"value":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))):
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(self.module, "execute_action", side_effect=error) if error else mock.patch.object(self.module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "keycloak.user_get"}), mock.patch(
                "sys.stdin", io.StringIO(raw)
            ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
