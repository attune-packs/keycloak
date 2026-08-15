"""Direct, safely scoped client for the current Keycloak Admin REST API."""

from __future__ import annotations

import json
import re
import ssl
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


DEFAULT_CREDENTIAL_KEY = "keycloak.credentials"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SENSITIVE = re.compile(r"(?:password|secret|token|credential|private.?key|api.?key)", re.IGNORECASE)

USER_FIELDS = {
    "username", "email", "firstName", "lastName", "enabled", "emailVerified",
    "attributes", "requiredActions",
}
GROUP_FIELDS = {"name", "attributes"}
CLIENT_FIELDS = {
    "clientId", "name", "description", "enabled", "protocol", "publicClient",
    "bearerOnly", "standardFlowEnabled",
    "directAccessGrantsEnabled", "redirectUris", "webOrigins", "baseUrl", "rootUrl",
    "adminUrl", "alwaysDisplayInConsole", "consentRequired",
}
ROLE_FIELDS = {"name", "description"}
IDP_CREATE_FIELDS = {
    "alias", "displayName", "providerId", "enabled", "trustEmail", "storeToken",
    "linkOnly", "hideOnLogin", "firstBrokerLoginFlowAlias", "postBrokerLoginFlowAlias",
    "config",
}
IDP_UPDATE_FIELDS = IDP_CREATE_FIELDS - {"alias"}


class KeycloakPackError(Exception):
    """An action-safe error that never contains credentials or response bodies."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _fetch_key(key_ref: str) -> Any:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise KeycloakPackError("Key reference must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:
        raise KeycloakPackError(f"could not read Attune Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise KeycloakPackError("Attune Key was not found")
        raise KeycloakPackError(f"could not read Attune Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _credential(key_ref: str) -> dict[str, Any]:
    value = _fetch_key(key_ref)
    if not isinstance(value, dict):
        raise KeycloakPackError("Keycloak credential Key must contain a JSON object")
    return value


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise KeycloakPackError(f"{name} must be a non-empty string")
    if any(ord(character) < 32 for character in value):
        raise KeycloakPackError(f"{name} contains a control character")
    return value


def _segment(value: Any, name: str) -> str:
    return quote(_nonempty(value, name), safe="")


def _uuid(value: Any, name: str) -> str:
    value = _nonempty(value, name)
    if not _UUID.fullmatch(value):
        raise KeycloakPackError(f"{name} must be a UUID-formatted internal Keycloak ID")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise KeycloakPackError(f"{name} must be a boolean")
    return value


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise KeycloakPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _representation(
    params: dict[str, Any], name: str, allowed: set[str], required: set[str] | None = None
) -> dict[str, Any]:
    value = params.get(name)
    if not isinstance(value, dict) or not value:
        raise KeycloakPackError(f"{name} must be a non-empty object")
    unknown = set(value) - allowed
    if unknown:
        raise KeycloakPackError(f"{name} contains unsupported fields: {', '.join(sorted(unknown))}")
    missing = (required or set()) - set(value)
    if missing:
        raise KeycloakPackError(f"{name} is missing required fields: {', '.join(sorted(missing))}")
    return dict(value)


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise KeycloakPackError(f"{name} must be a non-empty array of non-empty strings")
    if len(set(value)) != len(value):
        raise KeycloakPackError(f"{name} must not contain duplicates")
    return value


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class KeycloakClient:
    """Small direct REST client with in-process OAuth token refresh."""

    def __init__(self, credential: dict[str, Any], timeout_seconds: int):
        base_url = credential.get("base_url")
        if not isinstance(base_url, str):
            raise KeycloakPackError("credential base_url must be a string")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise KeycloakPackError("credential base_url must be an HTTPS URL without credentials, query, or fragment")
        try:
            parsed.port
        except ValueError:
            raise KeycloakPackError("credential base_url has an invalid port") from None
        raw_parts = parsed.path.split("/")
        decoded_parts = [unquote(part) for part in raw_parts]
        if (
            any(part in {".", ".."} or "/" in part or "\\" in part for part in decoded_parts if part)
            or any(not part for part in raw_parts[1:-1])
        ):
            raise KeycloakPackError("credential base_url path contains an unsafe segment")

        self.auth_realm = _nonempty(credential.get("auth_realm"), "credential auth_realm")
        allowed_realms = credential.get("allowed_realms")
        if (
            not isinstance(allowed_realms, list) or not allowed_realms
            or any(not isinstance(item, str) or not item or any(ord(character) < 32 for character in item) for item in allowed_realms)
            or len(set(allowed_realms)) != len(allowed_realms)
            or ("*" in allowed_realms and allowed_realms != ["*"])
        ):
            raise KeycloakPackError("credential allowed_realms must be unique realm names or exactly ['*']")
        self.allowed_realms = set(allowed_realms)
        self.auth_method = credential.get("auth_method", "client_credentials")
        if self.auth_method not in {"client_credentials", "password"}:
            raise KeycloakPackError("credential auth_method must be 'client_credentials' or 'password'")
        self.client_id = _nonempty(credential.get("client_id"), "credential client_id")
        self.client_secret = credential.get("client_secret")
        if self.client_secret is not None:
            self.client_secret = _nonempty(self.client_secret, "credential client_secret")
        self.username = credential.get("username")
        self.password = credential.get("password")
        if self.auth_method == "client_credentials":
            if not self.client_secret:
                raise KeycloakPackError("client_credentials requires credential client_secret")
            if self.username is not None or self.password is not None:
                raise KeycloakPackError("client_credentials must not include username or password")
        else:
            self.username = _nonempty(self.username, "credential username")
            self.password = _nonempty(self.password, "credential password")

        verify_tls = credential.get("verify_tls", True)
        if verify_tls is not True:
            raise KeycloakPackError("credential verify_tls must be true; insecure OAuth transport is not supported")
        ca_cert = credential.get("ca_cert")
        if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip()):
            raise KeycloakPackError("credential ca_cert must be a non-empty PEM string")
        try:
            context = ssl.create_default_context(cadata=ca_cert) if ca_cert else ssl.create_default_context()
        except (ssl.SSLError, ValueError):
            raise KeycloakPackError("credential ca_cert is not a valid CA certificate") from None

        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expires_at = 0.0

    def assert_realm(self, realm: str) -> None:
        if "*" not in self.allowed_realms and realm not in self.allowed_realms:
            raise KeycloakPackError("target realm is not allowed by the Keycloak credential Key")

    def _open(self, request: Request):
        return self._opener.open(request, timeout=self.timeout_seconds)

    def _send(self, request: Request) -> tuple[int, dict[str, str], bytes]:
        try:
            with self._open(request) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise KeycloakPackError("Keycloak response exceeded the 16 MiB action limit")
                return response.status, dict(response.headers.items()), content
        except HTTPError as exc:
            if exc.code == 409:
                raise KeycloakPackError("Keycloak resource conflict (HTTP 409)") from None
            messages = {
                400: "Keycloak rejected the request (HTTP 400)",
                401: "Keycloak authentication failed (HTTP 401)",
                403: "Keycloak authorization failed (HTTP 403)",
                404: "Keycloak resource was not found (HTTP 404)",
            }
            raise KeycloakPackError(messages.get(exc.code, f"Keycloak returned HTTP {exc.code}")) from None
        except (URLError, TimeoutError, OSError) as exc:
            raise KeycloakPackError(f"Keycloak request failed ({type(exc).__name__})") from None

    def _token(self) -> str:
        if self._access_token and time.monotonic() < self._token_expires_at - 30:
            return self._access_token
        form: dict[str, str]
        if self._refresh_token:
            form = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": self._refresh_token,
            }
            if self.client_secret:
                form["client_secret"] = self.client_secret
        elif self.auth_method == "client_credentials":
            form = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret or "",
            }
        else:
            form = {
                "grant_type": "password",
                "client_id": self.client_id,
                "username": self.username or "",
                "password": self.password or "",
            }
            if self.client_secret:
                form["client_secret"] = self.client_secret
        token_url = f"{self.base_url}/realms/{_segment(self.auth_realm, 'credential auth_realm')}/protocol/openid-connect/token"
        request = Request(
            token_url,
            data=urlencode(form).encode("ascii"),
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        status, _, content = self._send(request)
        if status != 200:
            raise KeycloakPackError(f"Keycloak token endpoint returned HTTP {status}")
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise KeycloakPackError("Keycloak token endpoint returned invalid JSON") from None
        token = payload.get("access_token") if isinstance(payload, dict) else None
        expires = payload.get("expires_in") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token or isinstance(expires, bool) or not isinstance(expires, int) or expires <= 0:
            raise KeycloakPackError("Keycloak token response is missing valid access_token or expires_in")
        refresh = payload.get("refresh_token")
        self._access_token = token
        self._refresh_token = refresh if isinstance(refresh, str) and refresh else None
        self._token_expires_at = time.monotonic() + expires
        return token

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        expected: set[int] | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        url = self.base_url + path
        if query:
            url += "?" + urlencode(query)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self._token()}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        status, response_headers, content = self._send(Request(url, data=data, headers=headers, method=method))
        expected = expected or {200}
        if status not in expected:
            raise KeycloakPackError(f"Keycloak returned unexpected HTTP {status}")
        meta = {"http_status": status}
        location = response_headers.get("Location") or response_headers.get("location")
        if location:
            meta["location_id"] = location.rstrip("/").rsplit("/", 1)[-1]
        if not content:
            return {"success": True}, meta
        try:
            return _redact(json.loads(content)), meta
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise KeycloakPackError("Keycloak returned invalid JSON") from None


def _admin(realm: Any, *parts: Any) -> str:
    path = f"/admin/realms/{_segment(realm, 'realm')}"
    return path + "".join(f"/{_segment(part, 'path identifier')}" for part in parts)


def _paginate(
    client: KeycloakClient,
    path: str,
    params: dict[str, Any],
    query: dict[str, Any] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    first = _integer(params, "first", 0, 0, 2**31 - 1)
    page_size = _integer(params, "max_results", 100, 1, 1000)
    all_pages = _boolean(params, "all_pages")
    max_total = _integer(params, "max_total", 1000, 1, 10000)
    items: list[Any] = []
    pages = 0
    while True:
        page_query = dict(query or {})
        page_query.update({"first": first + len(items), "max": min(page_size, max_total - len(items))})
        page, meta = client.request("GET", path, query=page_query)
        if not isinstance(page, list):
            raise KeycloakPackError("Keycloak returned an unexpected paginated response")
        if len(page) > page_query["max"]:
            raise KeycloakPackError("Keycloak returned more results than the requested page size")
        items.extend(page)
        pages += 1
        if not all_pages or len(page) < page_query["max"] or len(items) >= max_total:
            break
    return items, {**meta, "first": first, "count": len(items), "pages": pages, "truncated": all_pages and len(items) >= max_total}


def _scope_paths(realm: str, params: dict[str, Any]) -> tuple[str, str | None]:
    scope = params.get("scope", "realm")
    if scope == "realm":
        if params.get("client_uuid") is not None:
            raise KeycloakPackError("client_uuid is only valid for client role scope")
        return _admin(realm, "roles"), None
    if scope == "client":
        client_uuid = _uuid(params.get("client_uuid"), "client_uuid")
        return _admin(realm, "clients", client_uuid, "roles"), client_uuid
    raise KeycloakPackError("scope must be 'realm' or 'client'")


def _mapping_path(realm: str, params: dict[str, Any]) -> tuple[str, str, str | None]:
    principal_type = params.get("principal_type")
    if principal_type not in {"user", "group"}:
        raise KeycloakPackError("principal_type must be 'user' or 'group'")
    principal_id = _uuid(params.get("principal_id"), "principal_id")
    base = _admin(realm, "users" if principal_type == "user" else "groups", principal_id, "role-mappings")
    _, client_uuid = _scope_paths(realm, params)
    return (base + "/realm" if client_uuid is None else base + f"/clients/{client_uuid}"), principal_type, client_uuid


def _confirm(params: dict[str, Any], expected: str) -> None:
    if params.get("confirm") != expected:
        raise KeycloakPackError(f"destructive operation requires confirm exactly '{expected}'")


def _filters(params: dict[str, Any], names: set[str]) -> dict[str, Any]:
    query: dict[str, Any] = {}
    for name in names:
        if name in params and params[name] is not None:
            value = params[name]
            if not isinstance(value, (str, bool)):
                raise KeycloakPackError(f"{name} must be a string or boolean")
            query[name] = str(value).lower() if isinstance(value, bool) else value
    return query


def _execute(client: KeycloakClient, operation: str, params: dict[str, Any]) -> tuple[Any, dict[str, Any], str | None]:
    if operation == "realm_list":
        data, meta = client.request("GET", "/admin/realms", query={"briefRepresentation": "true"})
        if not isinstance(data, list):
            raise KeycloakPackError("Keycloak returned an unexpected realms response")
        if "*" not in client.allowed_realms:
            data = [item for item in data if isinstance(item, dict) and item.get("realm") in client.allowed_realms]
        return data, {**meta, "count": len(data)}, None

    realm = _nonempty(params.get("realm"), "realm")
    client.assert_realm(realm)
    if operation == "realm_get":
        data, meta = client.request("GET", _admin(realm))
        return data, meta, realm

    if operation == "user_search":
        query = _filters(params, {"search", "username", "email", "firstName", "lastName", "q", "exact", "enabled", "emailVerified"})
        data, meta = _paginate(client, _admin(realm, "users"), params, query)
        return data, meta, realm
    if operation == "user_get":
        user_id = _uuid(params.get("user_id"), "user_id")
        data, meta = client.request("GET", _admin(realm, "users", user_id))
        return data, meta, realm
    if operation == "user_create":
        body = _representation(params, "user", USER_FIELDS, {"username"})
        data, meta = client.request("POST", _admin(realm, "users"), body=body, expected={201})
        return {**data, "user_id": meta.get("location_id")}, meta, realm
    if operation == "user_update":
        user_id = _uuid(params.get("user_id"), "user_id")
        body = _representation(params, "user", USER_FIELDS)
        data, meta = client.request("PUT", _admin(realm, "users", user_id), body=body, expected={204})
        return {**data, "user_id": user_id}, meta, realm
    if operation == "user_set_enabled":
        user_id = _uuid(params.get("user_id"), "user_id")
        enabled = _boolean(params, "enabled")
        data, meta = client.request("PUT", _admin(realm, "users", user_id), body={"enabled": enabled}, expected={204})
        return {**data, "user_id": user_id, "enabled": enabled}, meta, realm
    if operation == "user_reset_password":
        user_id = _uuid(params.get("user_id"), "user_id")
        secret = _fetch_key(_nonempty(params.get("password_key"), "password_key"))
        if isinstance(secret, dict):
            secret = secret.get("password")
        password = _nonempty(secret, "password Key value")
        body = {"type": "password", "value": password, "temporary": _boolean(params, "temporary", True)}
        data, meta = client.request("PUT", _admin(realm, "users", user_id, "reset-password"), body=body, expected={204})
        return {**data, "user_id": user_id, "temporary": body["temporary"]}, meta, realm
    if operation == "user_delete":
        user_id = _uuid(params.get("user_id"), "user_id")
        _confirm(params, f"delete:{realm}:user:{user_id}")
        data, meta = client.request("DELETE", _admin(realm, "users", user_id), expected={204})
        return {**data, "deleted": True, "user_id": user_id}, meta, realm

    if operation in {"group_list", "group_members"}:
        if operation == "group_members":
            group_id = _uuid(params.get("group_id"), "group_id")
            path = _admin(realm, "groups", group_id, "members")
            query = {"briefRepresentation": "true"}
        else:
            parent = params.get("parent_group_id")
            path = _admin(realm, "groups") if parent is None else _admin(realm, "groups", _uuid(parent, "parent_group_id"), "children")
            query = _filters(params, {"search", "exact"} if parent is not None else {"search", "q", "exact"})
            query["briefRepresentation"] = "true"
        data, meta = _paginate(client, path, params, query)
        return data, meta, realm
    if operation == "group_get":
        group_id = _uuid(params.get("group_id"), "group_id")
        data, meta = client.request("GET", _admin(realm, "groups", group_id))
        return data, meta, realm
    if operation == "group_create":
        body = _representation(params, "group", GROUP_FIELDS, {"name"})
        parent = params.get("parent_group_id")
        path = _admin(realm, "groups") if parent is None else _admin(realm, "groups", _uuid(parent, "parent_group_id"), "children")
        data, meta = client.request("POST", path, body=body, expected={201})
        return {**data, "group_id": meta.get("location_id")}, meta, realm
    if operation == "group_update":
        group_id = _uuid(params.get("group_id"), "group_id")
        body = _representation(params, "group", GROUP_FIELDS)
        data, meta = client.request("PUT", _admin(realm, "groups", group_id), body=body, expected={204})
        return {**data, "group_id": group_id}, meta, realm
    if operation == "group_delete":
        group_id = _uuid(params.get("group_id"), "group_id")
        _confirm(params, f"delete:{realm}:group:{group_id}")
        data, meta = client.request("DELETE", _admin(realm, "groups", group_id), expected={204})
        return {**data, "deleted": True, "group_id": group_id}, meta, realm
    if operation in {"group_member_add", "group_member_remove"}:
        group_id = _uuid(params.get("group_id"), "group_id")
        user_id = _uuid(params.get("user_id"), "user_id")
        method = "PUT" if operation.endswith("add") else "DELETE"
        verb = "add" if method == "PUT" else "remove"
        _confirm(params, f"{verb}:{realm}:group:{group_id}:user:{user_id}")
        data, meta = client.request(method, _admin(realm, "users", user_id, "groups", group_id), expected={204})
        return {**data, "group_id": group_id, "user_id": user_id, "membership": "added" if method == "PUT" else "removed"}, meta, realm

    if operation == "client_list":
        query = _filters(params, {"clientId", "search", "q", "viewableOnly"})
        data, meta = _paginate(client, _admin(realm, "clients"), params, query)
        return data, meta, realm
    if operation == "client_get":
        client_uuid = _uuid(params.get("client_uuid"), "client_uuid")
        data, meta = client.request("GET", _admin(realm, "clients", client_uuid))
        return data, meta, realm
    if operation == "client_create":
        body = _representation(params, "client", CLIENT_FIELDS, {"clientId"})
        data, meta = client.request("POST", _admin(realm, "clients"), body=body, expected={201})
        return {**data, "client_uuid": meta.get("location_id")}, meta, realm
    if operation == "client_update":
        client_uuid = _uuid(params.get("client_uuid"), "client_uuid")
        body = _representation(params, "client", CLIENT_FIELDS)
        data, meta = client.request("PUT", _admin(realm, "clients", client_uuid), body=body, expected={204})
        return {**data, "client_uuid": client_uuid}, meta, realm
    if operation == "client_delete":
        client_uuid = _uuid(params.get("client_uuid"), "client_uuid")
        _confirm(params, f"delete:{realm}:client:{client_uuid}")
        data, meta = client.request("DELETE", _admin(realm, "clients", client_uuid), expected={204})
        return {**data, "deleted": True, "client_uuid": client_uuid}, meta, realm

    if operation.startswith("role_") and not operation.startswith("role_mapping_"):
        roles_path, client_uuid = _scope_paths(realm, params)
        if operation == "role_list":
            query = _filters(params, {"search"})
            query["briefRepresentation"] = "false"
            data, meta = _paginate(client, roles_path, params, query)
            return data, meta, realm
        if operation == "role_create":
            body = _representation(params, "role", ROLE_FIELDS, {"name"})
            data, meta = client.request("POST", roles_path, body=body, expected={201})
            return {**data, "role_name": body["name"], "client_uuid": client_uuid}, meta, realm
        role_name = _nonempty(params.get("role_name"), "role_name")
        path = roles_path + "/" + _segment(role_name, "role_name")
        if operation == "role_get":
            data, meta = client.request("GET", path)
            return data, meta, realm
        if operation == "role_update":
            body = _representation(params, "role", ROLE_FIELDS)
            data, meta = client.request("PUT", path, body=body, expected={204})
            return {**data, "role_name": role_name}, meta, realm
        if operation == "role_delete":
            scope_id = "realm" if client_uuid is None else client_uuid
            _confirm(params, f"delete:{realm}:role:{scope_id}:{role_name}")
            data, meta = client.request("DELETE", path, expected={204})
            return {**data, "deleted": True, "role_name": role_name}, meta, realm

    if operation in {"role_mapping_list", "role_mapping_add", "role_mapping_remove"}:
        mapping_path, principal_type, client_uuid = _mapping_path(realm, params)
        if operation == "role_mapping_list":
            data, meta = client.request("GET", mapping_path)
            if not isinstance(data, list):
                raise KeycloakPackError("Keycloak returned an unexpected role mapping response")
            return data, {**meta, "count": len(data)}, realm
        role_names = _string_list(params.get("role_names"), "role_names")
        roles_path, _ = _scope_paths(realm, params)
        roles = [client.request("GET", roles_path + "/" + _segment(name, "role name"))[0] for name in role_names]
        if any(not isinstance(role, dict) or role.get("name") != name for role, name in zip(roles, role_names)):
            raise KeycloakPackError("Keycloak returned an unexpected role representation")
        method = "POST" if operation.endswith("add") else "DELETE"
        scope_id = "realm" if client_uuid is None else client_uuid
        verb = "assign" if method == "POST" else "remove"
        expected = f"{verb}:{realm}:{principal_type}:{params['principal_id']}:{scope_id}:roles:{','.join(sorted(role_names))}"
        _confirm(params, expected)
        data, meta = client.request(method, mapping_path, body=roles, expected={204})
        return {**data, "roles": role_names, "mapping": "added" if method == "POST" else "removed"}, meta, realm

    if operation == "identity_provider_list":
        query = _filters(params, {"search", "type", "capability", "realmOnly"})
        query["briefRepresentation"] = "false"
        data, meta = _paginate(client, _admin(realm, "identity-provider", "instances"), params, query)
        return data, meta, realm
    if operation == "identity_provider_get":
        alias = _nonempty(params.get("alias"), "alias")
        data, meta = client.request("GET", _admin(realm, "identity-provider", "instances", alias))
        return data, meta, realm
    if operation == "identity_provider_create":
        body = _representation(params, "identity_provider", IDP_CREATE_FIELDS, {"alias", "providerId"})
        body = _merge_secret_config(body, params)
        data, meta = client.request("POST", _admin(realm, "identity-provider", "instances"), body=body, expected={201})
        return {**data, "alias": body["alias"]}, meta, realm
    if operation == "identity_provider_update":
        alias = _nonempty(params.get("alias"), "alias")
        body = _representation(params, "identity_provider", IDP_UPDATE_FIELDS)
        body = _merge_secret_config(body, params)
        data, meta = client.request("PUT", _admin(realm, "identity-provider", "instances", alias), body=body, expected={204})
        return {**data, "alias": alias}, meta, realm
    if operation == "identity_provider_delete":
        alias = _nonempty(params.get("alias"), "alias")
        _confirm(params, f"delete:{realm}:identity-provider:{alias}")
        data, meta = client.request("DELETE", _admin(realm, "identity-provider", "instances", alias), expected={204})
        return {**data, "deleted": True, "alias": alias}, meta, realm

    if operation == "authentication_flow_list":
        data, meta = client.request("GET", _admin(realm, "authentication", "flows"))
        if not isinstance(data, list):
            raise KeycloakPackError("Keycloak returned an unexpected authentication flow response")
        return data, {**meta, "count": len(data)}, realm
    if operation == "authentication_flow_get":
        flow_id = _uuid(params.get("flow_id"), "flow_id")
        data, meta = client.request("GET", _admin(realm, "authentication", "flows", flow_id))
        return data, meta, realm
    if operation == "authentication_flow_executions":
        alias = _nonempty(params.get("flow_alias"), "flow_alias")
        data, meta = client.request("GET", _admin(realm, "authentication", "flows", alias, "executions"))
        if not isinstance(data, list):
            raise KeycloakPackError("Keycloak returned an unexpected authentication execution response")
        return data, {**meta, "count": len(data)}, realm

    raise KeycloakPackError("unsupported Keycloak action")


def _merge_secret_config(body: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    inline = body.get("config", {})
    if not isinstance(inline, dict):
        raise KeycloakPackError("identity_provider config must be an object")
    if any(_SENSITIVE.search(str(key)) for key in inline):
        raise KeycloakPackError("sensitive identity-provider config must use secret_config_key")
    secret_key = params.get("secret_config_key")
    if secret_key is None:
        return body
    secret = _fetch_key(_nonempty(secret_key, "secret_config_key"))
    if not isinstance(secret, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in secret.items()):
        raise KeycloakPackError("identity-provider secret config Key must contain a string-to-string object")
    return {**body, "config": {**inline, **secret}}


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    timeout = _integer(params, "timeout_seconds", 30, 1, 120)
    credential_key = params.get("credential_key", DEFAULT_CREDENTIAL_KEY)
    client = KeycloakClient(_credential(credential_key), timeout)
    data, meta, realm = _execute(client, operation, params)
    return {"operation": operation, "realm": realm, "data": _redact(data), "meta": meta}
