# Keycloak Admin REST Attune Pack

This Attune pack rebuilds the Apache-2.0 StackStorm Exchange Keycloak pack at
revision `f978f295fbdcf72d3bde62d73d3ea023ed45378f`. It targets the current
Keycloak 26.7.1 Admin REST API directly, without `python-keycloak` or an
implicit legacy context path. See [SOURCE.md](SOURCE.md) for the verified source,
release, license, and documentation baseline.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- HTTPS reachability from the worker to Keycloak.
- A confidential Keycloak client/service account with only the realm-management
  permissions needed by the selected actions.
- An encrypted, pack-owned Attune Key, normally `pack.keycloak.credentials`.

## Credential Key

Preferred client-credentials Key:

```json
{
  "base_url": "https://keycloak.example.com",
  "auth_realm": "management",
  "allowed_realms": ["customer-a", "customer-b"],
  "auth_method": "client_credentials",
  "client_id": "attune-admin",
  "client_secret": "REDACTED",
  "verify_tls": true
}
```

`base_url` is the deployment root. For a currently configured relative path,
use that path explicitly, for example `https://keycloak.example.com/iam`. The
client appends the documented `/realms/.../protocol/openid-connect/token` and
`/admin/realms/...` routes; it does not inject any historical context path.

`auth_realm` is used only to obtain an OAuth token. Every target operation takes
a separate required `realm` parameter. `allowed_realms` provides a second,
Key-owned boundary against cross-realm mistakes. Use `allowed_realms: ["*"]`
only after deliberately accepting all realms visible to the service account.
`realm_list` filters its result through this allowlist.

TLS certificate verification is mandatory. To trust a private PKI, put its PEM
CA certificate in `ca_cert`; it is loaded directly into a dedicated verified
SSL context. URL credentials, plain HTTP, redirects, query strings, fragments,
invalid CA data, and `verify_tls: false` are rejected.

Username/password grant is available only for a reviewed bootstrap or migration
where a service account cannot yet be used:

```json
{
  "base_url": "https://keycloak.example.com",
  "auth_realm": "master",
  "allowed_realms": ["migration-target"],
  "auth_method": "password",
  "client_id": "admin-cli",
  "username": "migration-admin",
  "password": "REDACTED",
  "verify_tls": true
}
```

A confidential password-grant client may also include `client_secret`. The
client uses a returned refresh token in-process and otherwise obtains a fresh
token before expiry. Tokens, passwords, and response bodies are never included
in errors. Requests have a 1-120 second bounded timeout, reject redirects, and
cap responses at 16 MiB. The client performs no automatic mutation retries.

## Actions

All actions receive one flat JSON object on stdin and return:

```json
{
  "operation": "user_get",
  "realm": "customer-a",
  "data": {"id": "11111111-1111-4111-8111-111111111111", "username": "alex"},
  "meta": {"http_status": 200}
}
```

Action groups:

| Area | Actions |
|---|---|
| Realms | `realm_list`, `realm_get` |
| Users | `user_search`, `user_get`, `user_create`, `user_update`, `user_set_enabled`, `user_reset_password`, `user_delete` |
| Groups | `group_list`, `group_get`, `group_create`, `group_update`, `group_delete`, `group_members`, `group_member_add`, `group_member_remove` |
| Clients | `client_list`, `client_get`, `client_create`, `client_update`, `client_delete` |
| Roles | `role_list`, `role_get`, `role_create`, `role_update`, `role_delete` for `realm` or `client` scope |
| Direct mappings | `role_mapping_list`, `role_mapping_add`, `role_mapping_remove` for users/groups and realm/client roles |
| Identity providers | `identity_provider_list`, `identity_provider_get`, `identity_provider_create`, `identity_provider_update`, `identity_provider_delete` |
| Authentication flows | `authentication_flow_list`, `authentication_flow_get`, `authentication_flow_executions` (inspection only) |

`user_search`, `group_list`, `group_members`, `client_list`, `role_list`, and
`identity_provider_list` use Keycloak's `first`/`max` pagination. One page is
returned by default. Set `all_pages: true` to continue until a short page or
`max_total`; page size is at most 1,000 and total results at most 10,000.
Pagination metadata reports `first`, `count`, `pages`, and `truncated`.

## Identifiers and Schemas

- `realm` is a realm name, never a realm UUID.
- `user_id`, `group_id`, `client_uuid`, `principal_id`, and `flow_id` are
  UUID-formatted internal IDs, never usernames, group paths, `clientId` values,
  or aliases.
- `role_name`, identity-provider `alias`, and `flow_alias` are display
  identifiers encoded as one URL path segment.
- `scope: realm` rejects `client_uuid`; `scope: client` requires it.
- Direct mapping actions resolve each exact role name in the selected scope and
  send Keycloak's returned role representation. They do not request composite
  or available-role expansion.

Mutation bodies are allowlisted rather than passed through as arbitrary Admin
API representations. User credentials, federated identities, group mappings,
client secrets, service accounts, protocol mappers, arbitrary client attributes,
implicit flow, authorization settings,
composite roles, and management-permission objects are excluded. Those security
surfaces require separate reviewed actions rather than generic body escape
hatches. Keycloak HTTP 409 responses become explicit conflict failures without
including the server response body.

`user_reset_password` takes `password_key`, not a password. That Key may contain
a string or `{"password":"..."}`. Identity-provider `config` rejects keys whose
names look sensitive; supply those string fields through `secret_config_key`.
All returned object keys containing password, secret, token, credential, or
private-key terms are redacted recursively.

## Confirmations

Every `DELETE` request and each privilege-bearing membership/role assignment
requires an exact, case-sensitive `confirm` value:

```text
delete:<realm>:user:<user_id>
delete:<realm>:group:<group_id>
delete:<realm>:client:<client_uuid>
delete:<realm>:role:<realm-or-client_uuid>:<role_name>
delete:<realm>:identity-provider:<alias>
add:<realm>:group:<group_id>:user:<user_id>
remove:<realm>:group:<group_id>:user:<user_id>
assign:<realm>:<user-or-group>:<principal_id>:<realm-or-client_uuid>:roles:<sorted-comma-separated-role-names>
remove:<realm>:<user-or-group>:<principal_id>:<realm-or-client_uuid>:roles:<sorted-comma-separated-role-names>
```

For realm-role confirmations, the scope identifier is the literal `realm`. Role
names are sorted lexically only in the confirmation string. Confirmation does
not make an operation idempotent and does not trigger a retry.

## Privileges

This pack never creates management permissions, service accounts, composite
roles, client secrets, or arbitrary API requests. It can still perform powerful
administrative changes when its Keycloak principal is authorized. In particular,
group membership and role assignments can elevate a user; their confirmation
strings make the principal, scope, and exact roles explicit. Grant the service
account only `view-*` or `manage-*` capabilities required by the actions in use,
prefer per-realm fine-grained admin permissions, and avoid `realm-admin` unless
the automation genuinely needs it.

## Upstream Fidelity

| Upstream surface | Attune target | Difference |
|---|---|---|
| User/client/group reads and mutations | Explicit CRUD/search actions | Current routes, UUID clarity, schemas, pagination, confirmations |
| Realm/client roles and user role assignment | Scoped role and direct mapping actions | Supports users and groups; no composites or arbitrary permissions |
| Identity providers | Full instance CRUD | Current instance routes, pagination, Key-backed secret config |
| Authentication flow reads/writes | Three inspection actions | Writes deliberately omitted because flow edits alter login security |
| Old server-info helper and library wrappers | Omitted | No generic endpoint or obsolete client-library assumptions |
| Pack YAML host/port/admin password | Attune Key credential object | HTTPS, custom CA, OAuth refresh, realm allowlist |

## Validation

```bash
python3 -m unittest discover -s /home/david/Codebase/attune-packs/keycloak/tests -v
attune --output json pack check /home/david/Codebase/attune-packs/keycloak
attune pack test /home/david/Codebase/attune-packs/keycloak --detailed
```

Tests are deterministic and use only the Python standard library. They mock all
Keycloak and Attune Key access. Live validation remains deployment-specific due
to realm topology, fine-grained admin permissions, federation providers, custom
CA trust, and enabled OAuth grants.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).
