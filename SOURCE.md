# Source and API Baseline

## Upstream Pack

- Repository: https://github.com/StackStorm-Exchange/stackstorm-keycloak
- Verified revision: `f978f295fbdcf72d3bde62d73d3ea023ed45378f`
- Revision date: 2021-12-19
- Pack version at revision: `1.0.0`
- Latest upstream tag: `v1.0.0` at revision
  `ce1edd96752f88d3601c231d05fe34ce7261bc35`
- License: Apache License 2.0, verified from both repository metadata and the
  upstream `LICENSE` file

The upstream used `python-keycloak==0.13.3`, old host/port configuration, and
API assumptions from its 2017-2021 history. This pack preserves attribution and
the operational intent, not that implementation.

## Current Keycloak Baseline

- Current release verified 2026-08-14: Keycloak `26.7.1`, published 2026-08-05
- Release: https://github.com/keycloak/keycloak/releases/tag/26.7.1
- Admin REST documentation:
  https://www.keycloak.org/docs-api/latest/rest-api/index.html
- OpenAPI document used to verify routes and query parameters:
  https://www.keycloak.org/docs-api/latest/rest-api/openapi.json
- Documented Admin API URI scheme: `{base_url}/admin/realms`

The upstream documentation labels the Admin OpenAPI definition version `1.0`;
the Keycloak product release is therefore recorded separately. Endpoint
selection was checked against the live latest document and Keycloak 26.7.1.
