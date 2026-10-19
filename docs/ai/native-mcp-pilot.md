# Restrict the native MCP server to reviewed aggregate reports

This fork has an opt-in profile for one native user, exact public OAuth clients,
and reviewed saved questions. It retains Metabase's native OAuth, MCP sessions,
Agent API, query permissions, and query processor. The only exposed tool is
`execute_question`, with exactly one integer `id` argument.

This profile is a local implementation candidate until the deployment owner has
reviewed its policy, registered the clients, and verified the deployed behavior.
It does not grant approval to expose a report or change someone's permissions.

## Configure both deployment inputs

Set `MB_MCP_PILOT_CLIENT_IDS` to a JSON array of one to four unique exact client
IDs. Set `MB_MCP_PILOT_POLICY_PATH` to the absolute path of the policy JSON file.
Deploy the registry independently of the file, and replace the file atomically.
There is no cached last-good policy.

Only genuinely absent **both** inputs select the original native behavior.
Empty, whitespace, malformed, or missing counterpart values fail closed.

| Deployment state                                 | Result                                                                                                                                          |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Both inputs absent                               | Original native behavior; unsuitable as a public pilot fallback.                                                                                |
| Valid registry and matching valid policy         | Restricted native MCP for the exact user and clients.                                                                                           |
| Valid registry, unavailable or mismatched policy | MCP and known pilot credentials unavailable; other valid OAuth clients retain native behavior.                                                  |
| Missing or invalid registry in configured mode   | All supplied Bearer authentication fails with a sanitized 503 before session/API-key fallback; unclassifiable issuance and refresh are refused. |

The final row intentionally affects OAuth availability more broadly. Session-only
browser/API/Metabot operation stays available. Validate both inputs and negative
probes before activation; roll back configuration/image on integration regression.

## Register clients with the existing native OAuth server

Register separate CLI and application clients as public clients, with
`application_type = native`, `token_endpoint_auth_method = none`, response type
`code`, and exactly `authorization_code` and `refresh_token` grant types. The
registered scope list must be exactly `["agent:question:execute"]`.

Pin exact redirect URIs in both the registration and policy. A CLI can use its
reviewed fixed HTTP callback on `127.0.0.1`; other callbacks require HTTPS.
Wildcards, new localhost exceptions, and broad/empty scope sets are refused.
The supported native DCR flow may create a client, but registration alone never
enrolls it in the pilot. The deployment owner must independently review its exact
client ID and metadata, then pin it in both deployment inputs. Existing static
clients can use the same contract. The registration provenance label confers no
authority. DCR defaults remain native behavior behind the normal Access boundary;
the public pilot transport must not expose registration or automatically enroll
a client.

Every pilot grant must carry the exact policy resource. Resolution, authorization,
redemption/refresh, and issuance recheck the current registered client, user,
scope, and resource. Client deletion, callback/scope drift, or user deactivation
does not preserve old authority. Normal native token revocation remains available,
including when the grant no longer satisfies the pilot.

Supplied pilot Bearer credentials cannot authenticate direct REST calls, even to
the Agent API's saved-question endpoint. They cannot acquire a cookie/API-key
identity through fallback. MCP requires the native Bearer grant independently of
administrator status, session state, or API keys. An unrecognized supplied Bearer
also cannot fall back to another identity in configured mode.

## Review and pin each report

The policy has exactly these top-level fields: `version` (1), `user-id`, `resource`,
`clients`, and `reports`. Each client has `id` and `redirect-uris`. Each report has:

- `id`, a reviewed saved-question ID; `title`, a reviewed safe catalog label.
- `collection-id` and `database-id`, both exact positive IDs.
- `sha256`, the root snapshot fingerprint.
- `dependencies`, the complete transitive card/snippet list, each with `kind`
  (`card` or `snippet`), `id`, and `sha256`.
- `columns`, ordered objects with `name`, `base-type`, and `kind`.
- `max-rows` (1–1000) and `max-bytes` (up to 4 MiB).

Review the source queries and aggregate semantics before generating pins. The
in-process `metabase.mcp.pilot-snapshot/capture!` reads the graph under the existing
caller's permissions. Fingerprint each root/dependency using
`metabase.mcp.pilot-policy/fingerprint`. Store only fingerprints and reviewed
contracts in policy; do not print or copy raw queries, credentials, or data into
receipts. New questions may acquire result metadata on first execution: finish
that review/preparation before pinning their stable definition.

Snapshots use native persistence serialization to remove request-local metadata
providers, caches, and query-processor internals. They include stored queries,
card parameters, display/type/result metadata,
database and collection IDs, collection ancestry, and transitive saved cards and
native snippets. Missing, archived, cyclic, oversized, parameterized, unpinned,
or changed dependencies are unavailable. No query/filter/SQL/URL/database/handle
arguments may be supplied through the tool.

The available value kinds are `integer`, `number`, `boolean`, `date`, and
`datetime`, with exact supported native base types. Dates use ISO local dates;
datetimes require an ISO offset. Every value must be present and correctly typed;
numbers must be finite. Arbitrary text, nullable values, nested data, unexpected
columns, type changes, and continuations are refused. Only reviewed names/types,
rows, completion status, and row count leave the server. Missing data is
unavailable, never converted to zero.

The complete native response is buffered with an 8 MiB hard limit before
projection. The projected tool payload, including both JSON text and structured
content, must fit the report's byte limit. Request IDs are bounded separately;
the JSON-RPC/SSE envelope adds bounded protocol overhead. No partial results,
raw query metadata, upstream error details, or caller `clientInfo` logs are
released by the configured MCP path. Batches, Apps, raw resources, arbitrary
tools, and the persistent GET notification stream are unavailable.

Pre/post authorization and graph checks suppress ordinary concurrent changes.
They are **not atomic protection against a malicious privileged author who changes
and restores a definition during execution**. Reviewed warehouse view/schema
definitions and privileged authors remain explicit trust assumptions. Source
upgrades need a fresh policy review and native regression run.

## Prepare hashes without exporting definitions

The deployment owner chooses the execution mechanism and approves each report
and its output contract. The helpers below do not execute reports, change the
database, open a server, fetch credentials, or approve a report automatically.

For existing in-process operator access, bind the reviewed user with
`metabase.request.core/with-current-user` and call
`metabase.mcp.pilot-snapshot/pins!` with the reviewed `id`, `collection-id`, and
`database-id`. It reads the current graph under that user's permissions and
returns only `sha256` and the dependency `kind`, `id`, and `sha256` entries.

For an operator using ordinary authenticated native APIs, keep the complete
decoded response bodies in memory. Read `GET /api/card/:id` using its default
MBQL 5 representation, every transitive saved card and
`GET /api/native-query-snippet/:id`, and `GET /api/collection/:id` for every bound
collection. Pass integer-ID maps as `cards`, `snippets`, and `collections` to
`metabase.mcp.pilot-snapshot/pins-from-api`, along with the reviewed report
bindings. The helper uses the same definition projection, normalization,
serialization, graph traversal, and hash function as native capture.

Card metadata must include `id`, `dataset_query`, `collection_id`, `database_id`,
`type`, `display`, `parameters`, `result_metadata`, and `archived`. Snippets need
`id`, `name`, `content`, `template_tags`, `collection_id`, and `archived`.
Collections need `id`, `location`, `namespace`, and `archived`, including explicit
null values where present. Missing state fails closed; do not substitute an
effective location, legacy query, omitted metadata, or a guessed default. An API
upgrade or hydration difference requires a fresh equivalence check against
native capture before using this path.

Print only the returned pins and separately reviewed safe output contracts.
Never persist or log input response bodies, SQL, snippet content, user metadata,
credentials, or results. Helpers return a generic unavailable error on failure.
Review the graph again if definitions change during preparation; this process
does not make concurrent privileged edits atomic.

## Require native admission before public forwarding

The fork implements a private `HEAD /api/metabase-mcp` adjunct for the later
accounting transport. A current matching pilot grant and healthy configuration
return 204, `Cache-Control: no-store`, `X-Metabase-MCP-Pilot-Proof: 1`, and
`X-Metabase-MCP-Pilot-Digest`. The digest is the deterministic fingerprint of
`{:client-ids (sort registry-ids), :policy effective-policy}`. It contains no
identity/report values. The probe creates no MCP session and executes no report.
Aliases, trailing slashes, baseline mode, invalid configuration, and invalid or
revoked grants never emit this proof.

The deployment owner's later proxy must deny external HEAD, probe only the fixed
private native origin, require the expected proof/digest before reserving its
existing durable budget, strip proof headers, and forward the native MCP request
unchanged. Actual native dispatch independently repeats authorization and output
checks. This transport dependency is mandatory: accidental removal of both
native inputs must not turn the public endpoint into unrestricted forwarding.

The proof is a fork adjunct, not an upstream MCP feature or atomic authorization
guarantee. It does not replace the existing encrypted ledger/accounting principal
or authorize a deployment, issuer rewrite, new server, or public Access bypass.

## Verify the candidate before activation

Use the focused `metabase.mcp.pilot-*` namespaces and the affected native MCP,
OAuth, and session regression suites through `./bin/test-agent`. Tests use
invented H2 fixtures. Keep local tests, CI, independent review, deployment,
Inspector compatibility, and real-data/Claude acceptance distinct.

Official Inspector 2.1.0 testing must use its own private configuration/cache and
the exact registered callback. Cached success is not refresh proof; deleting a
cache is not revocation. Prove native refresh/rotation and server-side revocation
separately. Never print tokens, authorization callback URLs, or private results.
