# Premium subscription adapter

The user has authorized dynamic Premium country switching, beyond static exports.
Compatibility target: upstream AmneziaVPN 5.0.3.0, tag commit
`de93650a90739b87bb47a632872ea9d0adc9412f`.

The upstream `SubscriptionController` requests `/v1/config` with a country,
subscription authentication and an installation UUID. Native export instead uses
`/v1/native_config`. The adapter must never call native-export or revoke endpoints.
It is source-compatible integration, not an officially published third-party SDK.

Design before any live subscription or network mutation:

- One root-private subscription record and persistent, independent installation
  UUID. Never reuse the host GUI UUID or tunnel keys. Country changes reuse this
  worker identity; one worker device slot is needed, not one export per country.
- Root-only bootstrap may read the installed Linux client settings without writing
  them. Extract only subscription credentials, country metadata and trusted
  gateway transport material. Never expose credentials in command arguments,
  SQLite, API responses, test artifacts or logs. Browser enrollment accepts a
  subscription key through the existing authenticated CSRF-protected API.
- Pin the production RSA public-key fingerprint from the installed client.
  Use the client's encrypted request format over verified HTTPS gateway proxies;
  no plaintext fallback, no UI-supplied endpoints, no redirects or environment
  proxies. Bound response size, attempts and time. Fail closed for incompatible
  responses, device limits, expiry, rate limits and interactive captcha. Gateway
  subprocesses use a separate unprivileged `shodan-vpn-gateway` UID, never the
  web UID, and carry credentials only through private stdin/stdout pipes.
- Fetch real account/country data; persist only sanitized public metadata in the
  existing profile registry. Stable country profile IDs let existing per-job
  allowlists, cooldowns, checkpoints and audit records continue to work.
- Request an independent AWG configuration only at a safe switch boundary. Validate
  country and returned configuration with the existing strict parser. Connect only
  inside `ssvpn-worker`; require handshake, egress and leak-protection verification.
  Failures preserve/pause the job; restoring a Premium country obtains a new config
  for the same worker identity because server-side switching may expire the old one.
- Keep the helper worker lease and job queue reservation around subscription
  mutations. Read-only polling never performs registration or country switching.
- Test transport encryption, subscription decoding, redaction, persistent identity,
  country authorization, failure handling, GUI/API and checkpoint integration with
  local fixtures before a bounded live test. Compare host route/firewall/DNS and
  management-service state before/after live tests.

No schema change is required: existing JSON metadata supports the additional
provider and location fields. Secrets remain in root-owned mode-0600 files.

Sources:

- https://github.com/amnezia-vpn/amnezia-client/blob/5.0.3.0/client/core/controllers/api/subscriptionController.cpp
- https://github.com/amnezia-vpn/amnezia-client/blob/5.0.3.0/client/core/controllers/gatewayController.cpp
- https://github.com/amnezia-vpn/amnezia-client/blob/5.0.3.0/client/core/utils/api/gatewayPayloadBuilder.cpp
- https://docs.amnezia.org/documentation/instructions/personal_dashboard/
