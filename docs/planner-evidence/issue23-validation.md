# Issue #23 validation

All extraction tests use local synthetic responses. No live Shodan requests or
VPN changes were made for this change.

- Full Python suite: 275 passed. Focused adaptive/pacing regressions: 25 passed.
- JavaScript presentation tests: 22 passed.
- Arabic RTL browser acceptance: 375 and 1280 px; keyboard entry into job details,
  automatic/legacy strategy controls, reported source count, countdown ticks and
  reload persistence. Zero axe violations in the tested job and create-dialog
  regions; zero JavaScript page errors and no document overflow.
- Screenshots and machine-readable evidence: `issue23-pacing-*` and
  `issue23-completed-*`. These are synthetic fixture screens.
- Manual visual review covered desktop and mobile. A real screen-reader session
  was not performed; timer semantics were checked through the browser and axe.
- All six synthetic benchmark cases retained identical IP sets. Fragmented ports
  now use two packed leaves and four total requests, versus 55 in Priority.
- Anonymized 581-record snapshot regression: three facet probes choose four
  initial ASN branches (580 records in the newer snapshot), with eight estimated
  downstream requests instead of 60. A large child remains subject to further
  verification/splitting. This does not establish a live final branch count.
- Native demo worker integration retains all 292 unique IPs, with four branches
  and ten requests (previously five branches and eleven requests).
- No service deployment or migration is part of this evidence.
