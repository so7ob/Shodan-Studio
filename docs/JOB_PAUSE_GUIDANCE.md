# Paused-job guidance

The existing countdown remains in place. Paused-job alerts and the resume dialog
now explain the persisted source deadline in local time, keep an elapsed deadline
visible without claiming source acceptance, and identify an unrepresentable wait
as a manual hold. Missing or malformed deadlines are not treated as elapsed waits.
Checkpoint wording follows the server's actual `has_checkpoint` flag and does not
promise recovery when no checkpoint file is available. Technical errors remain
available in a keyboard-accessible details element and are rendered as literal
text, never HTML. The component makes no requests and adds no automatic retry.

Offline checks:

```sh
node --test tests/test_ip_progress.mjs tests/test_job_guidance.mjs
python3 tests/serve_job_guidance_fixture.py --info /tmp/guidance-fixture.json
# In another terminal; requires local Playwright and Chromium:
node tests/browser_job_guidance.cjs http://127.0.0.1:8878 /tmp/guidance-fixture.json /tmp/guidance-evidence
```

The fixture binds loopback, uses a temporary database and synthetic checkpoints,
and never starts the worker queue. Browser routing blocks non-fixture URLs. It
covers future/elapsed/unbounded waits, access denial, missing checkpoints,
reload, three interrupted resume dialogs, keyboard details, literal error markup,
and RTL 1280/375 layouts. It asserts zero mutation requests after fixture login.
These checks do not establish live source access or production acceptance.
