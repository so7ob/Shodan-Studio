# Premium refusal and retry holds

The Premium gateway classifies HTTP errors before reading or decrypting their
bodies. Empty/HTML 401, 403, 404 and 429 responses cannot become transport errors
or trigger a POST to another gateway. Other non-success HTTP statuses also stop
at the responding gateway. Network failures retain the existing bounded approved
origin fallback, with the same request identity; a refusal never enters it.

`Retry-After` accepts seconds and HTTP dates through the existing bounded parser.
Only a validated duration (or an explicit `unbounded` marker) crosses the private
unprivileged-worker pipe. The privileged adapter persists the later of the local
cooldown, upstream deadline and existing deadline before returning the fixed error
code. Restarting, repeated refreshes and selecting another location cannot shorten
that hold. Very large waits persist an explicit unbounded hold without non-finite
JSON numbers; there is no automatic early retry or fabricated expiry.

The tests use fake HTTPS replies, private temporary state and mock subprocesses.
They cover empty/HTML denials, no second gateway POST, HTTP dates, extreme waits,
private-pipe propagation, restart, repeated early calls, and resumption at the
stored finite deadline. They make no live Premium or Shodan requests.

This change is packaged in a cumulative candidate based on the existing feature
stack. It is not a deployment, live-access acceptance, or a reason to close the
broader VPN/browser acceptance issues. Review the complete candidate before
merging; retain the source branches and verify repository branch-deletion policy.
