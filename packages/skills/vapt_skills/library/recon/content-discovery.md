---
id: recon-content-discovery
title: Content and route discovery
phase: recon
target_kinds: [web]
when_to_use: >-
  The target has an HTTP(S) service, few routes are known from crawling, and
  further vulnerability scanning needs an endpoint surface. Content discovery
  exposes unlinked routes (admin consoles, backup files, debug endpoints) that
  the crawl cannot reach.
tools_available: [feroxbuster, katana, gobuster_dir, ffuf]
auth_sensitive: true
mitre_attack: [T1595.003]
owasp: []
confidence: high
version: 1
---

## When to use
After `recon-web-fingerprint` has stabilized the service. Pair the crawl
(`katana`, which parses JS for API routes) with a wordlist walker
(`feroxbuster`) — one finds what links to things, the other finds what
nothing links to.

## Workflow (advisory)
1. `katana -jc -d 5` to crawl JS + robots + sitemap. Captures `/api/*` and
   app routes that aren't in plain `<a>` tags.
2. `feroxbuster` with `VAPT_WORDLIST` (default seclists common.txt) to brute
   routes. `-n` bounds recursion; do not raise it without good reason.
3. Pass the discovered routes forward to `recon-param-discovery` — this is
   the point where arjun actually has somewhere worth probing.

## Known pitfalls
- `feroxbuster --silent -q` conflict exits with code 2 and NO findings. The
  governed builder uses `--silent -k -n` only.
- Content discovery against an authenticated-only app without a cookie
  catches almost nothing. When a `login_url` is detected, re-run with the
  session cookie — see `scan-web-authenticated`.
