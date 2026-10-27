---
id: scan-wordlist-generation
title: Target-tuned wordlist generation
phase: scan
target_kinds: [web]
when_to_use: >-
  Content discovery has found some routes but the stock wordlist is
  missing target-specific vocabulary (product names, internal jargon,
  acronyms visible on the site). `cewl` scrapes the live site to build
  a wordlist biased toward this specific target.
tools_available: [cewl]
mitre_attack: [T1595.003]
cwe: []
owasp: []
confidence: low
version: 1
---

## When to use
When a prior `recon-content-discovery` pass with the stock wordlist
returned sparse results on a site with obvious custom vocabulary. The
wordlist is useful for a second content-discovery pass; it is NOT a
credential-brute wordlist (that is attack-phase).

## Workflow (advisory)
1. `cewl -d 1 <url>` crawls one level deep. Outputs a word list, one
   per line.
2. Feed the resulting file as `VAPT_WORDLIST` to a second feroxbuster
   run on the same host. Keep the operator in the loop — the second
   pass is cheap but produces no new signal on static sites.

## Verification
Wordlist generation is a utility step. It produces no findings by
itself; its value shows up in the second content-discovery pass.

## Known pitfalls
- `cewl` on a very large site (news archive, blog with years of posts)
  returns tens of thousands of words. Cap the output; a huge wordlist
  does not improve content-discovery recall beyond the top few
  thousand words.
