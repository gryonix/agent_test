# agent_test

`gryonixnexusd` — the gryonixNexus control-plane agent — published here so an
already-installed server can be updated without waiting on an App Store
review of the client app. Test name, chosen deliberately: this validates the
mechanism before a normal-named repo replaces it.

## What is here

- `Agent/{bootstrap,gryonixnexusd,proto,systemd}` — the exact source tree
  `gryonixNexus/Tools/pack-agent-sources.sh` also bundles into the app, staged
  the same way. Published by `gryonixNexus/Tools/publish-agent-test.sh`, run
  by hand — there is no CI here.
- `latest.json` — what an agent checks: the newest published `version`, the
  `tag` and download `url` for its source, and the `sha256` an agent verifies
  before it runs anything from here as root.

## How an update reaches a server

1. The agent periodically checks `latest.json` here against its own version.
2. If newer, it tells the app there is one — nothing is fetched yet.
3. Only once the owner confirms from the app does the agent download the
   tagged source, check its sha256 against `latest.json`, and rebuild itself
   the same way the bootstrap already does today.

See `gryonixNexus`'s own `docs_ai/gryonixNexus/ROADMAP.md`, "Обновление
агента в обход App Store" (2026-09-13), for the open questions this is still
working through — most importantly, that a sha256 pinned in the same
repository a compromised account could rewrite is a starting point, not the
final answer, for a root daemon that updates itself.
