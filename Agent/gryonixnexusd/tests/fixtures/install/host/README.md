# Host-half fixtures — the bytes the setup script actually writes

Every file here is a heredoc BODY lifted out of a real generated setup script,
i.e. exactly what `cat > /opt/… <<'EOF_…'` puts on the server. Not a
transcription of the Swift source: a port checked against a reading of the
generator only proves the port matches how someone read it, which is the
failure mode `gryonixnexus-dms-dkim.sh` lived with for a year behind a green
test.

## How they were produced

```sh
# one SwiftPM lane, from Packages/gryonixNexus
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
GRYONIXNEXUS_DUMP_DIR=<dir> swift test --filter GeneratedScriptLintTests
# then, per wrapper
scratchpad/extract-heredoc-from-generated-script.sh \
    <dir>/<variant>__setup-mail-server.sh EOF_BACKUP_CTL out.txt
```

Delimiters: `EOF_BACKUP_CTL`, `EOF_UPDATE_CTL`, `EOF_UNINSTALL`, `EOF_RESTORE`,
`EOF_SUDOERS`, `EOF_CONTAINER_CTL`, `EOF_METRICS`, `EOF_METRICS_UNIT`,
`EOF_VPNPANEL_LOCKDOWN`, `EOF_AUTOBACKUP_UNIT`, `EOF_AUTOUPDATE_UNIT`.

The three `report_*` directories are the exception, and the difference
matters: the report is not written by a heredoc, it is PRINTED by a
`{ … } > "$GD_REPORT_TMP"` group. Those fixtures are that group's BODY —
shell that still has to run — cut out of the same generated scripts. They
are therefore verified by EXECUTING them against a sandbox and diffing
stdout, not by comparing source text; see `install/host/report/mod.rs`.

## Variant names

`<A|B>-<service-set>-<access|noaccess>-<en|ru>`, plus the `*-multidomain` rows.
`A` is a single public host, `B` is VPS relay + home backend. The service set
behind each name — and the full input that produced it — is
`GeneratedScriptLintTests.makeVariants()` in
`Packages/gryonixNexus/Tests/MailRecipeTests/`. That function is the manifest;
do not re-derive it from the file names.

The `report_*` directories additionally carry an `INDEX.json` mapping each
kept fixture to EVERY variant whose body was byte-identical to it. It is
bookkeeping, not a second manifest: it says which variants a given fixture
speaks for, so that dropping one is a visible loss of coverage rather than a
silent one.

## One fixture per DISTINCT body — and what that number means

97 script variants were generated; only the bodies that actually differ are
kept:

| wrapper | distinct bodies |
|---|---|
| `report_single` | 49 |
| `report_home` | 49 |
| `report_vps` | 19 |
| `restore` | 45 |
| `access_sudoers` | 25 |
| `uninstall` | 25 |
| `backup_ctl` | 23 |
| `update_ctl` | 23 |
| `access_container_ctl` | 1 |
| `metrics` | 1 |
| `lockdown` | 1 |

The bottom three are **constant across every variant** — they interpolate
nothing. That is a measurement, not a reassurance: a port with values hardcoded
would pass all of them, exactly the trap срез 4.9 found when all seven "real"
VPN compose fixtures turned out byte-identical. Where a fixture set is
constant, the coverage has to come from somewhere else (an argument-level test,
or a new dumped scenario), not from the fixture count.
