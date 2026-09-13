//! DNS record generation — a port of the Swift side's `DNSRecordGenerator`
//! (`Packages/gryonixNexus/Sources/MailRecipe/Generators/DNSRecordGenerator.swift`).
//!
//! **Ф4 слайс 4.0.** Picked first not because it is install (Ф4's actual
//! goal), but because it is already, today, "a separate artifact, not part
//! of the script" (ARCHITECTURE.md) — a pure function with no docker/shell/
//! nftables surface, the one class of code GOTCHAS.md never has to mention.
//! The point of this slice is to prove the RELOCATION PATTERN (how a
//! generation-time engine becomes Rust-side domain modelling) in isolation,
//! not to wire it up: there is deliberately **no RPC, no `api.rs` route, no
//! crate version bump** here. DNS generation happens client-side today,
//! before any server exists to call an RPC on — the right wire shape for
//! install-time generation is an open question for a later Ф4 slice, once
//! the install-flow redesign actually lands, not something to guess at now.
//! `Input`/`records`/`generate` below stand alone in the crate, exercised
//! only by `cargo test` and the parity fixtures under `tests/fixtures/dns/`.
//!
//! **Why this duplicates `DNSRecordGenerator` instead of depending on it**:
//! the same reasoning ARCHITECTURE.md's "Маркеры установки" note gives for
//! `GRYONIXNEXUS_STEP`/`REPORT` living independently in `MailRecipe` and
//! `ServerControl` — this binary is a self-contained musl build (see
//! `Cargo.toml`), Swift packages cannot be a dependency of it, and
//! `MailRecipe` has zero awareness of Rust, so there is no direction a
//! shared dependency could even go. The translation table
//! (`dns_l10n.rs`) is the same kind of duplication as `dkim.rs`'s
//! three-wrapper-parser or `restore.rs`'s hardcoded `restore_vaultwarden()`
//! knowledge: divergence is caught by tests, not prevented by a shared type.
//!
//! **What is ported and what is not.** `records()`/`generate()` below are a
//! line-by-line translation of the Swift methods of the same name — same
//! ordering, same dedup, same conditionals. `MailContext` itself is NOT
//! ported: `Input` below carries only the handful of values
//! `DNSRecordGenerator` actually reads out of it (domain/hostname/ptr
//! hostname/mail domains/raw per-service hostnames/topology/language/entry
//! point address/scope/hasMail) — everything else `MailContext` computes
//! (`ServiceContext`, `additionalServices`, firewall ports, …) belongs to
//! service catalog generation, a different and much larger Ф4 slice.

use crate::dns_l10n as l10n;

// MARK: - Language

/// Mirrors Swift's `AppLanguage` — same nine codes, same fallback-to-English
/// `pick`. Defined here (not shared) for the reasons in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    En,
    De,
    Fr,
    Es,
    Ru,
    Uk,
    It,
    Ja,
    Zh,
}

// MARK: - Records

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Mx,
    Txt,
}

impl RecordType {
    fn raw(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Mx => "MX",
            RecordType::Txt => "TXT",
        }
    }
}

/// A single DNS record — a port of `gryonixNexusCore`'s `DNSRecord`.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub r#type: RecordType,
    pub value: String,
    pub priority: Option<u16>,
    pub comment: Option<String>,
}

/// A rendered artifact — a port of the subset of `gryonixNexusCore`'s
/// `Artifact` this generator produces (`.dnsRecord` kind, no server, no
/// suggested path — those fields are ServerControl/App concerns that do not
/// exist on this side of the fence yet).
#[derive(Debug, Clone)]
pub struct DnsArtifact {
    pub file_name: String,
    pub contents: String,
    pub summary: String,
}

/// The entry point's public address — a port of `NetworkAddress`, reduced to
/// what `DNSRecordGenerator` reads (`.value`, `.isIPv4`).
#[derive(Debug, Clone)]
pub struct PublicAddress {
    pub value: String,
    pub is_ipv4: bool,
}

/// Everything `DNSRecordGenerator.records(in:)`/`.generate(in:)` read out of
/// `MailContext`, and nothing else — see the module doc for why `MailContext`
/// itself is not ported.
#[derive(Debug, Clone)]
pub struct Input {
    /// `context.domainName`.
    pub domain_name: String,
    /// `context.additionalDomainNames` — already deduplicated, primary
    /// excluded, exactly as the Swift property guarantees.
    pub additional_domain_names: Vec<String>,
    /// `context.hostname` — the mail host.
    pub hostname: String,
    /// `context.ptrHostname`.
    pub ptr_hostname: String,
    /// Raw, PRE-mirroring hostnames from
    /// `context.allSelectedServices.flatMap { $0.dnsHostnames(...) }` — the
    /// mirroring itself (`context.mirroredHostnames(of:)`) is redone here in
    /// `mirrored_hostnames`, the same function both the mail-host branch and
    /// the service-hostname branch call on the Swift side.
    pub service_hostnames: Vec<String>,
    /// `context.input.topology == .singleHost`.
    pub single_host: bool,
    pub language: Language,
    /// `context.entryPoint?.publicAddress` — `None` when there is no entry
    /// point or it has no public address, the same guard Swift's `guard let`
    /// performs before doing anything else.
    pub public_address: Option<PublicAddress>,
    /// `context.isLocalOnly`.
    pub is_local_only: bool,
    /// `context.hasMail`.
    pub has_mail: bool,
}

impl Input {
    /// `context.mailDomainNames`: the primary domain plus every additional
    /// one, in that order.
    pub fn mail_domain_names(&self) -> Vec<String> {
        let mut names = vec![self.domain_name.clone()];
        names.extend(self.additional_domain_names.iter().cloned());
        names
    }

    /// `context.mirroredHostnames(of:)`: only names that sit under the
    /// primary domain get mirrored onto the additional ones — a service
    /// pointed at a hostname of its own has nothing to do with this
    /// deployment's domains and is left alone.
    fn mirrored_hostnames(&self, hostname: &str) -> Vec<String> {
        let suffix = format!(".{}", self.domain_name);
        let Some(prefix) = hostname.strip_suffix(&suffix) else {
            return Vec::new();
        };
        self.additional_domain_names.iter().map(|d| format!("{prefix}.{d}")).collect()
    }
}

/// Structured records for DNSProvider implementations — a port of
/// `DNSRecordGenerator.records(in:)`.
pub fn records(input: &Input) -> Vec<DnsRecord> {
    // Local-only deployments are reached by LAN address, not by a resolvable
    // name — there is nothing here to publish.
    if input.is_local_only {
        return Vec::new();
    }
    let Some(public_address) = &input.public_address else {
        return Vec::new();
    };
    let hostname = &input.hostname;
    let address_type = if public_address.is_ipv4 { RecordType::A } else { RecordType::Aaaa };
    let language = input.language;
    let single_host = input.single_host;

    // The mail host answers on the alias domains too: its Caddy site is
    // written as `mail.<domain>, mail.<alias>` like every other service's.
    // Without the mirrored A records Caddy asks ACME for a name that does not
    // resolve — issuance fails for good, the retry loop burns the
    // deployment's Let's Encrypt failure quota, and the name never serves.
    // Mailcow declares no `dnsHostnames`, so the mirroring further down never
    // reaches it; it has to happen here.
    let mail_hostnames: Vec<String> = if input.has_mail {
        let mut names = vec![hostname.clone()];
        names.extend(input.mirrored_hostnames(hostname));
        names
    } else {
        Vec::new()
    };

    let mut records: Vec<DnsRecord> = Vec::new();
    if input.has_mail {
        for mail_hostname in &mail_hostnames {
            records.push(DnsRecord {
                name: mail_hostname.clone(),
                r#type: address_type,
                value: public_address.value.clone(),
                priority: None,
                comment: Some(l10n::dns_mail_host_comment(language, single_host)),
            });
        }
        // Every mail domain gets the same treatment: they all deliver to
        // this one mail host, each with its own DKIM key.
        for mail_domain in input.mail_domain_names() {
            records.push(DnsRecord {
                name: mail_domain.clone(),
                r#type: RecordType::Mx,
                value: hostname.clone(),
                priority: Some(10),
                comment: Some(l10n::dns_mx_comment(language, hostname)),
            });
            records.push(DnsRecord {
                name: mail_domain.clone(),
                r#type: RecordType::Txt,
                value: "v=spf1 mx -all".to_string(),
                priority: None,
                comment: Some(l10n::dns_spf_comment(language)),
            });
            records.push(DnsRecord {
                name: format!("_dmarc.{mail_domain}"),
                r#type: RecordType::Txt,
                value: format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{mail_domain}"),
                priority: None,
                comment: Some(l10n::dns_dmarc_comment(language)),
            });
        }
    }

    // Forward record for the PTR target (FCrDNS: PTR → name → same IP). Part
    // of the basic server setup, mail or not; only when the name lives in
    // this zone and isn't the mail host itself.
    let ptr_hostname = &input.ptr_hostname;
    if (ptr_hostname != hostname || !input.has_mail)
        && ptr_hostname.ends_with(&format!(".{}", input.domain_name))
    {
        records.push(DnsRecord {
            name: ptr_hostname.clone(),
            r#type: address_type,
            value: public_address.value.clone(),
            priority: None,
            comment: Some(l10n::ptr_forward_comment(language)),
        });
    }

    // User-facing service hostnames (vault.*, cloud.*, photos.*, or manually
    // entered) — same public IP, proxied by Caddy. Each service hostname
    // also answers on every additional domain, so those names need their own
    // A records. Anything already emitted as a mail host (primary or
    // mirrored) is skipped rather than duplicated.
    //
    // A BTreeSet both dedups AND sorts lexicographically by UTF-8 bytes,
    // which for the ASCII hostnames this generator ever sees is the same
    // ordering as Swift's default `String <` — matching `Set(...).sorted()`.
    let mut service_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for raw in &input.service_hostnames {
        service_set.insert(raw.clone());
        for mirrored in input.mirrored_hostnames(raw) {
            service_set.insert(mirrored);
        }
    }
    let service_hostnames: Vec<String> =
        service_set.into_iter().filter(|h| h != hostname && !mail_hostnames.contains(h)).collect();
    let service_comment = l10n::dns_service_hosts_comment(language, single_host);
    for service_hostname in &service_hostnames {
        records.push(DnsRecord {
            name: service_hostname.clone(),
            r#type: address_type,
            value: public_address.value.clone(),
            priority: None,
            comment: Some(service_comment.clone()),
        });
    }
    records
}

// MARK: - File names / zone membership

/// Public because a future caller needs to find these among generated
/// files — matching on extension broke silently the moment this one
/// changed (see GOTCHAS.md and the identical note on the Swift side).
pub fn zone_file_name(domain: &str) -> String {
    format!("{domain}-dns-zone.txt")
}

pub fn csv_file_name(domain: &str) -> String {
    format!("{domain}-dns-records.csv")
}

const ZONE_TTL: u32 = 3600;

/// Which zone a record belongs to — a port of `DNSRecordGenerator.zone(of:among:)`.
/// A BIND zone file describes exactly ONE zone, so with additional domains
/// the records MUST be split. The longest match wins, so a domain that is
/// itself a subdomain of another still gets its own records.
pub fn zone_of(record: &DnsRecord, domains: &[String]) -> Option<String> {
    domains
        .iter()
        .filter(|d| record.name == **d || record.name.ends_with(&format!(".{d}")))
        .max_by_key(|d| d.len())
        .cloned()
}

// MARK: - Rendering

/// TXT rdata as a BIND zone file must spell it: quoted, and split into
/// several quoted strings once it exceeds one character-string — a port of
/// `bindTXTRData`. RFC 1035 caps a single character-string at 255 bytes, and
/// a strict parser (Cloudflare's zone import among them) rejects the file
/// outright when one is longer, which a 2048-bit DKIM key always is. The
/// parts are concatenated back by the resolver, so `"a" "b"` and `"ab"` mean
/// the same record.
fn bind_txt_rdata(value: &str, chunk_size: usize) -> String {
    fn quoted(part: &str) -> String {
        // Backslash first: escaping the quotes would otherwise be re-escaped.
        let escaped = part.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }
    let bytes = value.as_bytes();
    if bytes.len() <= chunk_size {
        return quoted(value);
    }
    let mut parts = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let mut end = (start + chunk_size).min(bytes.len());
        // DKIM/SPF data is ASCII in practice, but keep this safe against a
        // multi-byte boundary landing mid-character rather than panicking.
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(quoted(&value[start..end]));
        start = end;
    }
    parts.join(" ")
}

/// A port of `DNSRecordGenerator.render(_:)`.
fn render(record: &DnsRecord) -> String {
    let value = match record.r#type {
        RecordType::Txt => bind_txt_rdata(&record.value, 255),
        RecordType::Mx => format!("{}.", record.value),
        RecordType::A | RecordType::Aaaa => record.value.clone(),
    };
    let type_field = match record.priority {
        Some(priority) => format!("{} {priority}", record.r#type.raw()),
        None => record.r#type.raw().to_string(),
    };
    format!("{}.    IN {type_field}    {value}", record.name)
}

/// A port of `DNSRecordGenerator.renderZoneLine(_:)`: same as `render`, but
/// with an explicit TTL column.
fn render_zone_line(record: &DnsRecord) -> String {
    let value = match record.r#type {
        RecordType::Txt => bind_txt_rdata(&record.value, 255),
        RecordType::Mx => format!("{}.", record.value),
        RecordType::A | RecordType::Aaaa => record.value.clone(),
    };
    let type_field = match record.priority {
        Some(priority) => format!("{} {priority}", record.r#type.raw()),
        None => record.r#type.raw().to_string(),
    };
    format!("{}.    {ZONE_TTL}    IN {type_field}    {value}", record.name)
}

/// A port of `DNSRecordGenerator.renderCSVRow(_:)`: RFC4180 quoting.
fn render_csv_row(record: &DnsRecord) -> String {
    fn field(value: &str) -> String {
        if !value.contains(',') && !value.contains('"') && !value.contains('\n') {
            return value.to_string();
        }
        format!("\"{}\"", value.replace('"', "\"\""))
    }
    let priority = record.priority.map(|p| p.to_string()).unwrap_or_default();
    [record.r#type.raw().to_string(), record.name.clone(), record.value.clone(), ZONE_TTL.to_string(), priority]
        .iter()
        .map(|f| field(f))
        .collect::<Vec<_>>()
        .join(",")
}

/// A port of `DNSRecordGenerator.instructionBlock(for:domain:language:)`: the
/// same records spelled out field by field — Type / Name / Value / Priority /
/// TTL — plus the two things people get wrong most often: what exactly goes
/// in the "Name" box, and Cloudflare's proxy switch.
fn instruction_block(input: &Input, all_records: &[DnsRecord], domain: &str, language: Language) -> String {
    let mut block = vec![format!("; {}", l10n::dns_form_header(language)), ";".to_string()];
    let zones = input.mail_domain_names();
    // Grouped by zone: with several domains the records go into DIFFERENT
    // panels, and "@" means a different thing in each — listing them in one
    // flat run invites putting a record in the wrong zone.
    for zone_name in &zones {
        let owned: Vec<&DnsRecord> =
            all_records.iter().filter(|r| zone_of(r, &zones).as_deref() == Some(zone_name.as_str())).collect();
        if owned.is_empty() {
            continue;
        }
        if zones.len() > 1 {
            block.push(format!("; ===== {zone_name} ====="));
            block.push(";".to_string());
        }
        for record in owned {
            let full = &record.name;
            // Panels normally take the label only ("mail"), and "@" for the
            // zone's own name.
            let (name_field, hint) = if full == zone_name {
                ("@".to_string(), l10n::dns_root_name_hint(language, zone_name))
            } else if let Some(label) = full.strip_suffix(&format!(".{zone_name}")) {
                (label.to_string(), l10n::dns_name_hint(language, label, full))
            } else {
                (full.clone(), String::new())
            };
            block.push(format!(
                ";   {}: {}",
                l10n::dns_field_type(language),
                record.r#type.raw().to_uppercase()
            ));
            let hint_suffix = if hint.is_empty() { String::new() } else { format!("   — {hint}") };
            block.push(format!(";   {}: {name_field}{hint_suffix}", l10n::dns_field_name(language)));
            block.push(format!(";   {}: {}", l10n::dns_field_value(language), record.value));
            if let Some(priority) = record.priority {
                block.push(format!(";   {}: {priority}", l10n::dns_field_priority(language)));
            }
            block.push(format!(";   {}: {}", l10n::dns_field_ttl(language), l10n::dns_ttl_auto(language)));
            block.push(";".to_string());
        }
        if zones.len() > 1 {
            for line in l10n::dns_import_instructions(language, &zone_file_name(zone_name), &csv_file_name(zone_name))
                .split('\n')
            {
                block.push(format!("; {line}"));
            }
            block.push(";".to_string());
        }
    }
    block.push(format!("; {}", l10n::dns_cloudflare_proxy_warning(language)));
    block.push(";".to_string());
    if zones.len() == 1 {
        for line in l10n::dns_import_instructions(language, &zone_file_name(domain), &csv_file_name(domain)).split('\n')
        {
            block.push(format!("; {line}"));
        }
    }
    block.join("\n")
}

fn generate_zone_file(domain: &str, records: &[DnsRecord], language: Language) -> DnsArtifact {
    // This file is read by an IMPORTER, not by a person — see the identical
    // note on the Swift side for why comments are dropped and the extension
    // is `.txt`, not `.zone`.
    let lines: Vec<String> = records.iter().map(render_zone_line).collect();
    let header = format!(
        "; BIND zone file for {domain} - import this at your DNS provider.\n\
         ; SOA/NS are managed by the provider and are intentionally not included.\n\
         $ORIGIN {domain}.\n\
         $TTL {ZONE_TTL}"
    );
    let contents = format!("{header}\n{}\n", lines.join("\n"));
    DnsArtifact { file_name: zone_file_name(domain), contents, summary: l10n::dns_zone_summary(language) }
}

fn generate_csv(domain: &str, records: &[DnsRecord], language: Language) -> DnsArtifact {
    let mut lines = vec!["type,name,value,ttl,priority".to_string()];
    lines.extend(records.iter().map(render_csv_row));
    DnsArtifact { file_name: csv_file_name(domain), contents: lines.join("\n"), summary: l10n::dns_csv_summary(language) }
}

/// A port of `DNSRecordGenerator.generate(in:)`.
pub fn generate(input: &Input) -> Vec<DnsArtifact> {
    // No dns-records.txt, zone file, or CSV for local-only deployments —
    // there are no records to give a DNS provider in the first place.
    if input.is_local_only {
        return Vec::new();
    }
    let Some(public_address) = &input.public_address else {
        return Vec::new();
    };
    let domain = &input.domain_name;
    let language = input.language;
    let single_host = input.single_host;

    let all_records = records(input);

    // Consecutive records sharing a comment are grouped under one comment line.
    let mut lines: Vec<String> = Vec::new();
    let mut last_comment: Option<&str> = None;
    for record in &all_records {
        if let Some(comment) = &record.comment {
            if last_comment != Some(comment.as_str()) {
                lines.push(String::new());
                lines.push(format!("; {comment}"));
                last_comment = Some(comment.as_str());
            }
        }
        lines.push(render(record));
    }

    let header = format!("; {}\n; {}", l10n::dns_header_title(language, domain), l10n::dns_header_format(language));
    let mut contents = header;
    // The same records spelled out the way a provider's form asks for them.
    // The BIND syntax below is exact but unreadable to anyone who has not
    // seen a zone file, and "which box do I type this into" is where people
    // actually get stuck.
    contents.push_str("\n\n");
    contents.push_str(&instruction_block(input, &all_records, domain, language));
    contents.push('\n');
    contents.push('\n');
    contents.push_str(&lines.join("\n"));
    if input.has_mail {
        // DKIM cannot be emitted as a ready record: the key is generated on
        // the server. mailcow's API-provisioned key uses the "dkim"
        // selector — the record name must match what the report prints.
        let dkim_selector = "dkim";
        contents.push_str("\n\n");
        contents.push_str(&format!(
            "; {}\n; {dkim_selector}._domainkey.{domain}.    IN TXT    \"v=DKIM1; k=rsa; p=<{}>\"",
            l10n::dkim_comment(language),
            l10n::dkim_value_placeholder(language)
        ));
    }
    // PTR lives in the hoster's panel — a note for every setup, mail or not.
    contents.push_str("\n\n");
    contents.push_str(&format!(
        "; {}\n; {}",
        l10n::ptr_comment(language, single_host),
        l10n::ptr_target_line(language, &public_address.value, &input.ptr_hostname)
    ));

    let mut artifacts = vec![DnsArtifact {
        file_name: "dns-records.txt".to_string(),
        contents,
        summary: if input.has_mail { l10n::dns_summary_mail(language) } else { l10n::dns_summary_services_only(language) },
    }];

    // One importable pair PER DOMAIN: a zone file covers a single zone by
    // definition, and providers import into one zone at a time.
    let zones = input.mail_domain_names();
    for zone_name in &zones {
        let owned: Vec<DnsRecord> = all_records
            .iter()
            .filter(|r| zone_of(r, &zones).as_deref() == Some(zone_name.as_str()))
            .cloned()
            .collect();
        if owned.is_empty() {
            continue;
        }
        artifacts.push(generate_zone_file(zone_name, &owned, language));
        artifacts.push(generate_csv(zone_name, &owned, language));
    }
    artifacts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> Input {
        Input {
            domain_name: "example.com".to_string(),
            additional_domain_names: Vec::new(),
            hostname: "mail.example.com".to_string(),
            ptr_hostname: "relay.example.com".to_string(),
            service_hostnames: Vec::new(),
            single_host: true,
            language: Language::En,
            public_address: Some(PublicAddress { value: "203.0.113.10".to_string(), is_ipv4: true }),
            is_local_only: false,
            has_mail: true,
        }
    }

    #[test]
    fn local_only_produces_no_records_and_no_artifacts() {
        let mut input = base_input();
        input.is_local_only = true;
        assert!(records(&input).is_empty());
        assert!(generate(&input).is_empty());
    }

    #[test]
    fn no_entry_point_address_produces_nothing_either() {
        let mut input = base_input();
        input.public_address = None;
        assert!(records(&input).is_empty());
        assert!(generate(&input).is_empty());
    }

    #[test]
    fn mail_off_still_emits_a_ptr_forward_record() {
        let mut input = base_input();
        input.has_mail = false;
        let recs = records(&input);
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(recs[0].name, "relay.example.com");
        assert_eq!(recs[0].r#type, RecordType::A);
    }

    #[test]
    fn address_records_are_not_duplicated_when_a_service_reuses_the_mail_host_name() {
        let mut input = base_input();
        input.service_hostnames = vec!["mail.example.com".to_string(), "vault.example.com".to_string()];
        let recs = records(&input);
        let names: Vec<&str> = recs.iter().filter(|r| r.r#type == RecordType::A).map(|r| r.name.as_str()).collect();
        assert_eq!(names.iter().filter(|n| **n == "mail.example.com").count(), 1);
        assert!(names.contains(&"vault.example.com"));
    }

    #[test]
    fn zone_file_and_csv_names_match_the_documented_contract() {
        assert_eq!(zone_file_name("example.com"), "example.com-dns-zone.txt");
        assert_eq!(csv_file_name("example.com"), "example.com-dns-records.csv");
    }

    #[test]
    fn zone_of_picks_the_longest_matching_domain() {
        let record = DnsRecord {
            name: "mail.a.example.com".to_string(),
            r#type: RecordType::A,
            value: "1.2.3.4".to_string(),
            priority: None,
            comment: None,
        };
        let domains = vec!["example.com".to_string(), "a.example.com".to_string()];
        assert_eq!(zone_of(&record, &domains), Some("a.example.com".to_string()));
    }

    #[test]
    fn a_long_txt_value_is_chunked_at_255_bytes_and_rejoins_without_a_separator_char() {
        let long = "p".repeat(300);
        let record = DnsRecord {
            name: "example.com".to_string(),
            r#type: RecordType::Txt,
            value: format!("v=DKIM1; k=rsa; p={long}"),
            priority: None,
            comment: None,
        };
        let line = render_zone_line(&record);
        // Two quoted chunks: the raw value is under 255 bytes for a while
        // then goes over, matching bindTXTRData's chunking rule.
        assert_eq!(line.matches('"').count(), 4, "{line}");
    }

    #[test]
    fn csv_quoting_follows_rfc4180_only_when_needed() {
        let plain = DnsRecord {
            name: "example.com".to_string(),
            r#type: RecordType::Txt,
            value: "v=spf1 mx -all".to_string(),
            priority: None,
            comment: None,
        };
        assert_eq!(render_csv_row(&plain), "TXT,example.com,v=spf1 mx -all,3600,");
        let needs_quoting = DnsRecord {
            name: "example.com".to_string(),
            r#type: RecordType::Txt,
            value: "a,\"b\"".to_string(),
            priority: None,
            comment: None,
        };
        assert_eq!(render_csv_row(&needs_quoting), "TXT,example.com,\"a,\"\"b\"\"\",3600,");
    }

    #[test]
    fn mirrored_hostnames_are_empty_for_a_name_outside_the_primary_domain() {
        let mut input = base_input();
        input.additional_domain_names = vec!["example.org".to_string()];
        assert!(input.mirrored_hostnames("files.company.net").is_empty());
        assert_eq!(input.mirrored_hostnames("vault.example.com"), vec!["vault.example.org".to_string()]);
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the discipline
/// GOTCHAS.md spells out repeatedly (the `authorized_keys` test, the mailcow
/// DKIM glob, the DMS wrapper: harnesses that were green because they
/// checked a generator's own text, not what it actually produces). Ground
/// truth here is not a re-reading of `DNSRecordGenerator.swift` — it is that
/// file's ACTUAL output, dumped to `tests/fixtures/dns/` by a one-off XCTest
/// (`ZZZDNSFixtureDumpTests`, run once via `GRYONIXNEXUS_DNS_FIXTURE_DIR` —
/// the same `GRYONIXNEXUS_DUMP_DIR` mechanism `GeneratedScriptLintTests`
/// already uses — and not committed to the Swift side; only its fixture
/// output lives on here). If a fixture and this module's output ever
/// disagree, the working assumption is that the BUG IS IN THIS PORT: the
/// Swift side is the one this app has shipped.
///
/// Coverage: mail on/off, single-host vs relay topology, with and without
/// additional/mirrored domains, a custom PTR hostname, and four languages
/// (en/ru/ja/de/zh across the scenarios below) — proving the translation
/// table in `dns_l10n.rs` is not just English, without dumping all nine for
/// every combination. Local-only is covered by `local_only_produces_no_records_and_no_artifacts`
/// above instead of a fixture: the Swift side produces literally no DNS
/// artifact for it (`LocalOnlyDeploymentTests.testLocalOnlyProducesNoDNSArtifacts`),
/// so there is nothing to diff — "empty" is the whole fixture.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/dns/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn addr(value: &str) -> Option<PublicAddress> {
        Some(PublicAddress { value: value.to_string(), is_ipv4: true })
    }

    fn artifact<'a>(artifacts: &'a [DnsArtifact], name: &str) -> &'a DnsArtifact {
        artifacts.iter().find(|a| a.file_name == name).unwrap_or_else(|| panic!("no artifact named {name}"))
    }

    /// Single-host or relay, mail on or off, no additional domains, no
    /// services beyond the mail engine — the shape most of the matrix below
    /// shares.
    fn base(language: Language, single_host: bool, has_mail: bool, service_hostnames: &[&str], ptr_hostname: &str) -> Input {
        Input {
            domain_name: "example.com".to_string(),
            additional_domain_names: vec![],
            hostname: "mail.example.com".to_string(),
            ptr_hostname: ptr_hostname.to_string(),
            service_hostnames: service_hostnames.iter().map(|s| s.to_string()).collect(),
            single_host,
            language,
            public_address: addr("203.0.113.10"),
            is_local_only: false,
            has_mail,
        }
    }

    /// Additional domains `example.org`/`example.net`, mail on, and a full
    /// service shelf (mailcow + vaultwarden + nextcloud + immich + forgejo +
    /// gitlab + amneziaWG, the same set `GeneratedScriptLintTests`'
    /// multidomain variant uses) — exercises the per-zone splitting in
    /// `instruction_block`/`generate` (three zone files, three CSVs) and the
    /// mirrored service hostnames together.
    fn multidomain(language: Language, single_host: bool) -> Input {
        Input {
            domain_name: "example.com".to_string(),
            additional_domain_names: vec!["example.org".to_string(), "example.net".to_string()],
            hostname: "mail.example.com".to_string(),
            ptr_hostname: "relay.example.com".to_string(),
            service_hostnames: ["cloud.example.com", "vault.example.com", "photos.example.com", "git.example.com", "gitlab.example.com", "vpn.example.com"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            single_host,
            language,
            public_address: addr("203.0.113.10"),
            is_local_only: false,
            has_mail: true,
        }
    }

    /// Asserts every artifact `generate` produced for `input` matches the
    /// fixture file `<prefix>__<file_name>` byte for byte, and that no
    /// artifact the fixture set expects is missing.
    fn assert_parity(input: &Input, prefix: &str, expected_file_names: &[&str]) {
        let artifacts = generate(input);
        assert_eq!(
            artifacts.len(),
            expected_file_names.len(),
            "{prefix}: artifact count mismatch — got {:?}",
            artifacts.iter().map(|a| &a.file_name).collect::<Vec<_>>()
        );
        for file_name in expected_file_names {
            assert_eq!(
                artifact(&artifacts, file_name).contents,
                fixture(&format!("{prefix}__{file_name}")),
                "{prefix}__{file_name}: Rust output does not match the real Swift-generated fixture"
            );
        }
    }

    const SINGLE_DOMAIN_FILES: &[&str] =
        &["dns-records.txt", "example.com-dns-zone.txt", "example.com-dns-records.csv"];

    #[test]
    fn bare_a_en_mail_off_no_services() {
        assert_parity(&base(Language::En, true, false, &[], "relay.example.com"), "bare-A-en", SINGLE_DOMAIN_FILES);
    }

    #[test]
    fn bare_a_de_mail_off_no_services_german() {
        assert_parity(&base(Language::De, true, false, &[], "relay.example.com"), "bare-A-de", SINGLE_DOMAIN_FILES);
    }

    #[test]
    fn mailcow_a_en_single_host() {
        assert_parity(&base(Language::En, true, true, &[], "relay.example.com"), "mailcow-A-en", SINGLE_DOMAIN_FILES);
    }

    #[test]
    fn mailcow_a_ru_single_host_russian() {
        assert_parity(&base(Language::Ru, true, true, &[], "relay.example.com"), "mailcow-A-ru", SINGLE_DOMAIN_FILES);
    }

    #[test]
    fn mailcow_a_ja_single_host_japanese() {
        assert_parity(&base(Language::Ja, true, true, &[], "relay.example.com"), "mailcow-A-ja", SINGLE_DOMAIN_FILES);
    }

    #[test]
    fn mailcow_b_en_relay_topology() {
        assert_parity(&base(Language::En, false, true, &[], "relay.example.com"), "mailcow-B-en", SINGLE_DOMAIN_FILES);
    }

    #[test]
    fn nomail_b_en_relay_topology_with_services() {
        assert_parity(
            &base(Language::En, false, false, &["vault.example.com", "cloud.example.com"], "relay.example.com"),
            "nomail-B-en",
            SINGLE_DOMAIN_FILES,
        );
    }

    #[test]
    fn nomail_b_ru_relay_topology_with_services_russian() {
        assert_parity(
            &base(Language::Ru, false, false, &["vault.example.com", "cloud.example.com"], "relay.example.com"),
            "nomail-B-ru",
            SINGLE_DOMAIN_FILES,
        );
    }

    #[test]
    fn customptr_a_en_custom_reverse_dns_hostname() {
        assert_parity(&base(Language::En, true, true, &[], "out.example.com"), "customptr-A-en", SINGLE_DOMAIN_FILES);
    }

    const MULTIDOMAIN_FILES: &[&str] = &[
        "dns-records.txt",
        "example.com-dns-zone.txt",
        "example.com-dns-records.csv",
        "example.org-dns-zone.txt",
        "example.org-dns-records.csv",
        "example.net-dns-zone.txt",
        "example.net-dns-records.csv",
    ];

    #[test]
    fn multidomain_a_en_single_host_full_shelf() {
        assert_parity(&multidomain(Language::En, true), "multidomain-A-en", MULTIDOMAIN_FILES);
    }

    #[test]
    fn multidomain_b_zh_relay_topology_full_shelf_chinese() {
        assert_parity(&multidomain(Language::Zh, false), "multidomain-B-zh", MULTIDOMAIN_FILES);
    }
}
