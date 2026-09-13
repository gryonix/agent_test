//! Compiled-in translation tables for the subset of `dns-records.txt` text —
//! a DELIBERATE line-by-line port of the DNS-relevant functions in the
//! Swift side's `Packages/gryonixNexus/Sources/MailRecipe/Localization/
//! L10nGeneration.swift` (a 916-line file; only the ~26 functions
//! `DNSRecordGenerator` actually calls are ported here, not the whole file).
//!
//! This is the SAME pattern the project already uses for the
//! `GRYONIXNEXUS_STEP`/`REPORT` markers, which live independently in both
//! `MailRecipe` and `ServerControl` and are pinned by tests on BOTH sides
//! rather than shared (see ARCHITECTURE.md's "Маркеры установки" note): the
//! Rust binary is a self-contained musl build with zero awareness of Swift
//! packages, and `MailRecipe` has zero awareness of Rust, so there is no
//! direction in which a shared dependency could go. Divergence is caught by
//! `tests/dns_parity.rs`, which compares this module's output against real
//! Swift-generated fixtures byte-for-byte — the same enforcement mechanism
//! `dkim.rs`'s module doc points at for its own three-way duplication.

use crate::dns_records::Language;

/// Resolves a translation table, falling back to English — a port of
/// `AppLanguage.pick`.
fn pick(language: Language, table: &[(Language, &str)]) -> String {
    table
        .iter()
        .find(|(l, _)| *l == language)
        .or_else(|| table.iter().find(|(l, _)| *l == Language::En))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

use Language::{De, En, Es, Fr, It, Ja, Ru, Uk, Zh};

pub fn dns_mail_host_comment(l: Language, single_host: bool) -> String {
    if single_host {
        pick(l, &[
            (En, "The mail host points at the server's public IP."),
            (De, "Der Mail-Host zeigt auf die öffentliche IP des Servers."),
            (Fr, "L'hôte de messagerie pointe vers l'IP publique du serveur."),
            (Es, "El host de correo apunta a la IP pública del servidor."),
            (Ru, "Почтовый хост указывает на публичный IP сервера."),
            (Uk, "Поштовий хост вказує на публічний IP сервера."),
            (It, "L'host di posta punta all'IP pubblico del server."),
            (Ja, "メールホストはサーバーのパブリック IP を指します。"),
            (Zh, "邮件主机指向服务器的公网 IP。"),
        ])
    } else {
        pick(l, &[
            (En, "The mail host points at the VPS's public IP."),
            (De, "Der Mail-Host zeigt auf die öffentliche IP des VPS."),
            (Fr, "L'hôte de messagerie pointe vers l'IP publique du VPS."),
            (Es, "El host de correo apunta a la IP pública del VPS."),
            (Ru, "Почтовый хост указывает на публичный IP VPS."),
            (Uk, "Поштовий хост вказує на публічний IP VPS."),
            (It, "L'host di posta punta all'IP pubblico del VPS."),
            (Ja, "メールホストは VPS のパブリック IP を指します。"),
            (Zh, "邮件主机指向 VPS 的公网 IP。"),
        ])
    }
}

pub fn dns_mx_comment(l: Language, hostname: &str) -> String {
    pick(l, &[
        (En, "Mail for the domain is received by host {H}."),
        (De, "E-Mails der Domain nimmt der Host {H} entgegen."),
        (Fr, "Le courrier du domaine est reçu par l'hôte {H}."),
        (Es, "El correo del dominio lo recibe el host {H}."),
        (Ru, "Почта домена принимается хостом {H}."),
        (Uk, "Пошту домену приймає хост {H}."),
        (It, "La posta del dominio è ricevuta dall'host {H}."),
        (Ja, "ドメイン宛のメールはホスト {H} が受信します。"),
        (Zh, "该域名的邮件由主机 {H} 接收。"),
    ])
    .replace("{H}", hostname)
}

pub fn dns_spf_comment(l: Language) -> String {
    pick(l, &[
        (En, "SPF: only the MX host may send mail for the domain."),
        (De, "SPF: Nur der MX-Host darf E-Mails für die Domain senden."),
        (Fr, "SPF : seul l'hôte MX peut envoyer du courrier pour le domaine."),
        (Es, "SPF: solo el host del MX puede enviar correo del dominio."),
        (Ru, "SPF: отправлять почту домена может только хост из MX."),
        (Uk, "SPF: надсилати пошту домену може лише хост із MX."),
        (It, "SPF: solo l'host MX può inviare posta per il dominio."),
        (Ja, "SPF: ドメインのメールを送信できるのは MX のホストのみです。"),
        (Zh, "SPF：只有 MX 主机可以发送该域名的邮件。"),
    ])
}

pub fn dns_dmarc_comment(l: Language) -> String {
    pick(l, &[
        (En, "DMARC: mail failing SPF/DKIM goes to quarantine; reports go to postmaster."),
        (De, "DMARC: E-Mails ohne SPF/DKIM kommen in Quarantäne, Berichte gehen an postmaster."),
        (Fr, "DMARC : les messages sans SPF/DKIM vont en quarantaine, rapports envoyés à postmaster."),
        (Es, "DMARC: el correo sin SPF/DKIM va a cuarentena; los informes, a postmaster."),
        (Ru, "DMARC: письма без SPF/DKIM — в карантин, отчёты на postmaster."),
        (Uk, "DMARC: листи без SPF/DKIM — у карантин, звіти на postmaster."),
        (It, "DMARC: la posta senza SPF/DKIM va in quarantena, i report a postmaster."),
        (Ja, "DMARC: SPF/DKIM に失敗したメールは隔離され、レポートは postmaster に送られます。"),
        (Zh, "DMARC：未通过 SPF/DKIM 的邮件进入隔离区，报告发送至 postmaster。"),
    ])
}

pub fn dns_service_hosts_comment(l: Language, single_host: bool) -> String {
    if single_host {
        pick(l, &[
            (En, "Service hostnames — the same public IP of the server (proxied by Caddy)."),
            (De, "Dienst-Hostnamen — dieselbe öffentliche IP des Servers (Caddy als Proxy)."),
            (Fr, "Noms d'hôte des services — la même IP publique du serveur (proxy Caddy)."),
            (Es, "Nombres de host de los servicios: la misma IP pública del servidor (con proxy Caddy)."),
            (Ru, "Хостнеймы сервисов — тот же публичный IP сервера (проксирует Caddy)."),
            (Uk, "Хостнейми сервісів — той самий публічний IP сервера (проксіює Caddy)."),
            (It, "Hostname dei servizi — lo stesso IP pubblico del server (proxy Caddy)."),
            (Ja, "サービスのホスト名 — サーバーの同じパブリック IP（Caddy がプロキシ）。"),
            (Zh, "服务主机名 —— 与服务器相同的公网 IP（由 Caddy 代理）。"),
        ])
    } else {
        pick(l, &[
            (En, "Service hostnames — the same public IP of the VPS (proxied by Caddy)."),
            (De, "Dienst-Hostnamen — dieselbe öffentliche IP des VPS (Caddy als Proxy)."),
            (Fr, "Noms d'hôte des services — la même IP publique du VPS (proxy Caddy)."),
            (Es, "Nombres de host de los servicios: la misma IP pública del VPS (con proxy Caddy)."),
            (Ru, "Хостнеймы сервисов — тот же публичный IP VPS (проксирует Caddy)."),
            (Uk, "Хостнейми сервісів — той самий публічний IP VPS (проксіює Caddy)."),
            (It, "Hostname dei servizi — lo stesso IP pubblico del VPS (proxy Caddy)."),
            (Ja, "サービスのホスト名 — VPS の同じパブリック IP（Caddy がプロキシ）。"),
            (Zh, "服务主机名 —— 与 VPS 相同的公网 IP（由 Caddy 代理）。"),
        ])
    }
}

pub fn dns_header_title(l: Language, domain: &str) -> String {
    pick(l, &[
        (En, "DNS records for {D} — add them at your DNS provider."),
        (De, "DNS-Einträge für {D} — fügen Sie sie bei Ihrem DNS-Anbieter hinzu."),
        (Fr, "Enregistrements DNS pour {D} — à ajouter chez votre fournisseur DNS."),
        (Es, "Registros DNS para {D}: añádalos en su proveedor de DNS."),
        (Ru, "DNS-записи для {D} — добавьте у вашего DNS-провайдера."),
        (Uk, "DNS-записи для {D} — додайте у вашого DNS-провайдера."),
        (It, "Record DNS per {D} — aggiungili presso il tuo provider DNS."),
        (Ja, "{D} の DNS レコード — DNS プロバイダーに追加してください。"),
        (Zh, "{D} 的 DNS 记录 —— 请在您的 DNS 服务商处添加。"),
    ])
    .replace("{D}", domain)
}

pub fn dns_header_format(l: Language) -> String {
    pick(l, &[
        (En, "Format: name  type  value"),
        (De, "Format: Name  Typ  Wert"),
        (Fr, "Format : nom  type  valeur"),
        (Es, "Formato: nombre  tipo  valor"),
        (Ru, "Формат: имя  тип  значение"),
        (Uk, "Формат: ім'я  тип  значення"),
        (It, "Formato: nome  tipo  valore"),
        (Ja, "形式: 名前  種別  値"),
        (Zh, "格式：名称  类型  值"),
    ])
}

pub fn dkim_comment(l: Language) -> String {
    pick(l, &[
        (En, "DKIM: the setup script prints the value in its report (the key is generated on the server)."),
        (De, "DKIM: Das Setup-Skript gibt den Wert im Bericht aus (der Schlüssel wird auf dem Server erzeugt)."),
        (Fr, "DKIM : le script d'installation affiche la valeur dans son rapport (la clé est générée sur le serveur)."),
        (Es, "DKIM: el script de instalación muestra el valor en su informe (la clave se genera en el servidor)."),
        (Ru, "DKIM: значение выведет setup-скрипт в отчёте (ключ генерируется на сервере)."),
        (Uk, "DKIM: значення виведе setup-скрипт у звіті (ключ генерується на сервері)."),
        (It, "DKIM: lo script di setup stampa il valore nel report (la chiave è generata sul server)."),
        (Ja, "DKIM: 値はセットアップスクリプトがレポートに出力します（鍵はサーバー上で生成されます）。"),
        (Zh, "DKIM：该值由安装脚本在报告中输出（密钥在服务器上生成）。"),
    ])
}

/// Placeholder inside the sample DKIM TXT line: p=<...>.
pub fn dkim_value_placeholder(l: Language) -> String {
    pick(l, &[
        (En, "from the setup script report"),
        (De, "aus dem Bericht des Setup-Skripts"),
        (Fr, "du rapport du script d'installation"),
        (Es, "del informe del script de instalación"),
        (Ru, "из отчёта setup-скрипта"),
        (Uk, "зі звіту setup-скрипта"),
        (It, "dal report dello script di setup"),
        (Ja, "セットアップスクリプトのレポートから"),
        (Zh, "来自安装脚本报告"),
    ])
}

pub fn ptr_comment(l: Language, single_host: bool) -> String {
    if single_host {
        pick(l, &[
            (En, "PTR (reverse DNS) is configured NOT here but in the server provider's panel:"),
            (De, "Der PTR-Eintrag (Reverse DNS) wird NICHT hier konfiguriert, sondern im Panel des Server-Anbieters:"),
            (Fr, "Le PTR (DNS inverse) se configure NON PAS ici, mais dans le panneau du fournisseur du serveur :"),
            (Es, "El PTR (DNS inverso) NO se configura aquí, sino en el panel del proveedor del servidor:"),
            (Ru, "PTR (обратный DNS) настраивается НЕ здесь, а в панели провайдера сервера:"),
            (Uk, "PTR (зворотний DNS) налаштовується НЕ тут, а в панелі провайдера сервера:"),
            (It, "Il PTR (DNS inverso) NON si configura qui, ma nel pannello del provider del server:"),
            (Ja, "PTR（逆引き DNS）はここではなく、サーバーのプロバイダーの管理画面で設定します:"),
            (Zh, "PTR（反向 DNS）不在此处配置，而是在服务器提供商的面板中设置："),
        ])
    } else {
        pick(l, &[
            (En, "PTR (reverse DNS) is configured NOT here but in the VPS provider's panel:"),
            (De, "Der PTR-Eintrag (Reverse DNS) wird NICHT hier konfiguriert, sondern im Panel des VPS-Anbieters:"),
            (Fr, "Le PTR (DNS inverse) se configure NON PAS ici, mais dans le panneau du fournisseur du VPS :"),
            (Es, "El PTR (DNS inverso) NO se configura aquí, sino en el panel del proveedor del VPS:"),
            (Ru, "PTR (обратный DNS) настраивается НЕ здесь, а в панели провайдера VPS:"),
            (Uk, "PTR (зворотний DNS) налаштовується НЕ тут, а в панелі провайдера VPS:"),
            (It, "Il PTR (DNS inverso) NON si configura qui, ma nel pannello del provider del VPS:"),
            (Ja, "PTR（逆引き DNS）はここではなく、VPS のプロバイダーの管理画面で設定します:"),
            (Zh, "PTR（反向 DNS）不在此处配置，而是在 VPS 提供商的面板中设置："),
        ])
    }
}

pub fn ptr_forward_comment(l: Language) -> String {
    pick(l, &[
        (En, "Forward record for the PTR hostname (reverse DNS must resolve back to the same IP)."),
        (De, "Vorwärts-Eintrag für den PTR-Hostnamen (Reverse DNS muss auf dieselbe IP zurückauflösen)."),
        (Fr, "Enregistrement direct pour le nom d'hôte PTR (le DNS inverse doit résoudre vers la même IP)."),
        (Es, "Registro directo para el nombre de host del PTR (el DNS inverso debe resolver a la misma IP)."),
        (Ru, "Прямая запись для PTR-хостнейма (обратный DNS должен резолвиться обратно в тот же IP)."),
        (Uk, "Прямий запис для PTR-хостнейму (зворотний DNS має резолвитися назад у ту саму IP)."),
        (It, "Record diretto per l'hostname del PTR (il DNS inverso deve risolvere sullo stesso IP)."),
        (Ja, "PTR ホスト名の正引きレコード（逆引き DNS は同じ IP に解決される必要があります）。"),
        (Zh, "PTR 主机名的正向记录（反向 DNS 必须解析回同一 IP）。"),
    ])
}

pub fn ptr_target_line(l: Language, ip: &str, hostname: &str) -> String {
    pick(l, &[
        (En, "{IP} -> {H} — critical for deliverability."),
        (De, "{IP} -> {H} — entscheidend für die Zustellbarkeit."),
        (Fr, "{IP} -> {H} — essentiel pour la délivrabilité."),
        (Es, "{IP} -> {H}: crítico para la entregabilidad."),
        (Ru, "{IP} -> {H} — критично для доставляемости."),
        (Uk, "{IP} -> {H} — критично для доставлюваності."),
        (It, "{IP} -> {H} — fondamentale per la deliverability."),
        (Ja, "{IP} -> {H} — 到達率に不可欠です。"),
        (Zh, "{IP} -> {H} —— 对送达率至关重要。"),
    ])
    .replace("{IP}", ip)
    .replace("{H}", hostname)
}

pub fn dns_summary_mail(l: Language) -> String {
    pick(l, &[
        (En, "DNS records (A, MX, SPF, DMARC + service hostnames) for the DNS provider's panel; DKIM is added after the key is generated on the server."),
        (De, "DNS-Einträge (A, MX, SPF, DMARC + Dienst-Hostnamen) für das Panel des DNS-Anbieters; DKIM wird hinzugefügt, nachdem der Schlüssel auf dem Server erzeugt wurde."),
        (Fr, "Enregistrements DNS (A, MX, SPF, DMARC + noms d'hôte des services) pour le panneau du fournisseur DNS ; DKIM s'ajoute après la génération de la clé sur le serveur."),
        (Es, "Registros DNS (A, MX, SPF, DMARC + nombres de host de servicios) para el panel del proveedor de DNS; DKIM se añade tras generar la clave en el servidor."),
        (Ru, "DNS-записи (A, MX, SPF, DMARC + хостнеймы сервисов) для панели DNS-провайдера; DKIM добавляется после генерации ключа на сервере."),
        (Uk, "DNS-записи (A, MX, SPF, DMARC + хостнейми сервісів) для панелі DNS-провайдера; DKIM додається після генерації ключа на сервері."),
        (It, "Record DNS (A, MX, SPF, DMARC + hostname dei servizi) per il pannello del provider DNS; DKIM si aggiunge dopo la generazione della chiave sul server."),
        (Ja, "DNS プロバイダーの管理画面用の DNS レコード（A、MX、SPF、DMARC + サービスのホスト名）。DKIM はサーバーで鍵を生成した後に追加します。"),
        (Zh, "用于 DNS 服务商面板的 DNS 记录（A、MX、SPF、DMARC + 服务主机名）；DKIM 在服务器上生成密钥后添加。"),
    ])
}

pub fn dns_summary_services_only(l: Language) -> String {
    pick(l, &[
        (En, "DNS records (A records for service hostnames) for the DNS provider's panel."),
        (De, "DNS-Einträge (A-Einträge der Dienst-Hostnamen) für das Panel des DNS-Anbieters."),
        (Fr, "Enregistrements DNS (enregistrements A des noms d'hôte des services) pour le panneau du fournisseur DNS."),
        (Es, "Registros DNS (registros A de los nombres de host de servicios) para el panel del proveedor de DNS."),
        (Ru, "DNS-записи (A-записи хостнеймов сервисов) для панели DNS-провайдера."),
        (Uk, "DNS-записи (A-записи хостнеймів сервісів) для панелі DNS-провайдера."),
        (It, "Record DNS (record A degli hostname dei servizi) per il pannello del provider DNS."),
        (Ja, "DNS プロバイダーの管理画面用の DNS レコード（サービスのホスト名の A レコード）。"),
        (Zh, "用于 DNS 服务商面板的 DNS 记录（服务主机名的 A 记录）。"),
    ])
}

pub fn dns_zone_summary(l: Language) -> String {
    pick(l, &[
        (En, "Standard BIND zone file with the same records — import it directly at most DNS providers."),
        (De, "Standard-BIND-Zonendatei mit denselben Einträgen — bei den meisten DNS-Anbietern direkt importierbar."),
        (Fr, "Fichier de zone BIND standard avec les mêmes enregistrements — importable directement chez la plupart des fournisseurs DNS."),
        (Es, "Archivo de zona BIND estándar con los mismos registros — importable directamente en la mayoría de proveedores de DNS."),
        (Ru, "Стандартный BIND zone-файл с теми же записями — импортируется напрямую у большинства DNS-провайдеров."),
        (Uk, "Стандартний BIND zone-файл із тими самими записами — імпортується напряму в більшості DNS-провайдерів."),
        (It, "File di zona BIND standard con gli stessi record — importabile direttamente presso la maggior parte dei provider DNS."),
        (Ja, "同じレコードを含む標準的な BIND ゾーンファイルです。多くの DNS プロバイダーで直接インポートできます。"),
        (Zh, "包含相同记录的标准 BIND 区域文件——可直接导入大多数 DNS 服务商。"),
    ])
}

pub fn dns_csv_summary(l: Language) -> String {
    pick(l, &[
        (En, "Generic CSV (type, name, value, ttl, priority) with the same records — for panels that prefer CSV import."),
        (De, "Generische CSV-Datei (type, name, value, ttl, priority) mit denselben Einträgen — für Panels, die CSV-Import bevorzugen."),
        (Fr, "Fichier CSV générique (type, name, value, ttl, priority) avec les mêmes enregistrements — pour les panneaux qui préfèrent l'import CSV."),
        (Es, "CSV genérico (type, name, value, ttl, priority) con los mismos registros — para paneles que prefieren la importación CSV."),
        (Ru, "Универсальный CSV (type, name, value, ttl, priority) с теми же записями — для панелей, которые предпочитают импорт CSV."),
        (Uk, "Універсальний CSV (type, name, value, ttl, priority) з тими самими записами — для панелей, які надають перевагу імпорту CSV."),
        (It, "CSV generico (type, name, value, ttl, priority) con gli stessi record — per i pannelli che preferiscono l'importazione CSV."),
        (Ja, "同じレコードを含む汎用 CSV（type, name, value, ttl, priority）です。CSV インポートを好む管理画面向けです。"),
        (Zh, "包含相同记录的通用 CSV（type, name, value, ttl, priority）——适用于偏好 CSV 导入的面板。"),
    ])
}

pub fn dns_form_header(l: Language) -> String {
    pick(l, &[
        (En, "WHAT TO ADD — one block below = one record in your provider's form"),
        (De, "WAS EINZUTRAGEN IST — ein Block unten = ein Eintrag im Formular Ihres Anbieters"),
        (Fr, "CE QU'IL FAUT AJOUTER — un bloc ci-dessous = un enregistrement dans le formulaire de votre fournisseur"),
        (Es, "QUÉ AÑADIR: cada bloque de abajo = un registro en el formulario de tu proveedor"),
        (Ru, "ЧТО ДОБАВИТЬ — один блок ниже = одна запись в форме вашего регистратора"),
        (Uk, "ЩО ДОДАТИ — один блок нижче = один запис у формі вашого реєстратора"),
        (It, "COSA AGGIUNGERE — ogni blocco sotto = un record nel modulo del tuo provider"),
        (Ja, "追加する内容 — 下の1ブロック = 事業者のフォームでの1レコード"),
        (Zh, "需要添加的内容 — 下面每个区块 = 服务商表单中的一条记录"),
    ])
}

pub fn dns_field_type(l: Language) -> String {
    pick(l, &[
        (En, "Type"), (De, "Typ"), (Fr, "Type"), (Es, "Tipo"), (Ru, "Тип"), (Uk, "Тип"),
        (It, "Tipo"), (Ja, "種類"), (Zh, "类型"),
    ])
}

pub fn dns_field_name(l: Language) -> String {
    pick(l, &[
        (En, "Name"), (De, "Name"), (Fr, "Nom"), (Es, "Nombre"), (Ru, "Имя"), (Uk, "Ім'я"),
        (It, "Nome"), (Ja, "名前"), (Zh, "名称"),
    ])
}

pub fn dns_field_value(l: Language) -> String {
    pick(l, &[
        (En, "Value"), (De, "Wert"), (Fr, "Valeur"), (Es, "Valor"), (Ru, "Значение"),
        (Uk, "Значення"), (It, "Valore"), (Ja, "値"), (Zh, "值"),
    ])
}

pub fn dns_field_priority(l: Language) -> String {
    pick(l, &[
        (En, "Priority"), (De, "Priorität"), (Fr, "Priorité"), (Es, "Prioridad"),
        (Ru, "Приоритет"), (Uk, "Пріоритет"), (It, "Priorità"), (Ja, "優先度"), (Zh, "优先级"),
    ])
}

pub fn dns_field_ttl(l: Language) -> String {
    pick(l, &[
        (En, "TTL"), (De, "TTL"), (Fr, "TTL"), (Es, "TTL"), (Ru, "TTL"), (Uk, "TTL"),
        (It, "TTL"), (Ja, "TTL"), (Zh, "TTL"),
    ])
}

pub fn dns_ttl_auto(l: Language) -> String {
    pick(l, &[
        (En, "Auto (or 3600)"), (De, "Auto (oder 3600)"), (Fr, "Auto (ou 3600)"),
        (Es, "Auto (o 3600)"), (Ru, "Авто (или 3600)"), (Uk, "Авто (або 3600)"),
        (It, "Auto (o 3600)"), (Ja, "自動（または 3600）"), (Zh, "自动（或 3600）"),
    ])
}

/// The single most common mistake: typing the full hostname where the panel
/// wants only the label, or a name where it wants "@".
pub fn dns_name_hint(l: Language, label: &str, full: &str) -> String {
    pick(l, &[
        (En, "most panels want just {L} — some want the full {F}"),
        (De, "die meisten Panels wollen nur {L} — manche das vollständige {F}"),
        (Fr, "la plupart des panneaux attendent seulement {L} — certains le nom complet {F}"),
        (Es, "la mayoría de los paneles piden solo {L}; algunos, el nombre completo {F}"),
        (Ru, "большинство панелей ждут просто {L} — некоторые полное {F}"),
        (Uk, "більшість панелей чекають просто {L} — деякі повне {F}"),
        (It, "la maggior parte dei pannelli vuole solo {L} — alcuni il nome completo {F}"),
        (Ja, "多くの管理画面では {L} だけ、一部では完全な {F} を入力します"),
        (Zh, "多数面板只需填 {L}，少数需要完整的 {F}"),
    ])
    .replace("{L}", label)
    .replace("{F}", full)
}

pub fn dns_root_name_hint(l: Language, domain: &str) -> String {
    pick(l, &[
        (En, "the domain itself — type @ (some panels want {D})"),
        (De, "die Domain selbst — geben Sie @ ein (manche Panels wollen {D})"),
        (Fr, "le domaine lui-même — saisissez @ (certains panneaux veulent {D})"),
        (Es, "el dominio en sí: escribe @ (algunos paneles piden {D})"),
        (Ru, "сам домен — впишите @ (некоторые панели хотят {D})"),
        (Uk, "сам домен — впишіть @ (деякі панелі хочуть {D})"),
        (It, "il dominio stesso — scrivi @ (alcuni pannelli vogliono {D})"),
        (Ja, "ドメイン自体 — @ と入力します（一部の画面では {D}）"),
        (Zh, "域名本身 — 填 @（部分面板需要 {D}）"),
    ])
    .replace("{D}", domain)
}

/// Cloudflare proxies HTTP by default; that breaks mail and every non-HTTP
/// service, so every record here must stay unproxied.
pub fn dns_cloudflare_proxy_warning(l: Language) -> String {
    pick(l, &[
        (En, "Cloudflare: set Proxy status to \"DNS only\" (grey cloud) for EVERY record here. The orange cloud breaks mail and the VPN."),
        (De, "Cloudflare: Setzen Sie den Proxy-Status bei JEDEM Eintrag hier auf „DNS only“ (graue Wolke). Die orange Wolke zerstört E-Mail und VPN."),
        (Fr, "Cloudflare : mettez le statut proxy sur « DNS only » (nuage gris) pour CHAQUE enregistrement ici. Le nuage orange casse la messagerie et le VPN."),
        (Es, "Cloudflare: pon el estado de proxy en «DNS only» (nube gris) en TODOS estos registros. La nube naranja rompe el correo y la VPN."),
        (Ru, "Cloudflare: у КАЖДОЙ записи здесь поставьте Proxy status = «DNS only» (серое облако). Оранжевое облако ломает почту и VPN."),
        (Uk, "Cloudflare: у КОЖНОГО запису тут поставте Proxy status = «DNS only» (сіра хмара). Помаранчева хмара ламає пошту та VPN."),
        (It, "Cloudflare: imposta Proxy status su «DNS only» (nuvola grigia) per OGNI record qui. La nuvola arancione rompe la posta e la VPN."),
        (Ja, "Cloudflare: ここのすべてのレコードで Proxy status を「DNS only」（灰色の雲）にしてください。オレンジの雲はメールと VPN を壊します。"),
        (Zh, "Cloudflare：请把这里每一条记录的 Proxy status 设为「DNS only」（灰色云朵）。橙色云朵会破坏邮件和 VPN。"),
    ])
}

/// Import instead of typing: Cloudflare (and most big providers) accept the
/// BIND zone file shipped alongside this one.
pub fn dns_import_instructions(l: Language, zone_file: &str, csv_file: &str) -> String {
    pick(l, &[
        (En, "IMPORT INSTEAD OF TYPING\nCloudflare: DNS → Records → \"Import and Export\" → \"Import DNS records\" → upload {Z}.\nThen check every imported record is \"DNS only\" (grey cloud).\nThe same {Z} works at Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nPanels that ask for a spreadsheet instead: use {C}."),
        (De, "IMPORTIEREN STATT TIPPEN\nCloudflare: DNS → Records → „Import and Export“ → „Import DNS records“ → {Z} hochladen.\nDanach prüfen, dass jeder importierte Eintrag auf „DNS only“ (graue Wolke) steht.\nDieselbe {Z} funktioniert bei Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nPanels, die eine Tabelle erwarten: {C} verwenden."),
        (Fr, "IMPORTER PLUTÔT QUE SAISIR\nCloudflare : DNS → Records → « Import and Export » → « Import DNS records » → envoyez {Z}.\nVérifiez ensuite que chaque enregistrement importé est en « DNS only » (nuage gris).\nLe même {Z} fonctionne chez Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nPour les panneaux qui attendent un tableur : {C}."),
        (Es, "IMPORTAR EN LUGAR DE ESCRIBIR\nCloudflare: DNS → Records → «Import and Export» → «Import DNS records» → sube {Z}.\nDespués comprueba que cada registro importado esté en «DNS only» (nube gris).\nEl mismo {Z} sirve en Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nPaneles que piden una hoja de cálculo: usa {C}."),
        (Ru, "ИМПОРТ ВМЕСТО РУЧНОГО ВВОДА\nCloudflare: DNS → Records → «Import and Export» → «Import DNS records» → загрузите {Z}.\nПосле импорта проверьте, что у каждой записи стоит «DNS only» (серое облако).\nТот же {Z} принимают Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nПанелям, которым нужна таблица, подойдёт {C}."),
        (Uk, "ІМПОРТ ЗАМІСТЬ РУЧНОГО ВВЕДЕННЯ\nCloudflare: DNS → Records → «Import and Export» → «Import DNS records» → завантажте {Z}.\nПісля імпорту перевірте, що в кожного запису стоїть «DNS only» (сіра хмара).\nТой самий {Z} приймають Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nПанелям, яким потрібна таблиця, підійде {C}."),
        (It, "IMPORTA INVECE DI DIGITARE\nCloudflare: DNS → Records → «Import and Export» → «Import DNS records» → carica {Z}.\nPoi verifica che ogni record importato sia su «DNS only» (nuvola grigia).\nLo stesso {Z} va bene su Route53, Google, Namecheap, GoDaddy, Gandi, Hetzner, deSEC, DNSimple, Porkbun.\nPer i pannelli che chiedono un foglio di calcolo: {C}."),
        (Ja, "手入力の代わりにインポート\nCloudflare: DNS → Records →「Import and Export」→「Import DNS records」→ {Z} をアップロード。\nその後、各レコードが「DNS only」（灰色の雲）になっているか確認してください。\n同じ {Z} は Route53、Google、Namecheap、GoDaddy、Gandi、Hetzner、deSEC、DNSimple、Porkbun でも使えます。\n表計算形式を求める管理画面には {C} を使ってください。"),
        (Zh, "用导入代替手动录入\nCloudflare：DNS → Records →「Import and Export」→「Import DNS records」→ 上传 {Z}。\n导入后请确认每条记录都是「DNS only」（灰色云朵）。\n同一个 {Z} 也适用于 Route53、Google、Namecheap、GoDaddy、Gandi、Hetzner、deSEC、DNSimple、Porkbun。\n需要表格的面板请使用 {C}。"),
    ])
    .replace("{Z}", zone_file)
    .replace("{C}", csv_file)
}
