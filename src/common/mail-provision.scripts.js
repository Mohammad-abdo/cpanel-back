/**
 * Phase 10C (TASK-034/035): pure generators for the mail stack provisioning scripts.
 *
 * Rules enforced here (and unit-tested):
 *  - Scripts are fixed text. Dynamic values (hostname, domain, selector, address) arrive as validated
 *    positional args ($1, $2...) and are never interpolated into the script text.
 *  - Secrets (mailbox passwords) arrive on STDIN only and are hashed ON THE SERVER with doveadm or
 *    openssl. They are never in script text, args, stdout or logs.
 *  - Virtual maps are plain files (postfix hash: maps + a Dovecot passwd-file), so there is no database
 *    dependency on the mail host and no SQL credentials to leak. Each mailbox change is one atomic file edit.
 *  - DKIM private keys are generated on the server (0600, owner opendkim). Only the public key is printed.
 *  - Ubuntu 22.04 / 24.04 (apt) only.
 */

export const SUPPORTED_OS = Object.freeze(['22.04', '24.04']);
export const MAIL_FIREWALL_PORTS = Object.freeze([25, 465, 587, 993]);
export const WEBMAIL_PORT = 2096;
export const SAFE_ARG = /^[A-Za-z0-9._@:-]{1,253}$/;
export const SAFE_SELECTOR = /^[a-z0-9]{1,32}$/;

export function assertSafeArgs(args) {
  for (const a of args) if (!SAFE_ARG.test(String(a))) throw new Error('Unsafe script argument');
  return args.map(String);
}

const lines = (...l) => `${['#!/usr/bin/env bash', 'set -euo pipefail', 'export DEBIAN_FRONTEND=noninteractive', ...l].join('\n')}\n`;

const PREFLIGHT_PROBE = lines(
  '. /etc/os-release 2>/dev/null || true',
  'echo "os_id=${ID:-unknown}"',
  'echo "os_version=${VERSION_ID:-unknown}"',
  'echo "is_root=$([ "$(id -u)" = 0 ] && echo yes || echo no)"',
  'for p in 25 465 587 993; do if ss -ltnH 2>/dev/null | awk -v p=":$p" \'$4 ~ p"$" {f=1} END{exit !f}\'; then echo "port_$p=in_use"; else echo "port_$p=free"; fi; done',
  'mta=none; for s in postfix exim4 sendmail; do if systemctl is-active --quiet "$s" 2>/dev/null; then mta=$s; fi; done; echo "existing_mta=$mta"',
  'for s in postfix dovecot opendkim rspamd; do if dpkg -s "$s" >/dev/null 2>&1; then echo "pkg_$s=installed"; else echo "pkg_$s=absent"; fi; done',
  'if command -v ufw >/dev/null 2>&1; then echo "ufw=$(ufw status 2>/dev/null | head -1 | awk \'{print tolower($2)}\')"; else echo "ufw=absent"; fi',
  'echo "disk_free_mb=$(df -Pm / | awk \'NR==2{print $4}\')"',
);

const STEP_SCRIPTS = {
  // $1 = mail hostname
  packages: lines(
    'echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections',
    'echo "postfix postfix/mailname string $1" | debconf-set-selections',
    'apt-get update -y',
    'apt-get install -y postfix dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved opendkim opendkim-tools rspamd fail2ban openssl ca-certificates',
    'id vmail >/dev/null 2>&1 || { groupadd -g 5000 vmail; useradd -g vmail -u 5000 -d /var/vmail -m -s /usr/sbin/nologin vmail; }',
    'mkdir -p /var/vmail && chown -R vmail:vmail /var/vmail && chmod 0750 /var/vmail',
    'echo "NT_RESULT stack_version=postfix:$(dpkg-query -W -f=\'${Version}\' postfix),dovecot:$(dpkg-query -W -f=\'${Version}\' dovecot-core)"',
  ),

  // $1 = mail hostname. Virtual maps are plain hash: files (no DB dependency).
  postfix: lines(
    'touch /etc/postfix/vdomains /etc/postfix/vmailbox /etc/postfix/valiases',
    'chmod 0640 /etc/postfix/vdomains /etc/postfix/vmailbox /etc/postfix/valiases',
    'postmap /etc/postfix/vdomains /etc/postfix/vmailbox /etc/postfix/valiases',
    'echo "$1" > /etc/mailname',
    'postconf -e "myhostname = $1" "myorigin = /etc/mailname" "mydestination = localhost" "mynetworks = 127.0.0.0/8 [::1]/128"',
    'postconf -e "inet_interfaces = all" "smtpd_banner = \\$myhostname ESMTP"',
    'postconf -e "virtual_mailbox_domains = hash:/etc/postfix/vdomains" "virtual_mailbox_maps = hash:/etc/postfix/vmailbox" "virtual_alias_maps = hash:/etc/postfix/valiases"',
    'postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"',
    // Relay hardening: never an open relay. Only SASL-authenticated clients may relay.
    'postconf -e "smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination"',
    'postconf -e "smtpd_recipient_restrictions = reject_non_fqdn_recipient, reject_unknown_recipient_domain, permit_sasl_authenticated, reject_unauth_destination"',
    'postconf -e "smtpd_sasl_type = dovecot" "smtpd_sasl_path = private/auth" "smtpd_sasl_auth_enable = no" "smtpd_sasl_security_options = noanonymous"',
    'postconf -e "smtpd_tls_cert_file = /etc/ssl/nt-mail/fullchain.pem" "smtpd_tls_key_file = /etc/ssl/nt-mail/privkey.pem"',
    'postconf -e "smtpd_tls_security_level = may" "smtp_tls_security_level = may" "smtpd_tls_auth_only = yes"',
    'postconf -e "smtpd_tls_protocols = >=TLSv1.2" "smtpd_tls_mandatory_protocols = >=TLSv1.2" "smtp_tls_protocols = >=TLSv1.2" "smtpd_tls_loglevel = 1"',
    'postconf -e "disable_vrfy_command = yes" "smtpd_helo_required = yes" "message_size_limit = 26214400"',
    'postconf -e "milter_default_action = accept" "milter_protocol = 6" "smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:11332" "non_smtpd_milters = inet:127.0.0.1:8891"',
    // master.cf: submission (587, STARTTLS) and smtps (465, implicit TLS) both REQUIRE auth + TLS.
    'cp -n /etc/postfix/master.cf /etc/postfix/master.cf.nt-orig',
    "sed -i '/^# NT-MAIL-BEGIN/,/^# NT-MAIL-END/d' /etc/postfix/master.cf",
    "cat >> /etc/postfix/master.cf <<'NTEOF'",
    '# NT-MAIL-BEGIN',
    'submission inet n - y - - smtpd',
    '  -o syslog_name=postfix/submission',
    '  -o smtpd_tls_security_level=encrypt',
    '  -o smtpd_sasl_auth_enable=yes',
    '  -o smtpd_tls_auth_only=yes',
    '  -o smtpd_client_restrictions=permit_sasl_authenticated,reject',
    '  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject',
    '  -o milter_macro_daemon_name=ORIGINATING',
    'smtps inet n - y - - smtpd',
    '  -o syslog_name=postfix/smtps',
    '  -o smtpd_tls_wrappermode=yes',
    '  -o smtpd_sasl_auth_enable=yes',
    '  -o smtpd_client_restrictions=permit_sasl_authenticated,reject',
    '  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject',
    '  -o milter_macro_daemon_name=ORIGINATING',
    '# NT-MAIL-END',
    'NTEOF',
    'postfix check',
  ),

  // passwd-file users; hashes are produced on the server by doveadm/openssl.
  dovecot: lines(
    'touch /etc/dovecot/users && chown root:dovecot /etc/dovecot/users && chmod 0640 /etc/dovecot/users',
    "cat > /etc/dovecot/conf.d/99-nt-mail.conf <<'NTEOF'",
    '# Managed by NodeTeam panel. Do not edit by hand.',
    'protocols = imap lmtp sieve',
    'mail_location = maildir:/var/vmail/%d/%n/Maildir',
    'mail_uid = vmail',
    'mail_gid = vmail',
    'first_valid_uid = 5000',
    'disable_plaintext_auth = yes',
    'auth_mechanisms = plain login',
    'ssl = required',
    'ssl_cert = </etc/ssl/nt-mail/fullchain.pem',
    'ssl_key = </etc/ssl/nt-mail/privkey.pem',
    'ssl_min_protocol = TLSv1.2',
    'passdb {',
    '  driver = passwd-file',
    '  args = scheme=CRYPT username_format=%u /etc/dovecot/users',
    '}',
    'userdb {',
    '  driver = static',
    '  args = uid=vmail gid=vmail home=/var/vmail/%d/%n',
    '}',
    'service auth {',
    '  unix_listener /var/spool/postfix/private/auth {',
    '    mode = 0660',
    '    user = postfix',
    '    group = postfix',
    '  }',
    '}',
    'service lmtp {',
    '  unix_listener /var/spool/postfix/private/dovecot-lmtp {',
    '    mode = 0600',
    '    user = postfix',
    '    group = postfix',
    '  }',
    '}',
    'protocol lmtp {',
    '  mail_plugins = $mail_plugins sieve',
    '}',
    'NTEOF',
    'doveconf -n >/dev/null',
  ),

  opendkim: lines(
    // Align package defaults with our inet milter socket. Ubuntu's /etc/default/opendkim often
    // keeps a unix SOCKET= that fights the conf file and makes systemctl restart hang/timeout.
    'mkdir -p /etc/opendkim/keys /run/opendkim',
    'touch /etc/opendkim/KeyTable /etc/opendkim/SigningTable /etc/opendkim/TrustedHosts',
    'chown opendkim:opendkim /run/opendkim || true',
    "cat > /etc/opendkim.conf <<'NTEOF'",
    '# Managed by NodeTeam panel.',
    'Syslog yes',
    'UMask 007',
    'Mode sv',
    'Canonicalization relaxed/simple',
    'KeyTable refile:/etc/opendkim/KeyTable',
    'SigningTable refile:/etc/opendkim/SigningTable',
    'ExternalIgnoreList refile:/etc/opendkim/TrustedHosts',
    'InternalHosts refile:/etc/opendkim/TrustedHosts',
    'Socket inet:8891@127.0.0.1',
    'PidFile /run/opendkim/opendkim.pid',
    'UserID opendkim',
    'NTEOF',
    'echo "127.0.0.1" > /etc/opendkim/TrustedHosts',
    'if [ -f /etc/default/opendkim ]; then',
    '  sed -i -E \'s|^#?[[:space:]]*SOCKET=.*|SOCKET="inet:8891@127.0.0.1"|\' /etc/default/opendkim',
    '  grep -q \'^SOCKET=\' /etc/default/opendkim || echo \'SOCKET="inet:8891@127.0.0.1"\' >> /etc/default/opendkim',
    'else',
    '  printf \'SOCKET="inet:8891@127.0.0.1"\\n\' > /etc/default/opendkim',
    'fi',
    'chown -R opendkim:opendkim /etc/opendkim && chmod 0750 /etc/opendkim /etc/opendkim/keys',
  ),

  rspamd: lines(
    'mkdir -p /etc/rspamd/local.d',
    "cat > /etc/rspamd/local.d/worker-proxy.inc <<'NTEOF'",
    'milter = yes;',
    'timeout = 120s;',
    'bind_socket = "127.0.0.1:11332";',
    'upstream "local" { default = yes; self_scan = yes; }',
    'NTEOF',
    // OpenDKIM already signs; avoid double signing.
    "printf 'enabled = false;\\n' > /etc/rspamd/local.d/dkim_signing.conf",
  ),

  // Phase 10F (TASK-038): abuse controls. Fixed text, no dynamic values, no secrets. Every file is rewritten whole
  // (marker NT-HARDENING-v1) and postconf -e is idempotent, so re-running changes nothing.
  hardening: lines(
    // 1) Postfix anvil rate limits (per client, per anvil_rate_time_unit).
    'postconf -e "anvil_rate_time_unit = 60s" "smtpd_client_message_rate_limit = 100" "smtpd_client_recipient_rate_limit = 200" "smtpd_client_connection_rate_limit = 30" "smtpd_client_connection_count_limit = 20" "smtpd_client_auth_rate_limit = 20"',
    'postconf -e "smtpd_error_sleep_time = 1s" "smtpd_soft_error_limit = 3" "smtpd_hard_error_limit = 10"',
    'postfix check',
    // 2) Dovecot: delay failed auth replies, cap parallel IMAP sessions per user+IP.
    "cat > /etc/dovecot/conf.d/98-nt-mail-hardening.conf <<'NTEOF'",
    '# NT-HARDENING-v1 Managed by NodeTeam panel. Do not edit by hand.',
    'auth_failure_delay = 2 secs',
    'auth_verbose = no',
    'protocol imap {',
    '  mail_max_userip_connections = 20',
    '}',
    'NTEOF',
    'doveconf -n >/dev/null',
    // 3) Rspamd baseline (scoring actions, headers, local-only controller).
    'mkdir -p /etc/rspamd/local.d',
    "cat > /etc/rspamd/local.d/actions.conf <<'NTEOF'",
    '# NT-HARDENING-v1 Managed by NodeTeam panel.',
    'reject = 15;',
    'add_header = 6;',
    'greylist = 4;',
    'NTEOF',
    "cat > /etc/rspamd/local.d/milter_headers.conf <<'NTEOF'",
    '# NT-HARDENING-v1 Managed by NodeTeam panel.',
    'extended_spam_headers = true;',
    'use = ["x-spamd-result", "x-rspamd-server", "authentication-results"];',
    'NTEOF',
    "cat > /etc/rspamd/local.d/worker-controller.inc <<'NTEOF'",
    '# NT-HARDENING-v1 Managed by NodeTeam panel. Controller listens on loopback only.',
    'bind_socket = "127.0.0.1:11334";',
    'NTEOF',
    "cat > /etc/rspamd/local.d/classifier-bayes.conf <<'NTEOF'",
    '# NT-HARDENING-v1 Managed by NodeTeam panel.',
    'autolearn = true;',
    'NTEOF',
    // 4) fail2ban jails: postfix, postfix-sasl, dovecot (journald backend; Ubuntu 24.04 has no mail.log by default).
    'mkdir -p /etc/fail2ban/jail.d',
    "cat > /etc/fail2ban/jail.d/nt-mail.local <<'NTEOF'",
    '# NT-HARDENING-v1 Managed by NodeTeam panel. Do not edit by hand.',
    '[DEFAULT]',
    'ignoreip = 127.0.0.1/8 ::1',
    'bantime = 1h',
    'findtime = 10m',
    'maxretry = 5',
    'backend = systemd',
    '',
    '[postfix]',
    'enabled = true',
    'port = smtp,465,submission',
    '',
    '[postfix-sasl]',
    'enabled = true',
    'port = smtp,465,submission,imap,imaps',
    'maxretry = 4',
    '',
    '[dovecot]',
    'enabled = true',
    'port = pop3,pop3s,imap,imaps,submission,465,sieve',
    'NTEOF',
    'fail2ban-client -t >/dev/null',
    'echo "NT_RESULT hardening=applied"',
  ),

  // $1 = mail hostname. Prefer Let's Encrypt for the mail host, then the parent apex
  // (mail.example.com → example.com), else a flagged self-signed placeholder.
  tls: lines(
    'mkdir -p /etc/ssl/nt-mail && chmod 0755 /etc/ssl/nt-mail',
    'host="$1"',
    'apex="${host#mail.}"',
    'pick=""',
    'for cand in "$host" "$apex"; do',
    '  if [ -n "$cand" ] && [ -s "/etc/letsencrypt/live/$cand/fullchain.pem" ] && [ -s "/etc/letsencrypt/live/$cand/privkey.pem" ]; then pick="$cand"; break; fi',
    'done',
    'if [ -n "$pick" ]; then',
    '  ln -sfn "/etc/letsencrypt/live/$pick/fullchain.pem" /etc/ssl/nt-mail/fullchain.pem',
    '  ln -sfn "/etc/letsencrypt/live/$pick/privkey.pem" /etc/ssl/nt-mail/privkey.pem',
    '  echo "NT_RESULT tls=existing tls_name=$pick"',
    'elif [ -L /etc/ssl/nt-mail/fullchain.pem ] && [ -s /etc/ssl/nt-mail/fullchain.pem ]; then',
    '  echo "NT_RESULT tls=existing"',
    'elif [ -s /etc/ssl/nt-mail/fullchain.pem ] && [ ! -L /etc/ssl/nt-mail/fullchain.pem ]; then',
    '  echo "NT_RESULT tls=selfsigned-placeholder"',
    'else',
    '  rm -f /etc/ssl/nt-mail/fullchain.pem /etc/ssl/nt-mail/privkey.pem',
    '  openssl req -x509 -newkey rsa:3072 -nodes -days 90 -subj "/CN=$host" -keyout /etc/ssl/nt-mail/privkey.pem -out /etc/ssl/nt-mail/fullchain.pem >/dev/null 2>&1',
    '  chmod 0600 /etc/ssl/nt-mail/privkey.pem',
    '  echo "NT_RESULT tls=selfsigned-placeholder"',
    'fi',
  ),

  services: lines(
    'systemctl enable postfix dovecot opendkim rspamd fail2ban >/dev/null 2>&1 || true',
    'mkdir -p /run/opendkim; chown opendkim:opendkim /run/opendkim 2>/dev/null || true',
    // Restart one-by-one. A single `systemctl restart a b c` waits on the slowest unit and
    // OpenDKIM often hits the default start timeout when SOCKET defaults disagree.
    'for s in opendkim rspamd dovecot postfix fail2ban; do',
    '  systemctl reset-failed "$s" >/dev/null 2>&1 || true',
    '  if ! systemctl restart "$s"; then',
    '    echo "restart failed: $s" >&2',
    '    systemctl status "$s" --no-pager -l >&2 || true',
    '    journalctl -u "$s" -n 30 --no-pager >&2 || true',
    '    exit 1',
    '  fi',
    '  ok=0; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do',
    '    if systemctl is-active --quiet "$s"; then ok=1; break; fi',
    '    sleep 1',
    '  done',
    '  if [ "$ok" != 1 ]; then',
    '    echo "service $s not active" >&2',
    '    systemctl status "$s" --no-pager -l >&2 || true',
    '    journalctl -u "$s" -n 30 --no-pager >&2 || true',
    '    exit 1',
    '  fi',
    'done',
    'echo "NT_RESULT services=active"',
  ),
};

/** Ordered executable steps. The firewall is intentionally NOT part of apply (separate CRITICAL action). */
export const PROVISION_STEP_ORDER = Object.freeze(['packages', 'postfix', 'dovecot', 'opendkim', 'rspamd', 'tls', 'hardening', 'services']);

export function stepScript(id) {
  const s = STEP_SCRIPTS[id];
  if (!s) throw new Error(`Unknown provisioning step: ${id}`);
  return s;
}
export const preflightScript = () => PREFLIGHT_PROBE;

/** Per-domain: virtual domain + DKIM key generated on the server. $1=domain $2=selector. Prints the public TXT value only. */
export const domainAddScript = () =>
  lines(
    'domain="$1"; sel="$2"; dir="/etc/opendkim/keys/$domain"',
    'exec 9>/var/lock/nt-mail.lock; flock 9',
    'grep -qxF "$domain OK" /etc/postfix/vdomains || echo "$domain OK" >> /etc/postfix/vdomains',
    'postmap /etc/postfix/vdomains',
    'mkdir -p "$dir"',
    'if [ ! -s "$dir/$sel.private" ]; then opendkim-genkey -b 2048 -d "$domain" -D "$dir" -s "$sel"; fi',
    'chown -R opendkim:opendkim "$dir" && chmod 0600 "$dir/$sel.private"',
    'awk -v k="$sel._domainkey.$domain" \'$1==k{f=1} END{exit !f}\' /etc/opendkim/KeyTable || echo "$sel._domainkey.$domain $domain:$sel:$dir/$sel.private" >> /etc/opendkim/KeyTable',
    'awk -v k="*@$domain" \'$1==k{f=1} END{exit !f}\' /etc/opendkim/SigningTable || echo "*@$domain $sel._domainkey.$domain" >> /etc/opendkim/SigningTable',
    'systemctl reload postfix; systemctl restart opendkim',
    'pub=$(tr -d \'\\n\\t " \' < "$dir/$sel.txt" | sed -e \'s/.*p=//\' -e \'s/).*//\' -e \'s/;.*//\')',
    'echo "NT_RESULT dkim_public=$pub"',
  );

/** Mailbox set/reset. $1=address $2=quotaMb; the password is read from STDIN (one line) and hashed here. */
export const mailboxSetScript = () =>
  lines(
    'addr="$1"; quota="$2"; local="${addr%@*}"; domain="${addr#*@}"',
    'IFS= read -r pw || true; [ -n "$pw" ] || { echo "empty password" >&2; exit 2; }',
    'hash=""',
    'if command -v doveadm >/dev/null 2>&1; then hash=$(printf \'%s\\n%s\\n\' "$pw" "$pw" | doveadm pw -s ARGON2ID 2>/dev/null || true); case "$hash" in "{ARGON2ID}"*) ;; *) hash="";; esac; fi',
    'if [ -z "$hash" ]; then hash="{SHA512-CRYPT}$(printf \'%s\' "$pw" | openssl passwd -6 -stdin)"; fi',
    'unset pw',
    'scheme="${hash%%\\}*}}"',
    'exec 9>/var/lock/nt-mail.lock; flock 9',
    'tmp=$(mktemp /etc/dovecot/users.XXXXXX); awk -F: -v a="$addr" \'$1 != a\' /etc/dovecot/users > "$tmp" || true',
    'echo "$addr:$hash:5000:5000::/var/vmail/$domain/$local::userdb_quota_rule=*:storage=${quota}M" >> "$tmp"',
    'chown root:dovecot "$tmp"; chmod 0640 "$tmp"; mv "$tmp" /etc/dovecot/users',
    'awk -v a="$addr" \'$1 != a\' /etc/postfix/vmailbox > /etc/postfix/vmailbox.tmp || true; echo "$addr $domain/$local/Maildir/" >> /etc/postfix/vmailbox.tmp; mv /etc/postfix/vmailbox.tmp /etc/postfix/vmailbox',
    'postmap /etc/postfix/vmailbox',
    'mkdir -p "/var/vmail/$domain/$local" && chown -R vmail:vmail "/var/vmail/$domain"',
    'echo "NT_RESULT hash_scheme=$scheme"',
  );

/** Mailbox removal from the server login/delivery maps. Maildir is kept (no destructive delete). $1=address */
export const mailboxRemoveScript = () =>
  lines(
    'addr="$1"',
    'exec 9>/var/lock/nt-mail.lock; flock 9',
    'tmp=$(mktemp /etc/dovecot/users.XXXXXX); awk -F: -v a="$addr" \'$1 != a\' /etc/dovecot/users > "$tmp" || true; chown root:dovecot "$tmp"; chmod 0640 "$tmp"; mv "$tmp" /etc/dovecot/users',
    'awk -v a="$addr" \'$1 != a\' /etc/postfix/vmailbox > /etc/postfix/vmailbox.tmp || true; mv /etc/postfix/vmailbox.tmp /etc/postfix/vmailbox; postmap /etc/postfix/vmailbox',
    'echo "NT_RESULT removed=yes"',
  );

/**
 * Firewall: opens ONLY the listed ports, one allow rule each. Never `ufw enable`, never delete/reset/default
 * changes. Inactive ufw => report and change nothing. Ports arrive as args ($@).
 */
export const firewallScript = () =>
  lines(
    'command -v ufw >/dev/null 2>&1 || { echo "NT_RESULT ufw=absent changed=no"; exit 0; }',
    'state=$(ufw status | head -1 | awk \'{print tolower($2)}\')',
    'if [ "$state" != "active" ]; then echo "NT_RESULT ufw=$state changed=no"; exit 0; fi',
    'changed=no',
    'for p in "$@"; do if ufw status | awk -v p="$p/tcp" \'$1==p && $2=="ALLOW" {f=1} END{exit !f}\'; then :; else ufw allow "$p/tcp" >/dev/null; changed=yes; fi; done',
    'echo "NT_RESULT ufw=active changed=$changed"',
  );

/** Read-only firewall state for the preview. */
export const firewallStatusScript = () =>
  lines(
    'command -v ufw >/dev/null 2>&1 || { echo "ufw=absent"; exit 0; }',
    'echo "ufw=$(ufw status | head -1 | awk \'{print tolower($2)}\')"',
    'for p in "$@"; do if ufw status | awk -v p="$p/tcp" \'$1==p && $2=="ALLOW" {f=1} END{exit !f}\'; then echo "rule_$p=allowed"; else echo "rule_$p=absent"; fi; done',
  );

/** Health probe incl. open-relay self-test from the server's non-loopback address (loopback is not a relay client). */
export const healthScript = () =>
  lines(
    'for s in postfix dovecot opendkim rspamd fail2ban; do echo "svc_$s=$(systemctl is-active "$s" 2>/dev/null || true)"; done',
    `echo "f2b_jails=$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{gsub(/[[:space:]]/,"",$2); gsub(/,/,"+",$2); print $2}' || true)"`,
    'cert=/etc/ssl/nt-mail/fullchain.pem; days=unknown',
    'if [ -s "$cert" ]; then end=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2 || true); if [ -n "$end" ]; then e=$(date -d "$end" +%s 2>/dev/null || echo 0); [ "$e" -gt 0 ] && days=$(( (e - $(date +%s)) / 86400 )); fi; fi',
    'echo "tls_days_left=$days"',
    `echo "queue_size=$(mailq 2>/dev/null | awk '/^Mail queue is empty/{n=0;f=1} /^-- .* Requests?[.]/{n=$5;f=1} END{print f?n:"unknown"}' || echo unknown)"`,
    'for p in 25 465 587 993; do if ss -ltnH 2>/dev/null | awk -v p=":$p" \'$4 ~ p"$" {f=1} END{exit !f}\'; then echo "port_$p=up"; else echo "port_$p=down"; fi; done',
    'if [ -L /etc/ssl/nt-mail/fullchain.pem ]; then echo "tls=existing"; elif [ -s /etc/ssl/nt-mail/fullchain.pem ]; then echo "tls=selfsigned-placeholder"; else echo "tls=missing"; fi',
    'ip=$(hostname -I 2>/dev/null | awk \'{print $1}\'); ip=${ip:-127.0.0.1}',
    'relay=unknown',
    'if exec 8<>"/dev/tcp/$ip/25" 2>/dev/null; then',
    '  read -r -t 8 _ <&8 || true',
    '  printf "EHLO nt-relay-probe.invalid\\r\\n" >&8; sleep 1',
    '  printf "MAIL FROM:<probe@nt-relay-probe.invalid>\\r\\n" >&8; sleep 1',
    '  printf "RCPT TO:<relay-probe@example.org>\\r\\n" >&8; sleep 1',
    '  resp=""; while read -r -t 2 l <&8; do resp="$resp$l|"; done',
    '  printf "QUIT\\r\\n" >&8 || true; exec 8>&-',
    '  case "$resp" in *"250 2.1.5"*) relay=open;; *"554 5."*|*"550 5."*|*"530 5."*|*"450 4."*|*"454 4."*|*"554 "*|*"550 "*) relay=closed;; *) relay=unknown;; esac',
    'fi',
    'echo "open_relay=$relay"',
    'v=$(dpkg-query -W -f=\'${Version}\' postfix 2>/dev/null || true); echo "postfix_version=$v"',
  );

export function parseKeyValues(text) {
  const out = {};
  for (const raw of String(text ?? '').split('\n')) {
    const l = raw.trim().replace(/^NT_RESULT /, '');
    for (const kv of l.split(' ')) {
      const i = kv.indexOf('=');
      if (i > 0 && /^[A-Za-z0-9_]+$/.test(kv.slice(0, i))) out[kv.slice(0, i)] = kv.slice(i + 1);
    }
  }
  return out;
}

/** Interprets the read-only preflight probe into prerequisites + blockers. */
export function evaluatePrerequisites(kv) {
  const blockers = [];
  const warnings = [];
  if (kv.os_id !== 'ubuntu' || !SUPPORTED_OS.includes(kv.os_version)) blockers.push(`Unsupported OS (${kv.os_id ?? '?'} ${kv.os_version ?? '?'}); Ubuntu 22.04 or 24.04 required`);
  if (kv.is_root !== 'yes') blockers.push('SSH user must be root (apt, systemd and config writes need it)');
  for (const p of MAIL_FIREWALL_PORTS) if (kv[`port_${p}`] === 'in_use' && kv.pkg_postfix !== 'installed') blockers.push(`Port ${p} is already in use by another service`);
  if (kv.existing_mta && !['none', 'postfix'].includes(kv.existing_mta)) blockers.push(`Another MTA is active (${kv.existing_mta}); remove it first`);
  if (Number(kv.disk_free_mb) < 2048) warnings.push('Less than 2 GB free disk');
  if (kv.ufw === 'inactive') warnings.push('ufw is inactive: the panel will not enable it; mail ports are only reachable if you manage the firewall elsewhere');
  return { ok: blockers.length === 0, blockers, warnings };
}

/** Interprets the health probe into per-check pass/fail. Self-signed TLS is a warning, not a hard fail. */
export function evaluateHealth(kv) {
  const checks = [];
  for (const s of ['postfix', 'dovecot', 'opendkim', 'rspamd']) checks.push({ id: `service.${s}`, pass: kv[`svc_${s}`] === 'active', detail: kv[`svc_${s}`] ?? 'unknown' });
  for (const p of MAIL_FIREWALL_PORTS) checks.push({ id: `port.${p}`, pass: kv[`port_${p}`] === 'up', detail: kv[`port_${p}`] ?? 'unknown' });
  checks.push({ id: 'open_relay', pass: kv.open_relay === 'closed', detail: kv.open_relay ?? 'unknown' });
  // Phase 10F additions: only evaluated when the probe reported them (older probe output stays valid).
  if (kv.svc_fail2ban !== undefined) checks.push({ id: 'service.fail2ban', pass: kv.svc_fail2ban === 'active', detail: kv.svc_fail2ban });
  if (kv.svc_fail2ban === 'active' && kv.f2b_jails !== undefined) {
    const missing = ['postfix-sasl', 'dovecot'].filter((j) => !String(kv.f2b_jails).split('+').includes(j));
    checks.push({ id: 'fail2ban.jails', pass: missing.length === 0, detail: missing.length ? `missing: ${missing.join(',')}` : kv.f2b_jails });
  }
  if (kv.tls_days_left !== undefined) {
    const days = Number(kv.tls_days_left);
    if (Number.isFinite(days) && kv.tls_days_left !== '') checks.push({ id: 'tls.expiry', pass: days > 0, warn: days > 0 && days < 14, detail: `${days} days left`, daysLeft: days });
    else checks.push({ id: 'tls.expiry', pass: true, warn: true, detail: 'unknown' });
  }
  if (kv.queue_size !== undefined) {
    const n = Number(kv.queue_size);
    const known = Number.isFinite(n) && kv.queue_size !== '' && kv.queue_size !== 'unknown';
    checks.push({ id: 'queue.size', pass: !known || n <= 500, warn: !known || n > 100, detail: known ? `${n} queued` : 'unknown', queueSize: known ? n : null });
  }
  const tls = kv.tls ?? 'unknown';
  if (tls === 'existing') {
    checks.push({ id: 'tls', pass: true, warn: false, detail: kv.tls_name ? `letsencrypt:${kv.tls_name}` : 'letsencrypt' });
  } else if (tls === 'selfsigned-placeholder') {
    checks.push({
      id: 'tls',
      pass: true,
      warn: true,
      detail: 'self-signed placeholder — issue a real certificate for the mail hostname (or apex) then re-run health',
    });
  } else {
    checks.push({ id: 'tls', pass: false, warn: false, detail: tls });
  }
  // F7 / TASK-038: maildir backup is not implemented yet — surface as a warning, never a hard fail.
  checks.push({
    id: 'maildir.backup',
    pass: true,
    warn: true,
    detail: 'not configured — maildir backup design REQUIRES DECISION (see runbooks/MAIL-BACKUP-RESTORE.md)',
  });
  return { ok: checks.every((c) => c.pass), openRelay: kv.open_relay ?? 'unknown', tls, stackVersion: kv.postfix_version || null, checks };
}

/** Softens stored health rows that still mark the intentional self-signed placeholder as a hard fail. */
export function normalizeStoredHealth(stored) {
  if (!stored || !Array.isArray(stored.checks)) return stored;
  const checks = stored.checks.map((c) => {
    if (c?.id !== 'tls') return c;
    const detail = String(c.detail ?? '');
    if (stored.tls === 'selfsigned-placeholder' || /self-signed/i.test(detail)) {
      return {
        ...c,
        pass: true,
        warn: true,
        detail: 'self-signed placeholder — issue a real certificate for the mail hostname (or apex) then re-run health',
      };
    }
    return c;
  });
  if (!checks.some((c) => c?.id === 'maildir.backup')) {
    checks.push({
      id: 'maildir.backup',
      pass: true,
      warn: true,
      detail: 'not configured — maildir backup design REQUIRES DECISION (see runbooks/MAIL-BACKUP-RESTORE.md)',
    });
  }
  return { ...stored, checks, ok: checks.every((c) => c.pass) };
}

export const PROVISION_STEPS = Object.freeze([
  { id: 'packages', title: 'Install packages', detail: 'postfix, dovecot (imap/lmtp/sieve), opendkim + tools, rspamd via apt; vmail user', risk: 'high' },
  { id: 'postfix', title: 'Configure Postfix', detail: 'hash: virtual maps (no database dependency); smtpd_relay_restrictions=permit_sasl_authenticated,reject_unauth_destination; 587/465 require auth + TLS; TLS 1.2+', risk: 'high' },
  { id: 'dovecot', title: 'Configure Dovecot', detail: 'passwd-file auth; hashes made on the server (ARGON2ID, else SHA512-CRYPT); maildir under /var/vmail; TLS required', risk: 'high' },
  { id: 'opendkim', title: 'Configure OpenDKIM', detail: 'Key/signing tables; private keys generated per domain on the server (0600)', risk: 'high' },
  { id: 'rspamd', title: 'Rspamd baseline', detail: 'Milter proxy on localhost; DKIM signing left to OpenDKIM', risk: 'medium' },
  { id: 'tls', title: 'TLS certificate', detail: "Existing Let's Encrypt cert for the mail hostname if present, else a self-signed placeholder flagged in health", risk: 'medium' },
  { id: 'hardening', title: 'Abuse controls', detail: 'fail2ban jails (postfix, postfix-sasl, dovecot), rspamd baseline actions/headers, Postfix anvil rate limits, Dovecot auth_failure_delay', risk: 'medium' },
  { id: 'services', title: 'Enable and restart services', detail: 'postfix, dovecot, opendkim, rspamd, fail2ban enabled and verified active', risk: 'high' },
]);

export const ROLLBACK_NOTES = Object.freeze([
  'Original master.cf is kept at /etc/postfix/master.cf.nt-orig; the managed block is between NT-MAIL-BEGIN/END markers.',
  'Panel-managed files: /etc/postfix/{vdomains,vmailbox,valiases}, /etc/dovecot/{users,conf.d/99-nt-mail.conf}, /etc/opendkim*, /etc/rspamd/local.d/worker-proxy.inc.',
  'To roll back: systemctl disable --now postfix dovecot opendkim rspamd, remove the managed files above. Maildirs under /var/vmail are never deleted by the panel.',
  'Packages are not purged automatically.',
]);
