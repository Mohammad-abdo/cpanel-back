/**
 * TASK-047: certbot DNS-01 script generator for wildcard certificates over the Cloudflare plugin.
 *
 * Secrets: the Cloudflare token reaches the server only through the SSH channel's stdin. The script writes it to a
 * 0600 file inside a 0700 temp directory (umask 077), and removes the directory on exit. The token is never an argument,
 * never echoed, never part of the script text, and certbot output is kept out of the returned stdout.
 * Running it on a real server is NOT_RUN.
 */
import { AppError } from '../../common/errors/app-error.js';
import { isValidCloudflareToken } from '../root-domains/cloudflare.client.js';

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;

export const wildcardNamesFor = (name) => [name, `*.${name}`];

/** args: DOMAIN EMAIL PROPAGATION_SECONDS STAGING(0|1). stdin: the credentials file. Prints NT_EXPIRES=<openssl date>. */
export const CERTBOT_DNS_CLOUDFLARE_SCRIPT = `set -eu
DOMAIN="$1"; EMAIL="$2"; PROP="$3"; STAGING="$4"
case "$DOMAIN" in ''|*[!a-z0-9.-]*) echo "bad domain" >&2; exit 64 ;; esac
case "$PROP" in ''|*[!0-9]*) echo "bad propagation" >&2; exit 64 ;; esac
command -v certbot >/dev/null 2>&1 || { echo "certbot-missing" >&2; exit 69; }
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo -n"
umask 077
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
cat > "$DIR/cloudflare.ini"
chmod 600 "$DIR/cloudflare.ini"
EXTRA=""; [ "$STAGING" = "1" ] && EXTRA="--staging"
if ! $SUDO certbot certonly --non-interactive --agree-tos --email "$EMAIL" --cert-name "$DOMAIN" $EXTRA \\
  --dns-cloudflare --dns-cloudflare-credentials "$DIR/cloudflare.ini" --dns-cloudflare-propagation-seconds "$PROP" \\
  -d "$DOMAIN" -d "*.$DOMAIN" >"$DIR/out" 2>&1; then
  tail -n 5 "$DIR/out" >&2
  exit 70
fi
$SUDO openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" | sed 's/^notAfter=/NT_EXPIRES=/'
`;

/** Credentials file content. The token format is validated, so no newline or option can be smuggled in. */
export function buildCloudflareCredentials(token) {
  if (!isValidCloudflareToken(token)) throw new AppError(422, 'DNS_TOKEN_INVALID', 'The Cloudflare API token has an invalid format');
  return `dns_cloudflare_api_token = ${token}\n`;
}

/** Plan for a preview: script text (no secrets), argv, and what is sent on stdin (a placeholder only). */
export function planWildcardCertificate({ domain, email, propagationSeconds = 30, staging = false }) {
  if (!HOSTNAME.test(domain)) throw new AppError(422, 'DOMAIN_INVALID', 'Root domain is not a valid hostname');
  if (!EMAIL.test(String(email ?? ''))) throw new AppError(422, 'ACME_EMAIL_INVALID', 'A valid ACME contact email is required');
  const prop = Math.min(Math.max(Number(propagationSeconds) || 30, 10), 600);
  return {
    names: wildcardNamesFor(domain),
    script: CERTBOT_DNS_CLOUDFLARE_SCRIPT,
    args: [domain, email, String(prop), staging ? '1' : '0'],
    stdinPreview: 'dns_cloudflare_api_token = [sent over stdin, never shown]\n',
    credentialsFile: '0600 file in a 0700 temp directory, removed on exit',
  };
}

/** "Jan  1 00:00:00 2027 GMT" (openssl) -> Date. Returns null when unparseable. */
export function parseOpensslDate(text) {
  const m = /NT_EXPIRES=(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+(\d{4})\s+GMT/.exec(String(text));
  if (!m) return null;
  const d = new Date(`${m[1]} ${m[2]} ${m[6]} ${m[3]}:${m[4]}:${m[5]} GMT`);
  return Number.isNaN(d.getTime()) ? null : d;
}
