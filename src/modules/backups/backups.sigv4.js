import { createHash, createHmac } from 'node:crypto';

/**
 * AWS Signature Version 4 for S3-compatible endpoints, implemented in-house (no SDK).
 * Pure functions: the caller supplies the clock so tests can pin the AWS published vectors.
 */
export const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();

/** RFC 3986 percent-encoding as required by SigV4 (slash kept only for paths). */
export function uriEncode(value, { keepSlash = false } = {}) {
  let out = '';
  for (const byte of Buffer.from(String(value), 'utf8')) {
    const c = String.fromCharCode(byte);
    if (/[A-Za-z0-9_.~-]/.test(c) || (keepSlash && c === '/')) out += c;
    else out += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

export const amzDate = (date) => date.toISOString().replace(/[:-]|\.\d{3}/g, '');

export function canonicalQuery(query = {}) {
  return Object.keys(query)
    .sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(query[k])}`)
    .join('&');
}

export function signingKey(secretKey, dateStamp, region, service) {
  return hmac(hmac(hmac(hmac(`AWS4${secretKey}`, dateStamp), region), service), 'aws4_request');
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Returns { headers (lower-case, incl. authorization), canonicalRequest, stringToSign, signature }.
 * `path` is an absolute path; each segment is (re)encoded once, as S3 requires.
 */
export function signRequest({ method, host, path, query = {}, headers = {}, body = '', region, service = 's3', accessKeyId, secretAccessKey, sessionToken = null, date = new Date(), payloadHash = null }) {
  const stamp = amzDate(date);
  const dateStamp = stamp.slice(0, 8);
  const hash = payloadHash ?? sha256Hex(body);
  const all = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, ' ')]));
  all.host = host;
  all['x-amz-date'] = stamp;
  if (service === 's3') all['x-amz-content-sha256'] = hash;
  if (sessionToken) all['x-amz-security-token'] = sessionToken;
  const names = Object.keys(all).sort();
  const signedHeaders = names.join(';');
  const canonicalPath = path.split('/').map((s) => uriEncode(decodeSafe(s))).join('/') || '/';
  const canonicalRequest = [method.toUpperCase(), canonicalPath, canonicalQuery(query), names.map((n) => `${n}:${all[n]}\n`).join(''), signedHeaders, hash].join('\n');
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', stamp, scope, sha256Hex(canonicalRequest)].join('\n');
  const signature = hmac(signingKey(secretAccessKey, dateStamp, region, service), stringToSign).toString('hex');
  all.authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: all, canonicalRequest, stringToSign, signature };
}
