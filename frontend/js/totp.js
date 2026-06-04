/* HorseSafe TOTP-renderer v0.0.1 — RFC 6238 via WebCrypto (browser-native).
 *
 * Leest otpauth://-URI's uit het entry-custom-field 'otp' (KeePassXC-compatibel)
 * en genereert het lopende 6-cijferige TOTP-codenummer + tijd-resterend.
 *
 * Default-params: SHA-1, 6 digits, 30s window. Override via URI-query.
 */
(function () {
  'use strict';

  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Decode(s) {
    const clean = String(s).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
    const out = [];
    let buf = 0, bits = 0;
    for (const ch of clean) {
      const v = B32.indexOf(ch);
      if (v === -1) continue;
      buf = (buf << 5) | v;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.push((buf >> bits) & 0xFF);
      }
    }
    return new Uint8Array(out);
  }

  function parseOtpauth(uri) {
    if (typeof uri !== 'string' || !uri.startsWith('otpauth://')) return null;
    let u;
    try { u = new URL(uri); } catch { return null; }
    if (u.host !== 'totp') return null; // HOTP niet ondersteund
    const q = u.searchParams;
    const secret = q.get('secret');
    if (!secret) return null;
    const digits = Math.min(8, Math.max(6, parseInt(q.get('digits') || '6', 10)));
    const period = Math.max(15, parseInt(q.get('period') || '30', 10));
    let algo = (q.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');
    if (!['SHA1', 'SHA256', 'SHA512'].includes(algo)) algo = 'SHA1';
    return { secret, digits, period, algo };
  }

  async function generateTotp(uri) {
    const params = parseOtpauth(uri);
    if (!params) throw new Error('invalid otpauth URI');
    const keyBytes = base32Decode(params.secret);
    if (keyBytes.length === 0) throw new Error('invalid base32 secret');

    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / params.period);

    // 8-byte big-endian counter
    const ctr = new ArrayBuffer(8);
    const dv = new DataView(ctr);
    dv.setUint32(0, Math.floor(counter / 0x100000000));
    dv.setUint32(4, counter >>> 0);

    const algoMap = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
    const key = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: algoMap[params.algo] }, false, ['sign']
    );
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, ctr));

    // Dynamic truncation per RFC 4226
    const offset = sig[sig.length - 1] & 0x0F;
    const code32 = ((sig[offset] & 0x7F) << 24)
                 | (sig[offset + 1] << 16)
                 | (sig[offset + 2] << 8)
                 | sig[offset + 3];
    const mod = Math.pow(10, params.digits);
    const code = (code32 % mod).toString().padStart(params.digits, '0');

    const secondsLeft = params.period - (now % params.period);
    return { code, secondsLeft, period: params.period, digits: params.digits, algo: params.algo };
  }

  window.HorseSafeTotp = { generateTotp, parseOtpauth };
})();
