/* HorseSafe API-wrapper v0.4.0-Montgomery (sinds v0.0.2-Hellman)
 * Fetch-helpers naar backend. Productie: relatieve paden onder /HorseSafe/api/.
 * Dev: absolute URL naar localhost:3997 (zelfde Schema voor cookies vereist HORSESAFE_CORS_ORIGINS).
 */
(function () {
  'use strict';

  const API_BASE = (function () {
    if (typeof window === 'undefined') return '';
    const isDev = location.port === '8000' || (location.hostname === 'localhost' && location.protocol === 'http:');
    // Dev: zelfde hostname als de frontend (localhost), poort 3997. Cross-origin
    // cookies tussen 127.0.0.1 en localhost worden door browsers als third-party
    // behandeld en geblokkeerd door SameSite=Strict — vandaar 'localhost' niet '127.0.0.1'.
    // Dev/e2e: andere backendpoort via localStorage 'horsesafe.devApiPort' (alleen in dev; productie
    // gebruikt altijd het relatieve pad). Nodig omdat 3997 op HC55 de productie-backend is.
    let devPort = '3997';
    if (isDev) {
      try {
        const p = localStorage.getItem('horsesafe.devApiPort');
        if (p && /^\d{2,5}$/.test(p)) devPort = p;
      } catch (_) { /* geen opslag: standaardpoort */ }
    }
    return isDev ? `http://${location.hostname}:${devPort}` : '/HorseSafe/api';
  })();

  // v0.4.0-Montgomery: extra = {signal, keepalive} (long-poll afbreken, annuleren bij tab dicht)
  // ───────────── v0.4.0-Montgomery: sessiebewaking (security-review H1) ─────────────
  // Na inloggen op een vertrouwde browser heeft de sessie scope "browser_pending": tot de telefoon het
  // ontgrendelen goedkeurt weigert de server bijna alles met 403 phone_approval_required. Elke pagina laadt
  // api.js; deze haak ziet ook de directe fetch()-aanroepen (settings, shares, admin) en meldt het netjes.
  // 401 met reason session_expired (absolute grens 12 u) → naar inloggen met "Sessie verlopen".
  const NOTICES = {
    phone_approval_required: 'Ontgrendel eerst met je telefoon. Deze actie kan pas nadat je de kluis op deze vertrouwde browser met je telefoon hebt geopend.',
    browser_session_not_allowed: 'Beheer kan niet vanuit een sessie van een vertrouwde browser. Log in met je wachtwoord.',
  };

  function showNotice(code) {
    if (typeof document === 'undefined' || !NOTICES[code]) return;
    let el = document.getElementById('hs-session-notice');
    if (!el) {
      el = document.createElement('div');
      el.id = 'hs-session-notice';
      el.className = 'error';
      el.setAttribute('role', 'alert');
      const host = document.querySelector('main') || document.body;
      host.insertBefore(el, host.firstChild);
    }
    el.textContent = NOTICES[code];
    el.dataset.code = code;
    if (code === 'phone_approval_required' && !/vault\.html$/.test(location.pathname)) {
      const a = document.createElement('a');
      a.href = 'vault.html';
      a.textContent = ' Naar de kluis';
      el.appendChild(a);
    }
    el.hidden = false;
  }

  function sessionExpired() {
    if (/(login|index)\.html$/.test(location.pathname)) return;
    try { document.dispatchEvent(new CustomEvent('horsesafe:session-expired')); } catch (_) { /* geen DOM */ }
    location.href = 'login.html?error=session_expired';
  }

  /** Lees de fout uit een API-antwoord (kloon, niet-blokkerend) en reageer op sessiecodes. */
  function watch(res) {
    if (res.status !== 401 && res.status !== 403) return;
    res.clone().json().then((d) => {
      const det = d && d.detail && !Array.isArray(d.detail) && typeof d.detail === 'object' ? d.detail : null;
      if (!det) return;
      if (res.status === 401 && det.reason === 'session_expired') sessionExpired();
      else if (res.status === 403 && NOTICES[det.error]) showNotice(det.error);
    }).catch(() => { /* geen JSON */ });
  }

  if (typeof window !== 'undefined' && typeof window.fetch === 'function' && !window.__hsFetchWatched) {
    const origFetch = window.fetch.bind(window);
    window.__hsFetchWatched = true;
    window.fetch = async (input, init) => {
      const res = await origFetch(input, init);
      try {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        if (url.startsWith(API_BASE)) watch(res);
      } catch (_) { /* bewaking mag nooit een aanroep breken */ }
      return res;
    };
  }

  async function jsonReq(method, path, body, extra) {
    const opts = {
      method,
      credentials: 'include',
      headers: {},
    };
    if (extra && extra.signal) opts.signal = extra.signal;
    if (extra && extra.keepalive) opts.keepalive = true;
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(API_BASE + path, opts);
    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      try { data = await res.json(); } catch (_) { data = null; }
    }
    return { ok: res.ok, status: res.status, data, headers: res.headers };
  }

  async function blobReq(method, path, blobData, opts = {}) {
    const headers = {};
    if (opts.ifMatch) headers['If-Match'] = opts.ifMatch;
    const reqOpts = { method, credentials: 'include', headers };
    if (blobData) {
      const form = new FormData();
      if (opts.name) form.append('name', opts.name);
      form.append('blob', new Blob([blobData], { type: 'application/octet-stream' }), 'vault.kdbx');
      reqOpts.body = form;
    }
    const res = await fetch(API_BASE + path, reqOpts);
    if (method === 'GET' && res.ok) {
      const buf = await res.arrayBuffer();
      return { ok: true, status: res.status, blob: buf, etag: res.headers.get('etag') };
    }
    let data = null;
    try { data = await res.json(); } catch (_) {}
    return { ok: res.ok, status: res.status, data, etag: res.headers.get('etag') };
  }

  window.HorseSafeAPI = {
    base: API_BASE,
    showNotice,
    health:    () => jsonReq('GET',  '/health'),
    register:  (body) => jsonReq('POST', '/auth/register', body),
    login:     (body) => jsonReq('POST', '/auth/login', body),
    logout:    () => jsonReq('POST', '/auth/logout'),
    listVaults:   () => jsonReq('GET', '/vault'),
    createVault:  (name, blobData) => blobReq('POST', '/vault', blobData, { name }),
    readVault:    (id) => blobReq('GET', `/vault/${encodeURIComponent(id)}`),
    updateVault:  (id, blobData, etag) => blobReq('PUT', `/vault/${encodeURIComponent(id)}`, blobData, { ifMatch: etag }),
    deleteVault:  (id) => jsonReq('DELETE', `/vault/${encodeURIComponent(id)}`),
    me:           () => jsonReq('GET', '/auth/me'),

    // v0.4.0-Montgomery — vertrouwde browser + telefoonvinger (docs/HARDWARE_KEYS.md §14.6).
    // Elk antwoord {ok, status, data}; fouten staan in data.detail.error (trust.js zet ze om).
    trust: {
      // SU — body {browser_id, vault_id, pub_B, label, proof} → 201 {browser_id, created_at}
      create:   (body) => jsonReq('POST', '/trusted-browsers', body),
      // S — {browsers:[{browser_id, vault_id, label, created_at, last_used_at}]}
      list:     () => jsonReq('GET', '/trusted-browsers'),
      // S — intrekken; 204
      revoke:   (browserId, extra) => jsonReq('DELETE', `/trusted-browsers/${encodeURIComponent(browserId)}`, undefined, extra),
      // publiek — {email} → 200 {challenge_id, challenge, expires_at}
      challenge: (email) => jsonReq('POST', '/auth/browser/challenge', { email }),
      // publiek — {challenge_id, browser_id, sig, totp} → 200 (JWT-cookie) | 401 browser_login_failed
      login:    (body) => jsonReq('POST', '/auth/browser/login', body),
    },
    approvals: {
      // S + sid — {browser_id} → 201 {approval_id, created_at}
      create: (vaultId, browserId) => jsonReq('POST', `/vault/${encodeURIComponent(vaultId)}/approvals`, { browser_id: browserId }),
      // S + zelfde sid — {epk_L, nonce_L, sig_req} → 200 {expires_at}
      submit: (vaultId, approvalId, body) => jsonReq('PUT',
        `/vault/${encodeURIComponent(vaultId)}/approvals/${encodeURIComponent(approvalId)}`, body),
      // S + zelfde sid — long-poll ≤ wait s → {status} | {status:'approved', resp}; daarna 410 gone
      status: (vaultId, approvalId, wait, extra) => jsonReq('GET',
        `/vault/${encodeURIComponent(vaultId)}/approvals/${encodeURIComponent(approvalId)}`
        + (wait ? `?wait=${encodeURIComponent(wait)}` : ''), undefined, extra),
      // S + zelfde sid — annuleren; 204
      cancel: (vaultId, approvalId, extra) => jsonReq('DELETE',
        `/vault/${encodeURIComponent(vaultId)}/approvals/${encodeURIComponent(approvalId)}`, undefined, extra),
    },
  };
})();
