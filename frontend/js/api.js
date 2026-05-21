/* HorseSafe API-wrapper v0.0.2-Hellman
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
    return isDev ? `http://${location.hostname}:3997` : '/HorseSafe/api';
  })();

  async function jsonReq(method, path, body) {
    const opts = {
      method,
      credentials: 'include',
      headers: {},
    };
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
    health:    () => jsonReq('GET',  '/health'),
    register:  (body) => jsonReq('POST', '/auth/register', body),
    login:     (body) => jsonReq('POST', '/auth/login', body),
    logout:    () => jsonReq('POST', '/auth/logout'),
    listVaults:   () => jsonReq('GET', '/vault'),
    createVault:  (name, blobData) => blobReq('POST', '/vault', blobData, { name }),
    readVault:    (id) => blobReq('GET', `/vault/${encodeURIComponent(id)}`),
    updateVault:  (id, blobData, etag) => blobReq('PUT', `/vault/${encodeURIComponent(id)}`, blobData, { ifMatch: etag }),
    deleteVault:  (id) => jsonReq('DELETE', `/vault/${encodeURIComponent(id)}`),
  };
})();
