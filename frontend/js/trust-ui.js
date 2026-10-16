/* HorseSafe vertrouwde browser + ontgrendelen met telefoon — schermkoppeling vault.html v0.4.0-Montgomery
 * Contract: docs/HARDWARE_KEYS.md §14.3 (vertrouwen) en §14.5 (ontgrendelen).
 *
 *   Kluis open → 🔑 Sleutels → "Deze browser vertrouwen" (alleen met keyfile én authenticator-app; step-up)
 *     → K_B in IndexedDB + proof uit de CK van de geopende kluis → POST /trusted-browsers. Lijst met Intrekken,
 *     "Vergeet deze browser" (lokaal + DELETE).
 *   Kluis dicht + trust-record voor deze kluis → "📱 Ontgrendel met telefoon" → verzoek + afteller 120 s →
 *     goedgekeurd: resp openen → kluis open; geweigerd: uitgelogd; verlopen: opnieuw proberen.
 */
(function () {
  'use strict';

  const T = window.HorseSafeTrust;
  const HK = window.HorseSafeHwKeys;
  const UI = window.HorseSafeVaultUI;
  const SU = window.HorseSafeStepUp;
  const API = window.HorseSafeAPI;

  const ui = {
    support: { ok: false, reason: null },
    me: null, // {email, has_totp}
    lockedVaultId: null, // kluis op het ontgrendelscherm
    record: null, // lokaal trust-record van de geopende kluis
    unlockRecord: null, // lokaal trust-record van de kluis op het ontgrendelscherm
    browsers: [],
    pending: null, // {session, ctrl}
    busy: false,
  };

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }
  function fmt(ts) {
    return ts ? new Date(ts * 1000).toLocaleString('nl-NL', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  }
  function mmss(n) {
    return `${Math.floor(n / 60)}:${String(n % 60).padStart(2, '0')}`;
  }
  function msg(id, text) {
    const el = $(id);
    if (!el) return;
    el.textContent = text || '';
    el.hidden = !text;
  }

  async function loadMe(force) {
    if (ui.me && !force) return ui.me;
    try {
      const r = await API.me();
      ui.me = r.ok && r.data ? { email: r.data.email, has_totp: !!r.data.has_totp } : null;
    } catch (_) {
      ui.me = null;
    }
    return ui.me;
  }

  // ───────────── beheer (kluis open) ─────────────
  /** Waarom kan deze browser (nu) niet vertrouwd worden? null = kan wel. */
  function blockReason() {
    if (!ui.support.ok) return T.MESSAGES.trust_unsupported;
    if (!UI.state.db || !UI.state.secret) return HK.MESSAGES.no_secret;
    if (!UI.state.secret.kh) return T.MESSAGES.trust_needs_keyfile;
    if (!ui.me) return 'Je accountgegevens konden niet worden opgehaald. Probeer het opnieuw.';
    if (!ui.me.has_totp) return T.MESSAGES.trust_needs_totp;
    return null;
  }

  function renderPanel() {
    const why = blockReason();
    const trusted = !!ui.record;
    $('trust-add').hidden = trusted;
    $('trust-add').disabled = !!why || ui.busy;
    $('trust-label-row').hidden = trusted;
    $('trust-forget').hidden = !trusted;
    $('trust-forget').disabled = ui.busy;
    msg('trust-why', trusted ? '' : (why || ''));
    $('trust-local').textContent = trusted
      ? `Deze browser is vertrouwd als "${ui.record.label}". Op het ontgrendelscherm kun je de kluis met je telefoon openen.`
      : 'Deze browser is (nog) niet vertrouwd.';

    const body = $('trust-body');
    if (!ui.browsers.length) {
      body.innerHTML = '<tr><td colspan="4" class="muted">Geen vertrouwde browsers.</td></tr>';
      return;
    }
    body.innerHTML = ui.browsers.map((b) => {
      const self = ui.record && ui.record.browser_id === b.browser_id;
      const other = b.vault_id !== UI.state.vaultId ? ' <span class="muted">(andere kluis)</span>' : '';
      return `<tr data-browser="${esc(b.browser_id)}"><td>${esc(b.label)}${self ? ' <strong>(deze browser)</strong>' : ''}${other}</td>
        <td>${fmt(b.created_at)}</td><td>${fmt(b.last_used_at)}</td>
        <td><button type="button" class="danger" data-trust-revoke="${esc(b.browser_id)}">Intrekken</button></td></tr>`;
    }).join('');
  }

  async function refreshPanel() {
    if (!UI.state.db || !UI.state.vaultId) return;
    await loadMe(true);
    ui.record = ui.support.ok ? await T.findRecord({ vaultId: UI.state.vaultId }) : null;
    let listed = false;
    try {
      ui.browsers = await T.listTrusted();
      listed = true;
    } catch (e) {
      ui.browsers = [];
      msg('trust-error', T.messageFor(e));
    }
    // Lokaal record dat de server niet (meer) kent (ingetrokken, of trokken door rekey): sleutel opruimen.
    if (listed && ui.record && !ui.browsers.some((b) => b.browser_id === ui.record.browser_id)) {
      await T.deleteRecord(ui.record.browser_id);
      msg('trust-status', `"${ui.record.label}" was op de server ingetrokken; deze browser is niet meer vertrouwd.`);
      ui.record = null;
    }
    if (!$('trust-label').value) $('trust-label').value = T.defaultLabel();
    renderPanel();
  }

  /**
   * Wie via een vertrouwde browser is ingelogd, is na vergeten/intrekken/rekey uitgelogd (401 session_revoked).
   * Dan kluis dicht en naar het inlogscherm. Geeft true als de sessie nog geldig is.
   */
  async function checkSession() {
    let r = null;
    try { r = await API.me(); } catch (_) { return true; } // netwerkfout: niet zelf uitloggen
    if (r && r.status === 401) {
      if (UI.state.db) UI.lockVault();
      window.location.href = 'login.html?error=session_revoked';
      return false;
    }
    return true;
  }

  async function trustThis() {
    msg('trust-error', '');
    msg('trust-status', '');
    const why = blockReason();
    if (why) { msg('trust-error', why); return; }
    const label = ($('trust-label').value || '').trim() || T.defaultLabel();
    if (!T.labelOk(label)) { msg('trust-error', T.MESSAGES.invalid_label); return; }
    const vaultId = UI.state.vaultId;
    ui.busy = true;
    renderPanel();
    try {
      const rec = await T.trustBrowser({
        vaultId, email: ui.me.email, label, secret: UI.state.secret, wrap: (fn) => SU.withStepUp(fn),
      });
      msg('trust-status', `✓ Deze browser is vertrouwd als "${rec.label}".`);
    } catch (e) {
      msg('trust-error', T.messageFor(e));
    } finally {
      ui.busy = false;
      await refreshPanel();
    }
  }

  async function forgetThis() {
    msg('trust-error', '');
    msg('trust-status', '');
    if (!ui.record) return;
    if (!confirm(`Deze browser vergeten? De sleutel "${ui.record.label}" wordt hier gewist en op de server ingetrokken. `
      + 'Ontgrendelen met je telefoon kan daarna pas weer na opnieuw vertrouwen.')) return;
    const r = await T.forget(ui.record.browser_id);
    if (r.server) msg('trust-status', '✓ Deze browser is vergeten en ingetrokken.');
    else msg('trust-error', `De sleutel is hier gewist, maar intrekken op de server lukte niet (${T.messageFor(r.error)}). Trek hem in via de lijst.`);
    if (await checkSession()) await refreshPanel();
  }

  async function revokeOne(browserId) {
    msg('trust-error', '');
    msg('trust-status', '');
    const b = ui.browsers.find((x) => x.browser_id === browserId);
    const name = b ? b.label : 'deze browser';
    if (!confirm(`Vertrouwen van "${name}" intrekken? Die browser kan daarna niet meer zonder wachtwoord inloggen of met je telefoon ontgrendelen.`)) return;
    try {
      await T.revoke(browserId);
      if (ui.record && ui.record.browser_id === browserId) await T.deleteRecord(browserId);
      msg('trust-status', `✓ "${name}" ingetrokken.`);
    } catch (e) {
      msg('trust-error', T.messageFor(e));
    }
    if (await checkSession()) await refreshPanel();
  }

  // ───────────── ontgrendelen met de telefoon (kluis dicht) ─────────────
  async function refreshUnlock() {
    if (UI.state.db) { $('phone-unlock').hidden = true; return; }
    ui.unlockRecord = null;
    if (ui.support.ok) {
      try {
        const r = await API.listVaults();
        ui.lockedVaultId = r.ok && Array.isArray(r.data) && r.data.length ? r.data[0].id : null;
      } catch (_) {
        ui.lockedVaultId = null;
      }
      if (ui.lockedVaultId) ui.unlockRecord = await T.findRecord({ vaultId: ui.lockedVaultId });
    }
    $('phone-unlock').hidden = !ui.unlockRecord;
    $('phone-unlock-btn').disabled = !!ui.pending;
  }

  function showWaiting(on) {
    $('phone-unlock-wait').hidden = !on;
    $('phone-unlock-btn').hidden = on;
  }

  async function endPending({ cancel = false } = {}) {
    const p = ui.pending;
    ui.pending = null;
    if (!p) return;
    p.ctrl.abort();
    if (cancel) await T.cancelApproval(p.session);
    T.wipe(p.session);
  }

  async function logoutDenied() {
    try { await API.logout(); } catch (_) { /* de server trok de sessie al in */ }
    window.location.href = 'login.html?error=approval_denied';
  }

  async function unlockWithPhone() {
    msg('phone-unlock-error', '');
    msg('unlock-error', '');
    msg('phone-unlock-status', '');
    if (ui.pending || !ui.unlockRecord || !ui.lockedVaultId) return;
    const vaultId = ui.lockedVaultId;
    const record = ui.unlockRecord;
    $('phone-unlock-btn').disabled = true;
    let session;
    try {
      session = await T.startApproval({ vaultId, record });
    } catch (e) {
      $('phone-unlock-btn').disabled = false;
      if (e && (e.code === 'not_found' || e.code === 'signature_invalid')) await refreshUnlock();
      msg('phone-unlock-error', T.messageFor(e));
      return;
    }
    const ctrl = new AbortController();
    ui.pending = { session, ctrl };
    showWaiting(true);
    msg('phone-unlock-status', 'Open HorseSafe op je telefoon en keur goed.');
    let lastMinute = null;
    let secret = null;
    try {
      secret = await T.waitForDecision(session, {
        signal: ctrl.signal,
        onTick: (left) => {
          $('phone-unlock-countdown').textContent = mmss(left);
          const minute = Math.ceil(left / 60);
          if (lastMinute !== null && minute !== lastMinute && left > 0) {
            msg('phone-unlock-status', `Open HorseSafe op je telefoon en keur goed. Nog ${minute} minuut${minute === 1 ? '' : 'en'}.`);
          }
          lastMinute = minute;
        },
      });
      await endPending();
      showWaiting(false);
      msg('phone-unlock-status', 'Goedgekeurd. Kluis openen…');
      const creds = HK.credentialsFromHashes(secret);
      HK.wipeSecret(secret);
      secret = null;
      const ok = await UI.unlockOrCreate({ credentials: creds });
      msg('phone-unlock-status', '');
      // Kopie verouderd: unlockOrCreate toont zelf de melding van de hwkeys-flow (stale_copy).
      if (!ok) $('phone-unlock-btn').disabled = false;
    } catch (e) {
      const cancelled = e && e.code === 'cancelled';
      await endPending({ cancel: !cancelled && e && e.code !== 'approval_denied' && e.code !== 'approval_expired' });
      showWaiting(false);
      $('phone-unlock-btn').disabled = false;
      msg('phone-unlock-status', '');
      if (cancelled) return; // Annuleren meldt zelf
      msg('phone-unlock-error', T.messageFor(e));
      if (e && e.code === 'approval_denied') {
        $('phone-unlock-btn').disabled = true;
        setTimeout(logoutDenied, 2500);
      } else if (e && (e.code === 'not_authenticated' || e.code === 'invalid_token')) {
        setTimeout(() => { window.location.href = 'login.html'; }, 1500);
      }
    } finally {
      HK.wipeSecret(secret);
    }
  }

  async function cancelPhoneUnlock() {
    if (!ui.pending) return;
    await endPending({ cancel: true });
    showWaiting(false);
    $('phone-unlock-btn').disabled = false;
    msg('phone-unlock-status', 'Verzoek geannuleerd.');
  }

  // ───────────── koppelen ─────────────
  $('trust-add').addEventListener('click', trustThis);
  $('trust-forget').addEventListener('click', forgetThis);
  $('trust-body').addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-trust-revoke]');
    if (b) revokeOne(b.dataset.trustRevoke);
  });
  $('phone-unlock-btn').addEventListener('click', unlockWithPhone);
  $('phone-unlock-cancel').addEventListener('click', cancelPhoneUnlock);
  $('keys-open').addEventListener('click', () => { msg('trust-error', ''); msg('trust-status', ''); refreshPanel(); });
  document.addEventListener('horsesafe:unlocked', () => { $('phone-unlock').hidden = true; refreshPanel(); });
  // Na rekey: de server trok de vertrouwde browsers van deze kluis in (§14.7) en kh kan veranderd zijn.
  document.addEventListener('horsesafe:rekeyed', async () => { if (await checkSession()) await refreshPanel(); });
  document.addEventListener('horsesafe:locked', () => {
    ui.record = null;
    ui.browsers = [];
    msg('trust-error', '');
    msg('trust-status', '');
    refreshUnlock();
  });
  // Tab dicht tijdens een verzoek: op de server annuleren (best effort, keepalive).
  window.addEventListener('pagehide', () => {
    if (ui.pending) {
      ui.pending.ctrl.abort();
      T.cancelApproval(ui.pending.session, { keepalive: true });
      T.wipe(ui.pending.session);
      ui.pending = null;
    }
  });

  window.HorseSafeTrustUI = { refreshPanel, refreshUnlock };

  (async () => {
    ui.support = await T.checkSupport();
    await refreshUnlock();
  })();
})();
