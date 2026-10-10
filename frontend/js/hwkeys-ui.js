/* HorseSafe hardware-sleutels — schermkoppeling vault.html v0.2.0-Koblitz (docs/HARDWARE_KEYS.md §8, §12.13) */
(function () {
  'use strict';

  const HK = window.HorseSafeHwKeys;
  const UI = window.HorseSafeVaultUI;
  const SU = window.HorseSafeStepUp;
  const METHOD_KEY = 'horsesafe.unlockMethod';
  const ui = {
    support: { ok: false, reason: null },
    vaultId: null,
    keys: [],
    notify: true,
    stale: false,
    viaKey: false,
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
  function left(ts) {
    const s = Math.max(0, Math.round(ts - Date.now() / 1000));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return h ? `${h} u ${m} m` : `${m} m`;
  }
  function msg(id, text) {
    const el = $(id);
    if (!el) return;
    el.textContent = text || '';
    el.hidden = !text;
  }
  function explain(e) { return HK.messageFor(e); }

  function storeMethod(m) {
    try { localStorage.setItem(METHOD_KEY, m); } catch (_) { /* geen opslag: geen voorkeur */ }
  }
  function storedMethod() {
    try { return localStorage.getItem(METHOD_KEY); } catch (_) { return null; }
  }

  const find = (id) => (id ? ui.keys.find((k) => k.id === id) || null : null);
  const recState = (k) => (k && k.recovery ? k.recovery.state : null);

  /** Status in gewone taal. */
  function statusText(k) {
    let s;
    if (k.kind === 'bio') {
      s = 'klaar';
    } else {
      const r = k.recovery || {};
      switch (r.state) {
        case 'idle': s = 'in de kluis (klaar)'; break;
        case 'waiting': s = `wacht nog ${left(r.release_at)} (tot ${fmt(r.release_at)})`; break;
        case 'released': s = `vrijgegeven tot ${fmt(r.release_until)}`; break;
        case 'consumed': s = 'gebruikt'; break;
        case 'expired': s = 'verlopen'; break;
        case 'blocked': s = `geblokkeerd sinds ${fmt(r.blocked_at)}`; break;
        default: s = '—';
      }
    }
    return ui.stale ? `${s} · kopie verouderd` : s;
  }

  function recoveryButtons(k, { withDelete, withUnlock }) {
    const st = recState(k);
    const id = esc(k.id);
    const b = [];
    if (st === 'released' && withUnlock) b.push(`<button type="button" data-recover="${id}">🔑 Ontgrendel met noodsleutel</button>`);
    if (['idle', 'consumed', 'expired'].includes(st)) {
      const dis = ui.notify ? '' : ' disabled title="Meldingen zijn niet ingesteld"';
      b.push(`<button type="button" class="secondary" data-request="${id}"${dis}>Vrijgave aanvragen (24 uur wachttijd)</button>`);
    }
    if (st === 'waiting' || st === 'released') b.push(`<button type="button" class="secondary" data-cancel="${id}">Vrijgave annuleren</button>`);
    if (st === 'blocked') b.push(`<button type="button" class="secondary" data-unblock="${id}">Blokkade opheffen (YubiKey Bio)</button>`);
    else b.push(`<button type="button" class="danger" data-block="${id}">Blokkeren</button>`);
    if (withDelete) b.push(`<button type="button" class="danger" data-delete="${id}">Verwijder</button>`);
    return b.join(' ');
  }

  async function refresh() {
    if (!ui.vaultId || (UI.state.vaultId && UI.state.vaultId !== ui.vaultId)) {
      ui.vaultId = UI.state.vaultId || null;
      if (!ui.vaultId) {
        const r = await window.HorseSafeAPI.listVaults();
        if (!r.ok || !r.data || !r.data.length) { ui.keys = []; renderAll(); return; }
        ui.vaultId = r.data[0].id;
      }
    }
    try {
      const data = await HK.listKeys(ui.vaultId);
      ui.keys = data.keys || [];
      ui.notify = data.notify_available !== false;
    } catch (_) {
      ui.keys = [];
    }
    renderAll();
  }

  function renderAll() {
    renderUnlock();
    renderAlert();
    renderPanel();
  }

  // ───────────── vergrendeld scherm ─────────────
  function renderUnlock() {
    const bio = ui.keys.filter((k) => k.kind === 'bio' && k.status === 'active');
    const rec = ui.keys.filter((k) => k.kind === 'recovery');
    const any = bio.length || rec.length;
    $('hwkey-unlock').hidden = !any;
    if (!any) return;
    const sup = $('hwkey-support');
    if (!ui.support.ok) {
      sup.innerHTML = esc(HK.MESSAGES[ui.support.reason] || HK.MESSAGES.browser_unsupported)
        + (ui.support.reason === 'wrong_host' ? ` <a href="${esc(HK.HOME_URL)}">${esc(HK.HOME_URL)}</a>` : '');
      sup.hidden = false;
    } else {
      sup.hidden = true;
    }
    $('hwkey-unlock-btn').hidden = !ui.support.ok || !bio.length;
    $('recovery-details').hidden = !rec.length;
    $('recovery-notify').hidden = ui.notify;
    $('recovery-list').innerHTML = rec.map((k) => `<p><strong>${esc(k.label)}</strong> — ${esc(statusText(k))}<br>
      ${recoveryButtons(k, { withDelete: false, withUnlock: ui.support.ok })}</p>`).join('');

    // Laatst gebruikte methode bovenaan
    const box = $('hwkey-unlock');
    const form = $('unlock-form');
    if (storedMethod() === 'hwkey' && box.nextElementSibling !== form) form.parentNode.insertBefore(box, form);
    else if (storedMethod() !== 'hwkey' && form.nextElementSibling !== box) form.parentNode.insertBefore(box, form.nextSibling);
  }

  async function unlockWithKey() {
    msg('hwkey-unlock-error', '');
    msg('unlock-error', '');
    $('hwkey-unlock-btn').disabled = true;
    let secret = null;
    try {
      const r = await HK.unlock({ vaultId: ui.vaultId });
      secret = r.secret;
      const creds = HK.credentialsFromHashes(secret);
      ui.viaKey = true;
      const ok = await UI.unlockOrCreate({ credentials: creds });
      ui.viaKey = false;
      if (ok) {
        storeMethod('hwkey');
        ui.stale = false;
      }
    } catch (e) {
      ui.viaKey = false;
      msg('hwkey-unlock-error', explain(e));
      if (e && e.code === 'sign_count_regression') await refresh();
    } finally {
      HK.wipeSecret(secret);
      $('hwkey-unlock-btn').disabled = false;
    }
  }

  // ───────────── waarschuwing ─────────────
  function renderAlert() {
    const pending = ui.keys.filter((k) => ['waiting', 'released'].includes(recState(k)));
    const el = $('recovery-alert');
    if (!pending.length) { el.hidden = true; el.innerHTML = ''; return; }
    el.innerHTML = pending.map((k) => {
      const r = k.recovery;
      return `⚠ Er loopt een vrijgave voor noodsleutel <strong>${esc(k.label)}</strong>
      (aangevraagd ${fmt(r.release_requested_at)}, bruikbaar vanaf ${fmt(r.release_at)}).
      Niet door jou aangevraagd? <button type="button" class="danger" data-block="${esc(k.id)}">Blokkeren</button>
      <button type="button" class="secondary" data-cancel="${esc(k.id)}">Annuleren</button>`;
    }).join('<br>');
    el.hidden = false;
  }

  // ───────────── beheerpaneel ─────────────
  function renderPanel() {
    $('notify-banner').hidden = ui.notify;
    $('stale-banner').hidden = !ui.stale;
    const body = $('keys-body');
    if (!ui.keys.length) {
      body.innerHTML = '<tr><td colspan="6" class="muted">Nog geen sleutels gekoppeld.</td></tr>';
      return;
    }
    body.innerHTML = ui.keys.map((k) => {
      const kind = k.kind === 'bio' ? 'YubiKey Bio' : 'Noodsleutel';
      const actions = k.kind === 'recovery'
        ? recoveryButtons(k, { withDelete: true, withUnlock: false })
        : `<button type="button" class="danger" data-delete="${esc(k.id)}">Verwijder</button>`;
      const model = k.authenticator ? `<br><span class="muted">${esc(k.authenticator)}</span>` : '';
      return `<tr data-key="${esc(k.id)}"><td>${esc(k.label)}</td><td>${kind}${model}</td>
        <td>${fmt(k.created_at)}</td><td>${fmt(k.last_used_at)}</td><td class="key-status">${esc(statusText(k))}</td>
        <td>${actions}</td></tr>`;
    }).join('');
  }

  function setBusy(busy) {
    ['key-add-bio', 'key-add-recovery', 'keys-reseal', 'rekey-submit'].forEach((id) => { $(id).disabled = busy || !ui.support.ok; });
    $('rekey-submit').disabled = busy; // wachtwoord wijzigen kan ook zonder hardware-sleutelsteun
  }

  async function addKey(kind) {
    msg('keys-error', '');
    msg('keys-status', '');
    if (!UI.state.secret) { msg('keys-error', HK.MESSAGES.no_secret); return; }
    const label = ($('key-label').value || '').trim() || (kind === 'bio' ? 'YubiKey Bio' : 'Noodsleutel kluis');
    const intro = kind === 'bio'
      ? 'Steek de YubiKey Bio in. Je browser vraagt twee keer om je vingerafdruk (koppelen en controleren).'
      : 'Steek de RESERVE-YubiKey in.\n\n• Hij moet een PIN van 63 tekens hebben; bewaar die PIN NIET bij de sleutel.\n• Leg de sleutel daarna in je fysieke kluis.\n• Hij werkt pas 24 uur na een vrijgave-aanvraag.';
    if (!confirm(intro)) return;
    setBusy(true);
    try {
      await SU.withStepUp(() => HK.enroll({ vaultId: ui.vaultId, kind, label, secret: UI.state.secret }));
      $('key-label').value = '';
      msg('keys-status', `✓ "${label}" gekoppeld.`);
      await refresh();
    } catch (e) {
      msg('keys-error', explain(e));
    } finally {
      setBusy(false);
    }
  }

  async function resealAll() {
    msg('keys-error', '');
    msg('keys-status', '');
    if (!UI.state.secret) { msg('keys-error', HK.MESSAGES.no_secret); return; }
    if (!ui.keys.length) { msg('keys-error', 'Er zijn geen sleutels om bij te werken.'); return; }
    if (!confirm('Alle sleutels bijwerken met het wachtwoord/de keyfile waarmee de kluis nu open is?')) return;
    setBusy(true);
    try {
      const n = await SU.withStepUp(() => HK.resealAll({ vaultId: ui.vaultId, keys: ui.keys, secret: UI.state.secret }));
      ui.stale = false;
      msg('keys-status', `✓ ${n} sleutel(s) bijgewerkt.`);
      await refresh();
    } catch (e) {
      msg('keys-error', explain(e));
    } finally {
      setBusy(false);
    }
  }

  // ───────────── wachtwoord/keyfile wijzigen (/rekey) ─────────────
  async function rekey(ev) {
    ev.preventDefault();
    msg('rekey-error', '');
    msg('rekey-status', '');
    const db = UI.state.db;
    if (!db) { msg('rekey-error', HK.MESSAGES.no_secret); return; }
    const pw = $('rekey-pw').value;
    const pw2 = $('rekey-pw2').value;
    const file = $('rekey-keyfile').files && $('rekey-keyfile').files[0];
    if (!pw && !file) { msg('rekey-error', 'Kies een nieuw wachtwoord, een nieuwe keyfile, of beide.'); return; }
    if (pw && pw.length < 12) { msg('rekey-error', 'Het nieuwe wachtwoord moet minimaal 12 tekens zijn.'); return; }
    if (pw !== pw2) { msg('rekey-error', 'De wachtwoorden zijn niet gelijk.'); return; }
    if (!confirm('Wachtwoord/keyfile van deze kluis wijzigen? Gekoppelde YubiKeys worden meteen bijgewerkt. '
      + 'Bewaar het nieuwe wachtwoord en/of de nieuwe keyfile goed: zonder kun je de kluis in KeePassXC niet meer openen.')) return;

    const kdb = window.kdbxweb;
    const kfBytes = file ? new Uint8Array(await file.arrayBuffer()) : null;
    const newCreds = new kdb.Credentials(pw ? kdb.ProtectedValue.fromString(pw) : null, kfBytes);
    $('rekey-pw').value = '';
    $('rekey-pw2').value = '';
    let newSecret = null;
    const oldCreds = db.credentials;
    $('rekey-submit').disabled = true;
    try {
      await newCreds.ready;
      newSecret = await HK.secretFromCredentials(newCreds);
      db.credentials = newCreds;
      const blob = await window.HorseSafeCrypto.saveDatabase(db);
      const r = await SU.withStepUp(async () => {
        const { keys } = await HK.listKeys(ui.vaultId);
        return HK.rekey({ vaultId: ui.vaultId, etag: UI.state.etag, blob, keys, secret: newSecret });
      });
      await UI.adoptRekey(r.etag);
      $('rekey-keyfile').value = '';
      ui.stale = false;
      msg('rekey-status', `✓ Gewijzigd. ${r.resealed} sleutel(s) bijgewerkt.`);
      await refresh();
    } catch (e) {
      db.credentials = oldCreds; // kluis blijft open met het oude materiaal
      msg('rekey-error', explain(e));
    } finally {
      HK.wipeSecret(newSecret);
      if (kfBytes) kfBytes.fill(0);
      $('rekey-submit').disabled = false;
    }
  }

  // ───────────── klikken (gedelegeerd) ─────────────
  async function onClick(ev) {
    const t = ev.target.closest('button');
    if (!t || !t.dataset) return;
    const d = t.dataset;
    const id = d.request || d.cancel || d.block || d.unblock || d.recover || d.delete;
    if (!id) return;
    const k = find(id);
    const errTarget = UI.state.db ? 'keys-error' : 'hwkey-unlock-error';
    msg(errTarget, '');
    if (!k) { msg(errTarget, 'Deze sleutel bestaat niet meer. De lijst is bijgewerkt.'); await refresh(); return; }
    try {
      if (d.request) {
        if (!confirm(`Vrijgave aanvragen voor "${k.label}"? Hij werkt over 24 uur; je krijgt een melding.`)) return;
        await HK.requestRelease(ui.vaultId, k.id);
      } else if (d.cancel) {
        await HK.cancelRelease(ui.vaultId, k.id);
      } else if (d.block) {
        if (!confirm(`Noodsleutel "${k.label}" blokkeren? Opheffen kan daarna alleen met je YubiKey Bio.`)) return;
        await HK.block(ui.vaultId, k.id);
      } else if (d.unblock) {
        await SU.withStepUp(() => HK.unblock(ui.vaultId, k.id), { bioOnly: true });
      } else if (d.recover) {
        await unlockWithKey();
        return;
      } else if (d.delete) {
        if (!confirm(`Sleutel "${k.label}" ontkoppelen? Je wachtwoord/keyfile blijft gewoon werken.`)) return;
        await HK.deleteKey(ui.vaultId, k.id);
      }
      await refresh();
    } catch (e) {
      msg(errTarget, explain(e));
      await refresh();
    }
  }

  document.addEventListener('click', (ev) => {
    if (ev.target.closest('#recovery-alert, #recovery-list, #keys-body')) onClick(ev);
  });
  $('hwkey-unlock-btn').addEventListener('click', unlockWithKey);
  $('keys-open').addEventListener('click', async () => {
    $('keys-section').hidden = false;
    msg('keys-error', ui.support.ok ? '' : (HK.MESSAGES[ui.support.reason] || HK.MESSAGES.browser_unsupported));
    setBusy(false);
    await refresh();
  });
  $('keys-close').addEventListener('click', () => { $('keys-section').hidden = true; });
  $('key-add-bio').addEventListener('click', () => addKey('bio'));
  $('key-add-recovery').addEventListener('click', () => addKey('recovery'));
  $('keys-reseal').addEventListener('click', resealAll);
  $('rekey-form').addEventListener('submit', rekey);
  document.addEventListener('horsesafe:unlocked', () => {
    if (!ui.viaKey) storeMethod('password');
    refresh();
  });
  document.addEventListener('horsesafe:locked', () => { $('keys-section').hidden = true; refresh(); });
  document.addEventListener('horsesafe:stale-copy', () => { ui.stale = true; renderAll(); });

  (async () => {
    ui.support = await HK.checkSupport();
    await refresh();
  })();
})();
