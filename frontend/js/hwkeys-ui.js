/* HorseSafe hardware-sleutels — schermkoppeling vault.html v0.2.0-Koblitz */
(function () {
  'use strict';

  const HK = window.HorseSafeHwKeys;
  const UI = window.HorseSafeVaultUI;
  const ui = { supported: false, vaultId: null, keys: [] };

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }
  function fmt(ts) {
    return ts ? new Date(ts * 1000).toLocaleString('nl-NL', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  }
  function msg(id, text) {
    const el = $(id);
    el.textContent = text || '';
    el.hidden = !text;
  }

  function recoveryState(k) {
    if (!k.release_at) return 'idle';
    const t = Date.now() / 1000;
    if (t < k.release_at) return 'waiting';
    if (k.release_until && t < k.release_until) return 'released';
    return 'expired';
  }

  function explain(e) {
    if (!e) return 'Onbekende fout.';
    if (e.name === 'NotAllowedError') return 'Geannuleerd of verlopen. Probeer het opnieuw en leg je vinger op de sleutel.';
    if (e.name === 'InvalidStateError') return 'Deze sleutel is al gekoppeld.';
    if (e.code === 'recovery_waiting') return 'Deze noodsleutel is nog niet vrijgegeven (wachttijd loopt).';
    if (e.code === 'recovery_idle' || e.code === 'recovery_expired') return 'Vraag eerst vrijgave aan voor deze noodsleutel.';
    if (e.code === 'credential_exists') return 'Deze sleutel is al gekoppeld.';
    if (e.code === 'too_many_keys') return 'Het maximale aantal sleutels is bereikt.';
    return e.message || String(e);
  }

  async function refresh() {
    if (!ui.vaultId) {
      const r = await window.HorseSafeAPI.listVaults();
      if (!r.ok || !r.data || !r.data.length) return;
      ui.vaultId = r.data[0].id;
    }
    try {
      ui.keys = await HK.listKeys(ui.vaultId);
    } catch (_) {
      ui.keys = [];
    }
    renderUnlock();
    renderAlert();
    renderPanel();
  }

  // ───────────── vergrendeld scherm ─────────────
  function renderUnlock() {
    const bio = ui.keys.filter((k) => k.kind === 'bio');
    const rec = ui.keys.filter((k) => k.kind === 'recovery');
    $('hwkey-unlock').hidden = !ui.supported || (!bio.length && !rec.length);
    $('hwkey-unlock-btn').hidden = !bio.length;
    $('recovery-details').hidden = !rec.length;
    $('recovery-list').innerHTML = rec.map((k) => {
      const st = recoveryState(k);
      let body;
      if (st === 'waiting') {
        body = `Aangevraagd ${fmt(k.release_requested_at)} — bruikbaar vanaf <strong>${fmt(k.release_at)}</strong>.
          <button type="button" class="secondary" data-cancel="${esc(k.id)}">Annuleren</button>`;
      } else if (st === 'released') {
        body = `Vrijgegeven tot ${fmt(k.release_until)}.
          <button type="button" data-recover="${esc(k.id)}">🔑 Ontgrendel met noodsleutel</button>`;
      } else {
        body = `<button type="button" class="secondary" data-request="${esc(k.id)}">Vrijgave aanvragen (24 uur wachttijd)</button>`;
      }
      return `<p><strong>${esc(k.label)}</strong><br>${body}</p>`;
    }).join('');
  }

  async function openWithSecret(secret) {
    return UI.unlockOrCreate({ pw: secret.pw, keyFileBuffer: HK.keyfileFromB64(secret.kf) });
  }

  async function unlockWith(keys) {
    msg('hwkey-unlock-error', '');
    $('hwkey-unlock-btn').disabled = true;
    try {
      const { secret } = await HK.unlock({ vaultId: ui.vaultId, keys });
      const ok = await openWithSecret(secret);
      secret.pw = null;
      secret.kf = null;
      if (!ok) msg('hwkey-unlock-error', 'De sleutel gaf materiaal terug, maar de kluis ging niet open. Is het wachtwoord of de keyfile veranderd? Open met je keyfile en kies "Opnieuw verzegelen".');
    } catch (e) {
      msg('hwkey-unlock-error', explain(e));
    } finally {
      $('hwkey-unlock-btn').disabled = false;
    }
  }

  // ───────────── waarschuwing ─────────────
  function renderAlert() {
    const pending = ui.keys.filter((k) => k.kind === 'recovery' && ['waiting', 'released'].includes(recoveryState(k)));
    const el = $('recovery-alert');
    if (!pending.length) { el.hidden = true; el.innerHTML = ''; return; }
    el.innerHTML = pending.map((k) => `⚠ Er loopt een vrijgave voor noodsleutel <strong>${esc(k.label)}</strong>
      (aangevraagd ${fmt(k.release_requested_at)}, bruikbaar vanaf ${fmt(k.release_at)}).
      Niet door jou aangevraagd? <button type="button" class="danger" data-cancel="${esc(k.id)}">Nu annuleren</button>`).join('<br>');
    el.hidden = false;
  }

  // ───────────── beheerpaneel ─────────────
  function renderPanel() {
    const body = $('keys-body');
    if (!ui.keys.length) {
      body.innerHTML = '<tr><td colspan="6" class="muted">Nog geen sleutels gekoppeld.</td></tr>';
      return;
    }
    body.innerHTML = ui.keys.map((k) => {
      let status = '—';
      if (k.kind === 'recovery') {
        const st = recoveryState(k);
        status = st === 'waiting' ? `wachttijd tot ${fmt(k.release_at)} <button type="button" class="secondary" data-cancel="${esc(k.id)}">Annuleren</button>`
          : st === 'released' ? `vrijgegeven tot ${fmt(k.release_until)}` : 'in de kluis';
      }
      return `<tr><td>${esc(k.label)}</td><td>${k.kind === 'bio' ? 'YubiKey Bio' : 'Noodsleutel'}</td>
        <td>${fmt(k.created_at)}</td><td>${fmt(k.last_used_at)}</td><td>${status}</td>
        <td><button type="button" class="danger" data-delete="${esc(k.id)}">Verwijder</button></td></tr>`;
    }).join('');
  }

  async function addKey(kind) {
    msg('keys-error', '');
    msg('keys-status', '');
    if (!UI.state.secret) { msg('keys-error', 'Open de kluis eerst.'); return; }
    const label = ($('key-label').value || '').trim() || (kind === 'bio' ? 'YubiKey Bio' : 'Noodsleutel kluis');
    const intro = kind === 'bio'
      ? 'Steek de YubiKey Bio in. Je browser vraagt om je vingerafdruk (twee keer bij sommige sleutels).'
      : 'Steek de RESERVE-YubiKey in.\n\n• Geef hem een extreem lange PIN (63 tekens) en bewaar die PIN NIET bij de sleutel.\n• Leg de sleutel daarna in je fysieke kluis.\n• Hij werkt pas 24 uur na een vrijgave-aanvraag.';
    if (!confirm(intro)) return;
    ['key-add-bio', 'key-add-recovery'].forEach((id) => { $(id).disabled = true; });
    try {
      await HK.enroll({ vaultId: ui.vaultId, kind, label, secret: UI.state.secret, existingKeys: ui.keys });
      $('key-label').value = '';
      msg('keys-status', `✓ "${label}" gekoppeld.`);
      await refresh();
    } catch (e) {
      msg('keys-error', explain(e));
    } finally {
      ['key-add-bio', 'key-add-recovery'].forEach((id) => { $(id).disabled = false; });
    }
  }

  async function resealAll() {
    msg('keys-error', '');
    msg('keys-status', '');
    if (!UI.state.secret) { msg('keys-error', 'Open de kluis eerst.'); return; }
    if (!ui.keys.length) { msg('keys-error', 'Er zijn geen sleutels om te verzegelen.'); return; }
    if (!confirm('Alle sleutels opnieuw verzegelen met het wachtwoord/de keyfile waarmee de kluis nu open is?')) return;
    try {
      const n = await HK.resealAll({ vaultId: ui.vaultId, keys: ui.keys, secret: UI.state.secret });
      msg('keys-status', `✓ ${n} sleutel(s) opnieuw verzegeld.`);
    } catch (e) {
      msg('keys-error', explain(e));
    }
  }

  // ───────────── klikken (gedelegeerd) ─────────────
  document.addEventListener('click', async (ev) => {
    const t = ev.target.closest('button');
    if (!t) return;
    const find = (id) => ui.keys.find((k) => k.id === id);
    try {
      if (t.dataset.request) {
        const k = find(t.dataset.request);
        if (!confirm(`Vrijgave aanvragen voor "${k.label}"? Hij werkt over 24 uur; je krijgt een melding.`)) return;
        const r = await HK.requestRelease(ui.vaultId, k.id);
        if (!r.ok) throw new Error('Aanvraag mislukt: ' + r.status);
        await refresh();
      } else if (t.dataset.cancel) {
        const r = await HK.cancelRelease(ui.vaultId, t.dataset.cancel);
        if (!r.ok) throw new Error('Annuleren mislukt: ' + r.status);
        await refresh();
      } else if (t.dataset.recover) {
        await unlockWith([find(t.dataset.recover)]);
      } else if (t.dataset.delete) {
        const k = find(t.dataset.delete);
        if (!confirm(`Sleutel "${k.label}" ontkoppelen? Je wachtwoord/keyfile blijft gewoon werken.`)) return;
        const r = await HK.deleteKey(ui.vaultId, k.id);
        if (!r.ok) throw new Error('Verwijderen mislukt: ' + r.status);
        await refresh();
      }
    } catch (e) {
      const target = UI.state.db ? 'keys-error' : 'hwkey-unlock-error';
      msg(target, explain(e));
    }
  });

  $('hwkey-unlock-btn').addEventListener('click', () => unlockWith(ui.keys.filter((k) => k.kind === 'bio')));
  $('keys-open').addEventListener('click', async () => {
    $('keys-section').hidden = false;
    if (!ui.supported) {
      msg('keys-error', 'Deze browser ondersteunt geen hardware-sleutels met PRF/X25519. Gebruik een recente Chrome of Edge.');
      ['key-add-bio', 'key-add-recovery'].forEach((id) => { $(id).disabled = true; });
    }
    await refresh();
  });
  $('keys-close').addEventListener('click', () => { $('keys-section').hidden = true; });
  $('key-add-bio').addEventListener('click', () => addKey('bio'));
  $('key-add-recovery').addEventListener('click', () => addKey('recovery'));
  $('keys-reseal').addEventListener('click', resealAll);
  document.addEventListener('horsesafe:unlocked', refresh);
  document.addEventListener('horsesafe:locked', () => { $('keys-section').hidden = true; refresh(); });

  (async () => {
    ui.supported = await HK.isSupported();
    await refresh();
  })();
})();
