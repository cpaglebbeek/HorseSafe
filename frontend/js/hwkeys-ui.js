/* HorseSafe hardware-sleutels — schermkoppeling vault.html v0.2.0-Koblitz (docs/HARDWARE_KEYS.md §8, §12.13)
 * v0.3.4-Miller: telefoonsleutels (kind 'phone', §13) in de lijst; toestel verwijderen via DELETE /devices/{id}.
 */
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

  /** Soort + model voor tabel en bevestigingen. */
  function kindText(k) {
    if (k.kind === 'phone') return 'Telefoon';
    return k.kind === 'bio' ? 'YubiKey Bio' : 'Noodsleutel';
  }
  function modelText(k) {
    if (k.kind === 'phone') return (k.device && k.device.model) || '';
    return k.authenticator || '';
  }
  /** Telefoon: het toestellabel uit de koppeling; anders het sleutellabel. */
  function labelText(k) {
    return (k.kind === 'phone' && k.device && k.device.label) || k.label;
  }

  /** Status in gewone taal. */
  function statusText(k) {
    let s;
    if (k.kind === 'bio' || k.kind === 'phone') {
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
    const pins = UI.pins();
    body.innerHTML = ui.keys.map((k) => {
      const kind = kindText(k);
      let actions;
      if (k.kind === 'recovery') actions = recoveryButtons(k, { withDelete: true, withUnlock: false });
      else if (k.kind === 'phone' && k.device && k.device.id) actions = `<button type="button" class="danger" data-device="${esc(k.device.id)}" data-key-id="${esc(k.id)}">Toestel verwijderen</button>`;
      else actions = `<button type="button" class="danger" data-delete="${esc(k.id)}">Verwijder</button>`;
      const model = modelText(k) ? `<br><span class="muted">${esc(modelText(k))}</span>` : '';
      // Kluis open: klopt de publieke sleutel met wat de kluis bij het koppelen vastlegde? (reviewronde 2)
      const pin = UI.state.db ? HK.pinStatus(k, pins) : 'ok';
      const pinWarn = pin === 'mismatch' ? '<br><strong class="error">⚠ publieke sleutel gewijzigd — verwijderen en opnieuw koppelen</strong>'
        : pin === 'missing' ? '<br><strong class="error">⚠ niet in de kluis vastgelegd — verwijderen en opnieuw koppelen</strong>' : '';
      return `<tr data-key="${esc(k.id)}"><td>${esc(labelText(k))}</td><td>${kind}${model}</td>
        <td>${fmt(k.created_at)}</td><td>${fmt(k.last_used_at)}</td><td class="key-status">${esc(statusText(k))}${pinWarn}</td>
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
      await SU.withStepUp(() => HK.enroll({
        vaultId: ui.vaultId, kind, label, secret: UI.state.secret, pin: (kid, pk) => UI.pinKey(kid, pk),
      }));
      $('key-label').value = '';
      msg('keys-status', `✓ "${label}" gekoppeld.`);
      await refresh();
    } catch (e) {
      msg('keys-error', explain(e));
    } finally {
      setBusy(false);
    }
  }

  /**
   * Wie krijgt het ontgrendelmateriaal? Vóór reseal/rekey toont de client elke sleutel die een
   * kopie krijgt (label, type, model, koppeldatum; recent gekoppeld gemarkeerd). Een sleutel die
   * een aanvaller koppelde krijgt zo nooit stil het echte {ph, kh} (reviewbevinding 2).
   */
  const RECENT_KEY_SECONDS = 7 * 24 * 3600;
  function confirmRecipients(keys, what) {
    if (!keys.length) return true;
    const now = Date.now() / 1000;
    const lines = keys.map((k) => {
      const kind = kindText(k);
      const model = modelText(k) ? `, ${modelText(k)}` : '';
      const recent = k.created_at && now - k.created_at < RECENT_KEY_SECONDS ? '  ⚠ RECENT GEKOPPELD' : '';
      return `• ${labelText(k)} (${kind}${model}), gekoppeld ${fmt(k.created_at)}${recent}`;
    });
    return confirm(`Deze sleutels krijgen toegang tot ${what}:\n\n${lines.join('\n')}\n\n`
      + 'Herken je ze allemaal? Zo niet: kies Annuleren en verwijder eerst de sleutel die je niet herkent.');
  }

  async function resealAll() {
    msg('keys-error', '');
    msg('keys-status', '');
    if (!UI.state.secret) { msg('keys-error', HK.MESSAGES.no_secret); return; }
    await refresh();
    if (!ui.keys.length) { msg('keys-error', 'Er zijn geen sleutels om bij te werken.'); return; }
    const keys = ui.keys.slice();
    if (!confirmRecipients(keys, 'het wachtwoord/de keyfile waarmee de kluis nu open is')) return;
    setBusy(true);
    try {
      const n = await SU.withStepUp(() => HK.resealAll({ vaultId: ui.vaultId, keys, secret: UI.state.secret, pins: UI.pins() }));
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
    const removePw = $('rekey-pw-remove').checked;
    const removeKf = $('rekey-kf-remove').checked;
    // Leeg veld = huidig onderdeel behouden; verwijderen alleen via het vinkje (reviewbevinding 4).
    if (!pw && !file && !removePw && !removeKf) { msg('rekey-error', HK.MESSAGES.rekey_nothing); return; }
    if ((pw && removePw) || (file && removeKf)) { msg('rekey-error', HK.MESSAGES.rekey_conflict); return; }
    if (pw && pw.length < 12) { msg('rekey-error', 'Het nieuwe wachtwoord moet minimaal 12 tekens zijn.'); return; }
    if (pw !== pw2) { msg('rekey-error', 'De wachtwoorden zijn niet gelijk.'); return; }
    const removing = [removePw && 'het huidige wachtwoord', removeKf && 'de huidige keyfile'].filter(Boolean);
    let question = 'Wachtwoord/keyfile van deze kluis wijzigen? Gekoppelde YubiKeys worden meteen bijgewerkt. '
      + 'Bewaar het nieuwe wachtwoord en/of de nieuwe keyfile goed: zonder kun je de kluis in KeePassXC niet meer openen.';
    if (removing.length) {
      question += `\n\nLet op: je verwijdert ${removing.join(' en ')}. Daarna opent de kluis (ook in KeePassXC) zonder dat onderdeel.`;
    }
    if (!confirm(question)) return;
    await refresh();
    const confirmed = new Set(ui.keys.map((k) => k.id));
    if (!confirmRecipients(ui.keys, 'het nieuwe wachtwoord/de nieuwe keyfile')) return;

    // Eigen buffer voor de keyfile; credentialsForRekey geeft kdbxweb een kopie, dus wissen mag.
    const kfBytes = file ? new Uint8Array(await file.arrayBuffer()) : null;
    $('rekey-pw').value = '';
    $('rekey-pw2').value = '';
    let newSecret = null;
    let blob = null;
    let done = false;
    const oldCreds = db.credentials;
    const pins = UI.pins();
    $('rekey-submit').disabled = true;
    try {
      const built = await HK.credentialsForRekey({
        current: oldCreds,
        password: pw || null,
        keyFile: kfBytes,
        removePassword: removePw,
        removeKeyFile: removeKf,
      });
      newSecret = built.secret;
      db.credentials = built.credentials;
      blob = await window.HorseSafeCrypto.saveDatabase(db);
      let r;
      try {
        r = await SU.withStepUp(async () => {
          const { keys } = await HK.listKeys(ui.vaultId);
          if (keys.some((k) => !confirmed.has(k.id))) throw new HK.HwKeyError('keys_changed');
          return HK.rekey({ vaultId: ui.vaultId, etag: UI.state.etag, blob, keys, secret: newSecret, pins });
        });
      } catch (e) {
        // Onbekende uitkomst (time-out/504/netwerk): de server kan al gecommit hebben (reviewronde 2).
        if (!e || e.code !== 'rekey_unknown') throw e;
        const check = await HK.rekeyLanded({ vaultId: ui.vaultId, blob });
        if (check.state === 'not_landed') throw new HK.HwKeyError('rekey_not_applied');
        if (check.state === 'unknown') {
          // Niet vast te stellen: nooit verder werken met mogelijk verkeerde credentials/etag.
          UI.lockVault();
          msg('unlock-error', 'Onbekend of het wijzigen van wachtwoord/keyfile is gelukt (geen antwoord van de server). '
            + 'De kluis is vergrendeld. Probeer eerst het NIEUWE wachtwoord/de nieuwe keyfile, daarna het oude. '
            + 'Gooi geen van beide weg.');
          return;
        }
        r = { etag: check.etag, resealed: null };
      }
      // Vanaf hier is de rekey doorgevoerd: nooit meer terug naar de oude credentials.
      done = true;
      try {
        await UI.adoptRekey(r.etag);
      } catch (_) {
        UI.state.etag = r.etag; // kluis blijft open met het nieuwe materiaal; sleutels koppelen vraagt opnieuw openen
      }
      $('rekey-keyfile').value = '';
      $('rekey-pw-remove').checked = false;
      $('rekey-kf-remove').checked = false;
      ui.stale = false;
      msg('rekey-status', r.resealed === null
        ? '✓ Gewijzigd (bevestigd na een vertraagd antwoord van de server). Gebruik vanaf nu het nieuwe wachtwoord/de nieuwe keyfile.'
        : `✓ Gewijzigd. ${r.resealed} sleutel(s) bijgewerkt.`);
      await refresh();
      // v0.4.0-Montgomery: CK is veranderd (o.a. keyfile erbij/eraf); trust-ui.js werkt zijn knop en lijst bij.
      document.dispatchEvent(new CustomEvent('horsesafe:rekeyed'));
    } catch (e) {
      if (!done) db.credentials = oldCreds; // niets doorgevoerd: kluis blijft open met het oude materiaal
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
    if (d.device) { await removeDevice(d.device, d.keyId); return; }
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

  /** v0.3.4-Miller: telefoon ontkoppelen = toestel intrekken (§13.4 DELETE /devices/{id}; alle kopieën weg). */
  async function removeDevice(deviceId, keyId) {
    msg('keys-error', '');
    msg('keys-status', '');
    const k = find(keyId);
    const name = k ? labelText(k) : 'dit toestel';
    const others = ui.keys.filter((x) => x.kind === 'phone' && x.device && x.device.id === deviceId).length;
    if (!confirm(`Telefoon "${name}" verwijderen?\n\nHet toestel wordt ingetrokken: het kan daarna geen enkele kluis meer `
      + `openen en de verzegelde kopie${others > 1 ? 'ën' : ''} op de server ${others > 1 ? 'worden' : 'wordt'} gewist. `
      + 'Je wachtwoord/keyfile blijft gewoon werken.')) return;
    try {
      await window.HorseSafePairing.revokeDevice(deviceId);
      msg('keys-status', `✓ Telefoon "${name}" verwijderd.`);
    } catch (e) {
      msg('keys-error', window.HorseSafePairing.messageFor(e && (e.code === 'not_found' || e.code === 'api_404') ? { code: 'device_not_found' } : e));
    }
    await refresh();
  }

  document.addEventListener('click', (ev) => {
    if (ev.target.closest('#recovery-alert, #recovery-list, #keys-body')) onClick(ev);
  });
  $('hwkey-unlock-btn').addEventListener('click', unlockWithKey);
  $('keys-open').addEventListener('click', async () => {
    $('keys-section').hidden = false;
    // HS-BUG-011: paneel in beeld brengen; zonder dit leek de knop niets te doen bij een lange lijst
    $('keys-section').scrollIntoView({ block: 'start', behavior: 'smooth' });
    $('keys-title').focus({ preventScroll: true });
    msg('keys-error', ui.support.ok ? '' : (HK.MESSAGES[ui.support.reason] || HK.MESSAGES.browser_unsupported));
    setBusy(false);
    await refresh();
  });
  $('keys-close').addEventListener('click', () => {
    $('keys-section').hidden = true;
    $('keys-open').focus();
  });
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

  // v0.3.4-Miller: pairing-ui.js ververst de lijst na een geslaagde koppeling
  window.HorseSafeKeysUI = { refresh };

  (async () => {
    ui.support = await HK.checkSupport();
    await refresh();
  })();
})();
