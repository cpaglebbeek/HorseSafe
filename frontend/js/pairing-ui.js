/* HorseSafe telefoon koppelen — schermkoppeling vault.html v0.3.4-Miller (S17, docs/HARDWARE_KEYS.md §13.3)
 *
 *   "📱 Telefoon koppelen" → (step-up bij 403) → QR + aftelling 300 s → pollen (1 s) tot claimed
 *   → mac_web controleren (fout: DELETE + "Koppeling niet vertrouwd") → SAS groot + toestel
 *   → "Klopt": Seal_v2 naar pk_c + vastleggen in de kluis + POST confirm → lijst verversen
 *   → "Klopt niet" / Annuleren / verlopen / kluis vergrendeld: DELETE.
 *
 * De QR wordt als SVG-elementen opgebouwd (geen innerHTML, geen inline script: past in de CSP
 * script-src 'self'). s en k_web worden na afloop gewist (pairing.js wipe).
 */
(function () {
  'use strict';

  const P = window.HorseSafePairing;
  const UI = window.HorseSafeVaultUI;
  const SU = window.HorseSafeStepUp;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const QR_MARGIN = 4; // stille zone in modules (QR-norm)

  let cur = null; // { session, ctrl }
  let supportOk = true;

  function $(id) { return document.getElementById(id); }

  function setError(text) {
    const el = $('pair-error');
    el.textContent = text || '';
    el.hidden = !text;
  }
  function setStatus(text) { $('pair-status').textContent = text || ''; }

  function mmss(n) {
    const m = Math.floor(n / 60);
    const s = n % 60;
    return `${m}:${String(s).padStart(2, '0')}`;
  }

  /** SAS als "267 364" (leesbaar), met aria-label per cijfer zodat een schermlezer cijfers voorleest. */
  function showSas(sas) {
    const el = $('pair-sas');
    el.textContent = `${sas.slice(0, 3)} ${sas.slice(3)}`;
    el.setAttribute('aria-label', `Code ${sas.split('').join(' ')}`);
  }

  // ───────────── QR (vendor/qrcode, qrcode-generator 2.0.4) ─────────────
  function clearQr() {
    const box = $('pair-qr');
    while (box.firstChild) box.removeChild(box.firstChild);
  }

  function renderQr(text) {
    clearQr();
    const qr = window.qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const size = n + 2 * QR_MARGIN;
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
    svg.setAttribute('shape-rendering', 'crispEdges');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    const bg = document.createElementNS(SVG_NS, 'rect');
    bg.setAttribute('width', String(size));
    bg.setAttribute('height', String(size));
    bg.setAttribute('fill', '#ffffff');
    svg.appendChild(bg);
    let d = '';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) d += `M${c + QR_MARGIN} ${r + QR_MARGIN}h1v1h-1z`;
      }
    }
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', '#000000');
    svg.appendChild(path);
    $('pair-qr').appendChild(svg);
  }

  // ───────────── weergave ─────────────
  function showStep(step) {
    $('pair-step-qr').hidden = step !== 'qr';
    $('pair-step-sas').hidden = step !== 'sas';
    $('pair-cancel').textContent = step ? 'Annuleren' : 'Sluiten';
  }

  function setSasBusy(busy) {
    $('pair-sas-ok').disabled = busy;
    $('pair-sas-bad').disabled = busy;
  }

  function updateButton() {
    $('phone-pair').disabled = !!cur || !UI.state.db;
  }

  /** Sessie afsluiten: geheimen wissen, QR weg. De melding (status/fout) blijft staan. */
  function end() {
    if (cur) {
      cur.ctrl.abort();
      P.wipe(cur.session);
    }
    cur = null;
    clearQr();
    $('pair-sas').textContent = '';
    ['pair-device-label', 'pair-device-model', 'pair-device-app'].forEach((id) => { $(id).textContent = ''; });
    showStep(null);
    setSasBusy(false);
    updateButton();
  }

  async function abortWith(errorCode) {
    const c = cur;
    if (c) {
      c.ctrl.abort(); // eerst het pollen stoppen, dan pas DELETE (anders ziet de poll zelf 'cancelled')
      await P.cancel(c.session);
    }
    end();
    if (errorCode) setError(P.messageFor({ code: errorCode }));
  }

  // ───────────── flow ─────────────
  async function startPairing() {
    setError('');
    setStatus('');
    if (cur) return;
    if (!supportOk) {
      $('pair-section').hidden = false;
      showStep(null);
      setError(P.MESSAGES.pairing_unsupported);
      return;
    }
    if (!UI.state.db || !UI.state.secret || !UI.state.vaultId) {
      $('pair-section').hidden = false;
      showStep(null);
      setError(P.messageFor({ code: 'no_secret' }));
      return;
    }
    const vaultId = UI.state.vaultId;
    $('pair-section').hidden = false;
    $('phone-pair').disabled = true;
    showStep(null);
    setStatus('Koppeling voorbereiden…');
    let session;
    try {
      session = await SU.withStepUp(() => P.start({ vaultId }));
    } catch (e) {
      setStatus('');
      setError(P.messageFor(e));
      updateButton();
      return;
    }
    // Kluis intussen vergrendeld of een andere geopend (tijdens de step-up)? Dan niet doorgaan.
    if (!UI.state.db || UI.state.vaultId !== vaultId) {
      await P.cancel(session);
      P.wipe(session);
      setStatus('');
      setError(P.messageFor({ code: 'no_secret' }));
      updateButton();
      return;
    }
    cur = { session, ctrl: new AbortController() };
    renderQr(session.qr);
    showStep('qr');
    setStatus('Scan de QR-code met de HorseSafe-app. Wachten op je telefoon…');
    $('pair-section').scrollIntoView({ block: 'center' });
    let lastMinute = null;
    try {
      const { claim, sas } = await P.waitForClaim(session, {
        signal: cur.ctrl.signal,
        onTick: (left) => {
          $('pair-countdown').textContent = mmss(left);
          // Schermlezers: alleen per minuut melden, niet elke seconde.
          const minute = Math.ceil(left / 60);
          if (lastMinute !== null && minute !== lastMinute && left > 0) {
            setStatus(`Wachten op je telefoon… nog ${minute} minuut${minute === 1 ? '' : 'en'}.`);
          }
          lastMinute = minute;
        },
      });
      if (!cur || cur.session !== session) return;
      clearQr(); // QR (met s) niet langer tonen
      $('pair-device-label').textContent = claim.label;
      $('pair-device-model').textContent = claim.model || '—';
      $('pair-device-app').textContent = claim.app_version || '—';
      showSas(sas);
      showStep('sas');
      setStatus(`Telefoon "${claim.label}" gevonden. Vergelijk de code met je telefoon.`);
      $('pair-sas-ok').focus();
    } catch (e) {
      if (e && e.code === 'cancelled') return; // door de gebruiker of bij vergrendelen; die melden zelf
      if (!cur || cur.session !== session) return; // al afgesloten (Annuleren/vergrendelen)
      // waitForClaim heeft bij mac_web-fout/verlopen al DELETE gedaan
      end();
      setStatus('');
      setError(P.messageFor(e));
    }
  }

  async function sasOk() {
    if (!cur || !cur.session.claim) return;
    const session = cur.session;
    setError('');
    setSasBusy(true);
    setStatus('Bezig met koppelen…');
    try {
      if (!UI.state.secret || UI.state.vaultId !== session.vaultId) throw new window.HorseSafeHwKeys.HwKeyError('no_secret');
      const key = await P.confirm(session, {
        secret: UI.state.secret,
        pin: (kid, pk) => UI.pinKey(kid, pk),
        pins: () => UI.pins(),
      });
      const label = (key && key.device && key.device.label) || session.claim.label;
      end();
      setStatus(`✓ Telefoon "${label}" gekoppeld. Op je telefoon verschijnt zo "Gekoppeld".`);
      if (window.HorseSafeKeysUI) await window.HorseSafeKeysUI.refresh();
    } catch (e) {
      // Niet bevestigd: de koppeling opruimen (claimed-device wordt door de server verwijderd).
      await P.cancel(session);
      end();
      setStatus('');
      setError(P.messageFor(e));
      if (window.HorseSafeKeysUI) await window.HorseSafeKeysUI.refresh();
    }
  }

  async function sasBad() {
    if (!cur) return;
    setSasBusy(true);
    setStatus('');
    await abortWith('sas_rejected');
  }

  async function onCancel() {
    if (!cur) {
      $('pair-section').hidden = true;
      setError('');
      setStatus('');
      return;
    }
    await abortWith(null);
    setStatus('Koppeling geannuleerd.');
  }

  $('phone-pair').addEventListener('click', startPairing);
  $('pair-sas-ok').addEventListener('click', sasOk);
  $('pair-sas-bad').addEventListener('click', sasBad);
  $('pair-cancel').addEventListener('click', onCancel);

  document.addEventListener('horsesafe:locked', () => {
    if (cur) {
      abortWith(null);
    }
    $('pair-section').hidden = true;
    setError('');
    setStatus('');
    updateButton();
  });
  document.addEventListener('horsesafe:unlocked', updateButton);
  $('keys-open').addEventListener('click', updateButton);
  // Tab dicht tijdens het koppelen: koppeling op de server annuleren (best effort, keepalive).
  window.addEventListener('pagehide', () => {
    if (cur) {
      cur.ctrl.abort();
      P.cancel(cur.session, { keepalive: true });
      P.wipe(cur.session);
      cur = null;
    }
  });

  (async () => {
    supportOk = (await P.checkSupport()).ok;
    updateButton();
  })();
})();
