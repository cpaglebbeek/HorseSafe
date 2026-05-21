/* HorseSafe Settings UI v0.0.3-Merkle */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function show(id, msg) { const el = $(id); if (msg !== undefined) el.textContent = msg; el.hidden = false; }
  function hide(id) { $(id).hidden = true; }

  let currentSecret = null;

  async function probeTotpStatus() {
    // v0.0.4: gebruikt /auth/me ipv /vault-probe-hack
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/me', { credentials: 'include' });
      if (r.status === 401) {
        window.location.href = 'login.html';
        return;
      }
      const me = await r.json();
      if (me.has_totp) {
        $('totp-status').textContent = `Ingeschakeld (${me.backup_codes_remaining} backup-codes over)`;
        $('totp-enable-btn').hidden = true;
        $('totp-disable-btn').hidden = false;
      } else {
        $('totp-status').textContent = 'Niet ingeschakeld';
        $('totp-enable-btn').hidden = false;
        $('totp-disable-btn').hidden = true;
      }
      // Admin-link tonen
      if (me.is_admin) {
        const adminLink = document.getElementById('admin-link');
        if (adminLink) adminLink.hidden = false;
      }
      // Backup-codes-link tonen indien TOTP enabled
      const bcLink = document.getElementById('backup-codes-link');
      if (bcLink) bcLink.hidden = !me.has_totp;
    } catch (e) {
      $('totp-status').textContent = 'Onbekend (' + e.message + ')';
    }
  }

  function renderQR(otpauthUrl) {
    const canvas = $('qr-canvas');
    canvas.innerHTML = '';
    // qrcode(typeNumber, errorCorrectionLevel)
    const qr = window.qrcode(0, 'M');
    qr.addData(otpauthUrl);
    qr.make();
    // createSvgTag(cellSize, margin)
    canvas.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 2, scalable: true });
  }

  $('totp-enable-btn').addEventListener('click', async () => {
    $('totp-enable-btn').disabled = true;
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/totp/setup', {
        method: 'POST', credentials: 'include',
      });
      if (!r.ok) {
        if (r.status === 401) { window.location.href = 'login.html'; return; }
        alert('TOTP setup-fout: ' + r.status);
        return;
      }
      const data = await r.json();
      currentSecret = data.secret;
      $('secret-text').textContent = data.secret;
      renderQR(data.otpauth_url);
      hide('totp-status-pane');
      show('totp-setup-pane');
      $('setup-code').focus();
    } finally {
      $('totp-enable-btn').disabled = false;
    }
  });

  $('totp-verify-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    hide('setup-error'); hide('setup-success');
    const code = $('setup-code').value.trim();
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/totp/verify', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: currentSecret, code }),
      });
      if (r.ok) {
        show('setup-success', 'TOTP succesvol gekoppeld! Bij volgende login wordt om een code gevraagd.');
        setTimeout(() => {
          hide('totp-setup-pane');
          show('totp-status-pane');
          probeTotpStatus();
        }, 1500);
      } else {
        const data = await r.json().catch(() => null);
        show('setup-error', data?.detail?.error === 'invalid_code'
          ? 'Verkeerde code. Probeer een nieuwe code uit je app.'
          : 'Fout: ' + (data?.detail?.error || r.status));
      }
    } catch (e) {
      show('setup-error', 'Netwerkfout: ' + e.message);
    }
  });

  $('setup-cancel').addEventListener('click', () => {
    currentSecret = null;
    hide('totp-setup-pane');
    show('totp-status-pane');
  });

  $('totp-disable-btn').addEventListener('click', () => {
    hide('totp-status-pane');
    show('totp-disable-pane');
    $('disable-code').focus();
  });

  $('totp-disable-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    hide('disable-error');
    const code = $('disable-code').value.trim();
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/totp/disable', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      if (r.ok) {
        hide('totp-disable-pane');
        show('totp-status-pane');
        probeTotpStatus();
      } else {
        const data = await r.json().catch(() => null);
        show('disable-error', data?.detail?.error === 'invalid_code'
          ? 'Verkeerde code.'
          : 'Fout: ' + (data?.detail?.error || r.status));
      }
    } catch (e) {
      show('disable-error', 'Netwerkfout: ' + e.message);
    }
  });

  $('disable-cancel').addEventListener('click', () => {
    hide('totp-disable-pane');
    show('totp-status-pane');
  });

  $('logout-btn').addEventListener('click', () => window.HorseSafeAuth.logout());

  // Init
  probeTotpStatus();
})();
