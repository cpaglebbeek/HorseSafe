/* HorseSafe MFA-challenge UI v0.0.3-Merkle */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function show(id, msg) { const el = $(id); if (msg) el.textContent = msg; el.hidden = false; }
  function hide(id) { $(id).hidden = true; }

  // Tab-switch
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
      $('totp-pane').hidden = (tab !== 'totp');
      $('magic-pane').hidden = (tab !== 'magic');
    });
  });

  // TOTP-challenge
  $('totp-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    hide('totp-error');
    const code = $('totp-code').value.trim();
    $('totp-submit').disabled = true;
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/totp/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      if (r.ok) {
        window.location.href = 'vault.html';
      } else {
        const data = await r.json().catch(() => null);
        const err = data?.detail?.error || 'unknown';
        const msg = (
          err === 'invalid_code' ? 'Verkeerde code. Probeer een nieuwe code uit je app.' :
          err === 'totp_not_configured' ? 'Je account heeft geen TOTP geconfigureerd.' :
          err === 'throttled' ? 'Te veel mislukte pogingen. Wacht 15 minuten.' :
          `Fout: ${err}`
        );
        show('totp-error', msg);
      }
    } catch (e) {
      show('totp-error', 'Netwerkfout: ' + e.message);
    } finally {
      $('totp-submit').disabled = false;
    }
  });

  $('totp-logout').addEventListener('click', () => window.HorseSafeAuth.logout());

  // Magic-link aanvragen
  $('magic-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    hide('magic-status');
    const email = $('magic-email').value.trim();
    $('magic-submit').disabled = true;
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/magic-link', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      if (r.ok) {
        show('magic-status', 'Als dit e-mailadres bekend is, is er een link verstuurd. Controleer je inbox (en spam).');
      }
    } catch (e) {
      show('magic-status', 'Netwerkfout: ' + e.message);
    } finally {
      $('magic-submit').disabled = false;
    }
  });
})();
