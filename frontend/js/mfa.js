/* HorseSafe MFA-challenge UI v0.0.3-Merkle */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function show(id, msg) { const el = $(id); if (msg) el.textContent = msg; el.hidden = false; }
  function hide(id) { $(id).hidden = true; }

  // v0.2.0-Koblitz (reviewronde 3): magic-link uit de mail → mfa.html#ml=<token>.
  // Het sessie-cookie is SameSite=Strict en gaat niet mee bij een klik vanuit webmail (cross-site).
  // Deze pagina verzilvert daarom met een same-site POST, waarbij het cookie wel meegaat.
  const LINK_ERRORS = {
    invalid_link: 'Deze link is ongeldig, verlopen of al gebruikt. Vraag hieronder een nieuwe aan.',
  };
  async function redeemMagicLink() {
    const m = /(?:^#|&)ml=([A-Za-z0-9_-]+)/.exec(window.location.hash);
    if (!m) return;
    // Token direct uit de adresbalk/geschiedenis halen
    history.replaceState(null, '', window.location.pathname + window.location.search);
    show('magic-redeem', 'Link wordt bevestigd…');
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/magic-link/redeem', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ t: m[1] }),
      });
      if (r.ok) {
        window.location.href = 'vault.html';
        return;
      }
      const data = await r.json().catch(() => null);
      const err = data?.detail?.error || 'unknown';
      if (err === 'magic_link_login_first') {
        window.location.href = 'login.html?error=magic_link_login_first';
        return;
      }
      $('magic-redeem').hidden = true;
      show('magic-redeem-error', LINK_ERRORS[err] || `Fout: ${err}`);
    } catch (e) {
      $('magic-redeem').hidden = true;
      show('magic-redeem-error', 'Netwerkfout: ' + e.message);
    }
  }
  redeemMagicLink();

  // Tab-switch
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
      $('totp-pane').hidden = (tab !== 'totp');
      $('magic-pane').hidden = (tab !== 'magic');
      $('backup-pane').hidden = (tab !== 'backup');
    });
  });

  // Backup-code challenge
  $('backup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    hide('backup-error');
    const code = $('backup-code-input').value.trim();
    $('backup-submit').disabled = true;
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/backup-codes/verify', {
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
          err === 'invalid_code' ? 'Code niet geldig of al gebruikt.' :
          err === 'throttled' ? 'Te veel mislukte pogingen. Wacht 15 minuten.' :
          `Fout: ${err}`
        );
        show('backup-error', msg);
      }
    } catch (e) {
      show('backup-error', 'Netwerkfout: ' + e.message);
    } finally {
      $('backup-submit').disabled = false;
    }
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
