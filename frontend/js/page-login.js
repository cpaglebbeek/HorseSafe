/* HorseSafe page-init voor login.html v0.4.0-Montgomery (sinds v0.0.7-Bellare, CSP-compliant) */
(function () {
  'use strict';
  // v0.2.0-Koblitz: foutmelding na een geweigerde magic-link (?error=…)
  const LINK_ERRORS = {
    invalid_link: 'Deze link is ongeldig, verlopen of al gebruikt. Log in en vraag een nieuwe aan.',
    magic_link_login_first: 'Log eerst in deze browser in met je wachtwoord en open de link daarna opnieuw. '
      + 'De link is een tweede stap en logt niet zelf in; hij is nog niet gebruikt.',
    // v0.4.0-Montgomery: verzoek op de telefoon geweigerd → sessie ingetrokken (§14.5)
    approval_denied: 'Geweigerd op je telefoon. Je bent uitgelogd.',
    session_expired: 'Sessie verlopen. Log opnieuw in.',
    session_revoked: 'Je bent uitgelogd: het vertrouwen van deze browser is ingetrokken of de kluis is gewijzigd. Log opnieuw in.',
  };
  const err = new URLSearchParams(window.location.search).get('error');
  if (err && LINK_ERRORS[err]) {
    const el = document.getElementById('login-error');
    el.textContent = LINK_ERRORS[err];
    el.hidden = false;
  }
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await window.HorseSafeAuth.handleLogin();
  });

  // v0.4.0-Montgomery: vertrouwde browser → e-mail + handtekening + TOTP (§14.4). Gewone login blijft.
  const T = window.HorseSafeTrust;
  if (!T) return;
  const $ = (id) => document.getElementById(id);
  let records = [];
  const current = () => {
    const sel = $('trusted-email-select');
    return records.length > 1 ? records[Number(sel.value) || 0] : records[0];
  };
  function showErr(text) {
    $('trusted-error').textContent = text || '';
    $('trusted-error').hidden = !text;
  }
  (async () => {
    const all = await T.listRecords();
    // Eén record per e-mailadres (meerdere kluizen van één account delen de login)
    const seen = new Set();
    records = all.filter((r) => {
      const k = r.email.toLowerCase();
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    if (!records.length) return;
    if (records.length > 1) {
      const sel = $('trusted-email-select');
      records.forEach((r, i) => {
        const o = document.createElement('option');
        o.value = String(i);
        o.textContent = r.email;
        sel.appendChild(o);
      });
      sel.hidden = false;
      $('trusted-email').hidden = true;
      sel.addEventListener('change', () => { $('trusted-email').value = current().email; });
    }
    $('trusted-email').value = current().email;
    $('login-email').value = current().email;
    $('trusted-login').hidden = false;
    $('trusted-code').focus();
  })();

  $('trusted-login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showErr('');
    const rec = current();
    if (!rec) return;
    $('trusted-submit').disabled = true;
    try {
      await T.browserLogin({ record: rec, totp: $('trusted-code').value });
      window.location.href = 'vault.html';
    } catch (err) {
      $('trusted-code').value = '';
      showErr(T.messageFor(err));
    } finally {
      $('trusted-submit').disabled = false;
    }
  });
})();
