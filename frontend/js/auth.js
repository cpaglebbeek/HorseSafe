/* HorseSafe Auth UI v0.0.2-Hellman */
(function () {
  'use strict';

  function show(id, msg) {
    const el = document.getElementById(id);
    el.textContent = msg;
    el.hidden = false;
  }
  function hide(id) {
    const el = document.getElementById(id);
    el.hidden = true;
  }

  async function handleRegister() {
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-pw').value;
    const ack = document.getElementById('reg-ack').checked;
    const submitBtn = document.getElementById('register-submit');

    hide('register-error'); hide('register-success');
    if (!ack) {
      show('register-error', 'Je moet bevestigen dat data permanent verloren gaat bij verlies van vault-wachtwoord.');
      return;
    }
    if (password.length < 12) {
      show('register-error', 'Account-wachtwoord moet minimaal 12 tekens zijn.');
      return;
    }

    submitBtn.disabled = true;
    try {
      const r = await window.HorseSafeAPI.register({
        email, password, ack_data_loss: true,
      });
      if (r.ok) {
        show('register-success', 'Account aangemaakt! Doorgaan naar login...');
        setTimeout(() => { window.location.href = 'login.html'; }, 1200);
      } else {
        const err = r.data?.detail?.error || r.data?.error || 'unknown';
        const msg = r.data?.detail?.message || (
          err === 'email_in_use' ? 'Dit e-mailadres is al in gebruik.' :
          err === 'ack_required' ? 'Bevestig dat je data-verlies begrijpt.' :
          `Fout: ${err}`
        );
        show('register-error', msg);
      }
    } catch (e) {
      show('register-error', 'Netwerkfout: ' + e.message);
    } finally {
      submitBtn.disabled = false;
    }
  }

  async function handleLogin() {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-pw').value;
    const submitBtn = document.getElementById('login-submit');

    hide('login-error');
    submitBtn.disabled = true;
    try {
      const r = await window.HorseSafeAPI.login({ email, password });
      if (r.ok) {
        // Bij mfa_required: door naar MFA-challenge. Anders direct vault.
        const next = r.data?.mfa_required ? 'mfa.html' : 'vault.html';
        window.location.href = next;
      } else {
        const err = r.data?.detail?.error || r.data?.error || 'unknown';
        const msg = (
          err === 'invalid_credentials' ? 'Verkeerd e-mailadres of wachtwoord.' :
          err === 'throttled' ? 'Te veel mislukte pogingen. Wacht 15 minuten.' :
          err === 'rate_limited' ? 'Te veel verzoeken. Wacht even.' :
          `Fout: ${err}`
        );
        show('login-error', msg);
      }
    } catch (e) {
      show('login-error', 'Netwerkfout: ' + e.message);
    } finally {
      submitBtn.disabled = false;
    }
  }

  async function logout() {
    try { await window.HorseSafeAPI.logout(); } catch (_) {}
    window.location.href = 'index.html';
  }

  window.HorseSafeAuth = { handleRegister, handleLogin, logout };
})();
