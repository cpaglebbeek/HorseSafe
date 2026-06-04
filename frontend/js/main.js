/* HorseSafe main wiring v0.0.2-Hellman — vault.html */
(function () {
  'use strict';

  const UI = window.HorseSafeVaultUI;

  function $(id) { return document.getElementById(id); }

  $('unlock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await UI.unlockOrCreate();
  });

  $('logout-from-unlock').addEventListener('click', () => window.HorseSafeAuth.logout());
  $('logout-from-vault').addEventListener('click', () => window.HorseSafeAuth.logout());

  $('lock-vault').addEventListener('click', () => UI.lockVault());
  $('add-entry').addEventListener('click', () => {
    $('edit-form').reset();
    $('edit-section').hidden = false;
    $('e-title').focus();
  });
  $('e-cancel').addEventListener('click', () => { $('edit-section').hidden = true; });
  $('e-genpw').addEventListener('click', () => UI.generatePw());
  $('edit-form').addEventListener('submit', UI.addNewEntry);

  $('d-pw-toggle').addEventListener('click', () => UI.togglePwDisplay());
  $('d-copy-pw').addEventListener('click', () => UI.copyPassword());
  const totpCopyBtn = $('d-totp-copy');
  if (totpCopyBtn) totpCopyBtn.addEventListener('click', () => UI.copyTotp());
  $('d-share').addEventListener('click', async () => {
    const entry = UI.state.currentEntry;
    if (!entry) return;
    const toEmail = prompt('Met wie wil je deze entry delen? (e-mail)');
    if (!toEmail) return;
    try {
      // Haal recipient pubkey op
      const r = await fetch(window.HorseSafeAPI.base + `/users/by-email/${encodeURIComponent(toEmail)}/pubkey`, { credentials: 'include' });
      if (r.status === 404) { alert('Ontvanger niet gevonden of heeft nog geen key-pair.'); return; }
      if (!r.ok) { alert('Fout: ' + r.status); return; }
      const recipient = await r.json();
      // Bouw plaintext-payload
      const pw = entry.password;
      const plain = JSON.stringify({
        title: entry.title, username: entry.username,
        password: (pw && pw.getText) ? pw.getText() : (pw || ''),
        url: entry.url, notes: entry.notes,
      });
      // Encrypt voor recipient
      const encrypted = await window.HorseSafeSharing.encryptForRecipient(recipient.pubkey, plain);
      // Stuur naar server
      const postRes = await fetch(window.HorseSafeAPI.base + '/shares', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to_email: toEmail, encrypted_payload: encrypted, title_hint: entry.title }),
      });
      if (postRes.status === 201) { alert(`✓ Gedeeld met ${toEmail}.`); }
      else { alert('Share-fout: ' + postRes.status); }
    } catch (e) { alert('Fout: ' + e.message); }
  });
  $('d-delete').addEventListener('click', () => UI.deleteCurrent());

  // Reload-warning bij open vault
  window.addEventListener('beforeunload', (e) => {
    if (UI.state.db) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
})();
