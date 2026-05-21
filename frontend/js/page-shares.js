/* HorseSafe page-init voor shares.html v0.0.7-Bellare (CSP-compliant) */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  const API = window.HorseSafeAPI;
  const SHARING = window.HorseSafeSharing;

  function fmtTs(ts) { return new Date(ts * 1000).toLocaleString('nl-NL'); }
  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  let myUserId = null;
  let inboxRows = [];

  async function fetchMe() {
    const r = await fetch(API.base + '/auth/me', { credentials: 'include' });
    if (r.status === 401) { window.location.href = 'login.html'; return null; }
    if (r.status === 403) { window.location.href = 'mfa.html'; return null; }
    return r.json();
  }

  async function loadInbox() {
    const r = await fetch(API.base + '/shares/inbox', { credentials: 'include' });
    if (r.status === 403) { window.location.href = 'mfa.html'; return; }
    if (!r.ok) { $('inbox-status').textContent = 'Fout bij inbox-load'; return; }
    inboxRows = await r.json();
    $('inbox-count').textContent = `(${inboxRows.length})`;
    if (inboxRows.length === 0) {
      $('inbox-status').textContent = 'Geen inkomende shares.';
      $('inbox-table').hidden = true;
      return;
    }
    $('inbox-status').textContent = '';
    $('inbox-table').hidden = false;
    const tbody = $('inbox-body');
    tbody.innerHTML = '';
    for (const row of inboxRows) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(row.from_email)}</td>
        <td>${escapeHtml(row.title_hint || '')}</td>
        <td>${fmtTs(row.created_at)}</td>
        <td>
          <button data-action="decrypt" data-id="${row.id}">🔓 Decrypt</button>
          <button data-action="accept" data-id="${row.id}" class="secondary">✓ Accept</button>
          <button data-action="decline" data-id="${row.id}" class="danger">✗ Decline</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-action]').forEach(b => {
      b.addEventListener('click', () => handleAction(b.dataset.action, b.dataset.id));
    });
  }

  async function loadSent() {
    const r = await fetch(API.base + '/shares/sent', { credentials: 'include' });
    if (!r.ok) return;
    const rows = await r.json();
    const tbody = $('sent-body');
    tbody.innerHTML = '';
    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">Geen verzonden shares.</td></tr>';
      return;
    }
    for (const row of rows) {
      const status = row.accepted_at ? '✓ Geaccepteerd' : row.declined_at ? '✗ Geweigerd' : '⏳ Wacht';
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(row.to_email)}</td><td>${escapeHtml(row.title_hint || '')}</td>` +
                      `<td>${fmtTs(row.created_at)}</td><td>${status}</td>`;
      tbody.appendChild(tr);
    }
  }

  async function handleAction(action, shareId) {
    if (action === 'accept' || action === 'decline') {
      const r = await fetch(API.base + `/shares/${shareId}/${action}`, {
        method: 'POST', credentials: 'include',
      });
      if (r.ok) await loadInbox();
      else alert('Fout: ' + r.status);
      return;
    }
    // decrypt
    const vaultPw = $('vault-pw').value;
    if (!vaultPw) { alert('Vul eerst vault-wachtwoord in onderaan.'); return; }
    const row = inboxRows.find(r => r.id === shareId);
    if (!row) return;
    try {
      const kpRes = await fetch(API.base + '/keypair', { credentials: 'include' });
      const kp = await kpRes.json();
      if (!kp.encrypted_privkey) { alert('Geen key-pair gevonden. Genereer eerst in settings.'); return; }
      const myPriv = await SHARING.unwrapPrivateKey(vaultPw, myUserId, kp.encrypted_privkey);
      const plainJson = await SHARING.decryptFromSender(myPriv, row.encrypted_payload);
      const entry = JSON.parse(plainJson);
      $('dec-title').textContent = entry.title || '';
      $('dec-username').textContent = entry.username || '';
      $('dec-password').textContent = entry.password || '';
      $('dec-url').textContent = entry.url || '';
      $('dec-notes').textContent = entry.notes || '';
      $('decrypted-pane').hidden = false;
    } catch (e) {
      alert('Decryptie mislukt: ' + e.message + ' (verkeerd vault-wachtwoord?)');
    }
  }

  $('dec-close').addEventListener('click', () => { $('decrypted-pane').hidden = true; });

  (async () => {
    const me = await fetchMe();
    if (!me) return;
    myUserId = me.id;
    if (!me.has_keypair) {
      $('inbox-status').textContent = 'Je hebt nog geen key-pair. Genereer eerst in settings.';
      return;
    }
    await loadInbox();
    await loadSent();
  })();
})();
