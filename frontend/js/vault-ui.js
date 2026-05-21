/* HorseSafe Vault UI v0.0.2-Hellman
 * State per pagina-load: { db, vaultId, etag, currentEntry }
 */
(function () {
  'use strict';

  const state = {
    db: null,
    vaultId: null,
    etag: null,
    currentEntry: null,
  };

  function $(id) { return document.getElementById(id); }
  function show(id) { $(id).hidden = false; }
  function hide(id) { $(id).hidden = true; }
  function setText(id, t) { $(id).textContent = (t === null || t === undefined) ? '' : String(t); }

  function showError(id, msg) {
    const el = $(id);
    el.textContent = msg;
    el.hidden = false;
  }

  function clearError(id) { $(id).hidden = true; }

  function renderEntries() {
    const entries = window.HorseSafeCrypto.listEntries(state.db);
    setText('entry-count', entries.length);
    const tbody = $('entries-body');
    tbody.innerHTML = '';
    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" class="muted">Geen entries — klik "+ Nieuwe entry"</td></tr>';
      hide('detail-pane');
      return;
    }
    for (const e of entries) {
      const tr = document.createElement('tr');
      tr.className = 'selectable';
      tr.dataset.uuid = e.uuid;
      tr.innerHTML = `<td>${escapeHtml(e.title)}</td><td>${escapeHtml(e.username)}</td><td>${escapeHtml(e.url)}</td>`;
      tr.addEventListener('click', () => selectEntry(e));
      tbody.appendChild(tr);
    }
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function selectEntry(entry) {
    state.currentEntry = entry;
    document.querySelectorAll('#entries-body tr').forEach(r => r.classList.remove('selected'));
    const tr = document.querySelector(`#entries-body tr[data-uuid="${entry.uuid}"]`);
    if (tr) tr.classList.add('selected');

    setText('d-title',    entry.title);
    setText('d-username', entry.username);

    const a = $('d-url');
    a.textContent = entry.url || '—';
    a.href = entry.url || '#';

    setText('d-notes',    entry.notes);

    // Wachtwoord — verborgen by default
    const pwDisplay = $('d-pw-display');
    pwDisplay.textContent = '••••••••••••';
    pwDisplay.classList.add('pw-hidden');
    pwDisplay.dataset.shown = '0';

    show('detail-pane');
  }

  async function persist() {
    try {
      const blob = await window.HorseSafeCrypto.saveDatabase(state.db);
      const r = await window.HorseSafeAPI.updateVault(state.vaultId, blob, state.etag);
      if (!r.ok) {
        if (r.status === 412) {
          showError('global-error', 'Vault is elders gewijzigd (etag-conflict). Herlaad de pagina.');
        } else {
          showError('global-error', `Save-fout: ${r.status} ${r.data?.detail?.error || ''}`);
        }
        return false;
      }
      state.etag = r.etag;
      clearError('global-error');
      return true;
    } catch (e) {
      showError('global-error', 'Save mislukt: ' + e.message);
      return false;
    }
  }

  async function unlockOrCreate() {
    const pw = $('vault-pw').value;
    if (pw.length < 6) {
      showError('unlock-error', 'Vault-wachtwoord moet minimaal 6 tekens zijn (POC; productie ≥12).');
      return;
    }
    clearError('unlock-error');
    $('unlock-submit').disabled = true;
    $('unlock-status').hidden = false;

    try {
      const listRes = await window.HorseSafeAPI.listVaults();
      if (!listRes.ok) {
        if (listRes.status === 401) {
          window.location.href = 'login.html';
          return;
        }
        showError('unlock-error', `Fout bij vault-list: ${listRes.status}`);
        return;
      }

      if (listRes.data.length === 0) {
        // Geen vault — maak nieuwe aan
        $('unlock-status').textContent = 'Nog geen vault — nieuwe wordt aangemaakt met dit wachtwoord...';
        const { db } = await window.HorseSafeCrypto.createDatabase(pw, 'default');
        const blob = await window.HorseSafeCrypto.saveDatabase(db);
        const createRes = await window.HorseSafeAPI.createVault('default', blob);
        if (!createRes.ok) {
          showError('unlock-error', `Vault create-fout: ${createRes.status}`);
          return;
        }
        state.db = db;
        state.vaultId = createRes.data.id;
        state.etag = createRes.data.etag;
      } else {
        // Bestaande vault openen
        const meta = listRes.data[0];
        $('unlock-status').textContent = 'Vault openen...';
        const readRes = await window.HorseSafeAPI.readVault(meta.id);
        if (!readRes.ok) {
          showError('unlock-error', `Read-fout: ${readRes.status}`);
          return;
        }
        try {
          state.db = await window.HorseSafeCrypto.openDatabase(readRes.blob, pw);
          state.vaultId = meta.id;
          state.etag = readRes.etag;
        } catch (e) {
          showError('unlock-error', 'Verkeerd wachtwoord (of vault corrupt).');
          return;
        }
      }

      // Switch UI
      hide('unlock-section');
      show('vault-section');
      $('vault-name').textContent = listRes.data[0]?.name || 'default';
      $('vault-stats').textContent = ' — zero-knowledge (server ziet alleen ciphertext)';
      renderEntries();
    } catch (e) {
      showError('unlock-error', 'Onverwachte fout: ' + e.message);
    } finally {
      $('unlock-submit').disabled = false;
    }
  }

  function lockVault() {
    state.db = null;
    state.vaultId = null;
    state.etag = null;
    state.currentEntry = null;
    $('vault-pw').value = '';
    hide('vault-section');
    show('unlock-section');
  }

  async function addNewEntry(e) {
    e.preventDefault();
    const data = {
      title:    $('e-title').value,
      username: $('e-username').value,
      password: $('e-pw').value,
      url:      $('e-url').value,
      notes:    $('e-notes').value,
    };
    window.HorseSafeCrypto.addEntry(state.db, data);
    if (await persist()) {
      hide('edit-section');
      renderEntries();
      $('edit-form').reset();
    }
  }

  async function deleteCurrent() {
    if (!state.currentEntry) return;
    if (!confirm('Verwijder entry "' + state.currentEntry.title + '"?')) return;
    window.HorseSafeCrypto.deleteEntry(state.db, state.currentEntry.uuid);
    state.currentEntry = null;
    if (await persist()) {
      hide('detail-pane');
      renderEntries();
    }
  }

  function togglePwDisplay() {
    if (!state.currentEntry) return;
    const display = $('d-pw-display');
    if (display.dataset.shown === '1') {
      display.textContent = '••••••••••••';
      display.classList.add('pw-hidden');
      display.dataset.shown = '0';
    } else {
      const pw = state.currentEntry.password;
      display.textContent = (pw && pw.getText) ? pw.getText() : (pw || '');
      display.classList.remove('pw-hidden');
      display.dataset.shown = '1';
    }
  }

  async function copyPassword() {
    if (!state.currentEntry) return;
    const pw = state.currentEntry.password;
    const plain = (pw && pw.getText) ? pw.getText() : (pw || '');
    if (!plain) return;

    const btn = $('d-copy-pw');
    btn.disabled = true;
    const progressEl = btn.querySelector('.copy-progress');
    const bar        = btn.querySelector('.copy-progress-bar');
    progressEl.hidden = false;
    btn.firstChild.textContent = '⏱ Wipe over 10s';

    await window.HorseSafeCrypto.copyWithWipe(
      plain,
      (frac) => { bar.style.width = (frac * 100).toFixed(1) + '%'; },
      () => {
        progressEl.hidden = true;
        btn.disabled = false;
        btn.firstChild.textContent = '📋 Kopieer wachtwoord';
      }
    );
  }

  function generatePw() {
    $('e-pw').value = window.HorseSafeCrypto.generatePassword(20);
  }

  window.HorseSafeVaultUI = {
    state,
    unlockOrCreate,
    lockVault,
    addNewEntry,
    deleteCurrent,
    togglePwDisplay,
    copyPassword,
    generatePw,
    renderEntries,
  };
})();
