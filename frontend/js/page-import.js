/* HorseSafe page-init voor import.html v0.0.7-Bellare (CSP-compliant) */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  let parsedEntries = null;
  let currentDb = null;
  let currentVaultId = null;
  let currentEtag = null;

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  $('import-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('import-error').hidden = true;
    $('preview-section').hidden = true;
    $('preview-btn').disabled = true;
    try {
      const fmt = $('format').value;
      const fileEl = $('file');
      const file = fileEl.files[0];
      if (!file) { throw new Error('Geen bestand geselecteerd'); }
      const vaultPw = $('vault-pw').value;
      if (!vaultPw) { throw new Error('Vault-wachtwoord vereist'); }

      // 1. Lees + parse import
      if (fmt === 'kdbx') {
        const buf = await file.arrayBuffer();
        const importDb = await window.HorseSafeCrypto.openDatabase(buf, $('kdbx-pw').value);
        parsedEntries = window.HorseSafeImportExport.extractEntries(importDb);
      } else if (fmt === 'bitwarden') {
        const text = await file.text();
        parsedEntries = window.HorseSafeImportExport.parseBitwardenJson(text);
      } else if (fmt === 'csv') {
        const text = await file.text();
        parsedEntries = window.HorseSafeImportExport.parseKeePassCsv(text);
      }

      // 2. Laad HorseSafe-vault
      const listRes = await window.HorseSafeAPI.listVaults();
      if (!listRes.ok || listRes.data.length === 0) {
        throw new Error('Geen HorseSafe-vault gevonden. Maak eerst een vault aan.');
      }
      const meta = listRes.data[0];
      const readRes = await window.HorseSafeAPI.readVault(meta.id);
      if (!readRes.ok) throw new Error('Kan vault niet laden');
      currentDb = await window.HorseSafeCrypto.openDatabase(readRes.blob, vaultPw);
      currentVaultId = meta.id;
      currentEtag = readRes.etag;

      // 3. Toon preview
      $('preview-count').textContent = `(${parsedEntries.length} entries gevonden)`;
      const tbody = $('preview-body');
      tbody.innerHTML = '';
      for (const e of parsedEntries.slice(0, 100)) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${escapeHtml(e.title)}</td><td>${escapeHtml(e.username)}</td><td>${escapeHtml(e.url)}</td>`;
        tbody.appendChild(tr);
      }
      if (parsedEntries.length > 100) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="3" class="muted">… en ${parsedEntries.length - 100} meer</td>`;
        tbody.appendChild(tr);
      }
      $('preview-section').hidden = false;
    } catch (err) {
      $('import-error').textContent = 'Fout: ' + err.message;
      $('import-error').hidden = false;
    } finally {
      $('preview-btn').disabled = false;
    }
  });

  $('commit-btn').addEventListener('click', async () => {
    if (!currentDb || !parsedEntries) return;
    $('commit-btn').disabled = true;
    try {
      const strategy = $('conflict').value;
      const result = window.HorseSafeImportExport.mergeEntriesInto(currentDb, parsedEntries, strategy);
      const blob = await window.HorseSafeCrypto.saveDatabase(currentDb);
      const putRes = await window.HorseSafeAPI.updateVault(currentVaultId, blob, currentEtag);
      if (!putRes.ok) throw new Error('Upload-fout ' + putRes.status);
      await fetch(window.HorseSafeAPI.base + `/vault/${currentVaultId}/audit-import`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: $('format').value, count: result.added }),
      });
      $('import-status').textContent = `✅ ${result.added} toegevoegd, ${result.skipped} overgeslagen.`;
      setTimeout(() => { window.location.href = 'vault.html'; }, 2000);
    } catch (err) {
      $('import-error').textContent = 'Save-fout: ' + err.message;
      $('import-error').hidden = false;
    } finally {
      $('commit-btn').disabled = false;
    }
  });

  $('reset-btn').addEventListener('click', () => {
    parsedEntries = null; currentDb = null;
    $('preview-section').hidden = true;
    $('import-form').reset();
  });
})();
