/* HorseSafe page-init voor export.html v0.0.7-Bellare (CSP-compliant) */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }

  $('format').addEventListener('change', () => {
    const fmt = $('format').value;
    $('reason-section').hidden = (fmt === 'kdbx');
  });

  $('export-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('export-error').hidden = true;
    const fmt = $('format').value;
    const reason = $('reason').value;
    if (fmt !== 'kdbx' && reason.length < 10) {
      $('export-error').textContent = 'Reden van minimaal 10 tekens vereist voor plaintext-export.';
      $('export-error').hidden = false;
      return;
    }
    if (fmt !== 'kdbx') {
      // Toon eerst waarschuwing
      $('warning-section').hidden = false;
      return;
    }
    await doExport(fmt, '');
  });

  $('confirm-plaintext').addEventListener('click', async () => {
    await doExport($('format').value, $('reason').value);
  });
  $('cancel-plaintext').addEventListener('click', () => {
    $('warning-section').hidden = true;
  });

  async function doExport(fmt, reason) {
    $('export-btn').disabled = true;
    try {
      const vaultPw = $('vault-pw').value;
      const listRes = await window.HorseSafeAPI.listVaults();
      if (!listRes.ok || listRes.data.length === 0) {
        throw new Error('Geen vault gevonden');
      }
      const meta = listRes.data[0];
      const readRes = await window.HorseSafeAPI.readVault(meta.id);
      if (!readRes.ok) throw new Error('Vault niet leesbaar');
      const db = await window.HorseSafeCrypto.openDatabase(readRes.blob, vaultPw);
      const entries = window.HorseSafeImportExport.extractEntries(db);

      const stampRes = await fetch(window.HorseSafeAPI.base + `/vault/${meta.id}/audit-export`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: fmt, reason }),
      });
      if (!stampRes.ok) {
        const data = await stampRes.json().catch(() => ({}));
        throw new Error('Audit-fout: ' + (data?.detail?.error || stampRes.status));
      }

      const ts = new Date().toISOString().slice(0, 10);
      if (fmt === 'kdbx') {
        const blob = await window.HorseSafeCrypto.saveDatabase(db);
        window.HorseSafeImportExport.downloadBlob(blob, `horsesafe-${ts}.kdbx`, 'application/octet-stream');
      } else if (fmt === 'csv') {
        const csv = window.HorseSafeImportExport.buildCSV(entries);
        window.HorseSafeImportExport.downloadBlob(csv, `horsesafe-${ts}.csv`, 'text/csv');
      } else if (fmt === 'json') {
        const json = window.HorseSafeImportExport.buildJSON(entries);
        window.HorseSafeImportExport.downloadBlob(json, `horsesafe-${ts}.json`, 'application/json');
      }
      $('warning-section').hidden = true;
      alert('✅ Export voltooid. Bestand is gedownload.');
    } catch (err) {
      $('export-error').textContent = 'Fout: ' + err.message;
      $('export-error').hidden = false;
    } finally {
      $('export-btn').disabled = false;
    }
  }
})();
