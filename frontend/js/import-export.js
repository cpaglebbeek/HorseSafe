/* HorseSafe import/export library v0.0.5-Shamir.
 * Volledig client-side. Server ziet alleen ciphertext + audit-events.
 */
(function () {
  'use strict';

  // ─── Import parsers ───

  /**
   * Parse Bitwarden JSON-export.
   * Schema: { "encrypted": false, "items": [{name, login.username, login.password, login.uris[].uri, notes, ...}] }
   */
  function parseBitwardenJson(text) {
    const data = JSON.parse(text);
    if (data.encrypted) {
      throw new Error('Bitwarden JSON is encrypted — exporteer eerst als "json" (unencrypted) vanuit Bitwarden');
    }
    if (!Array.isArray(data.items)) throw new Error('Geen "items" array in JSON');
    return data.items.filter(it => it.type === 1 || !it.type).map(it => ({
      title: it.name || '(zonder naam)',
      username: it.login?.username || '',
      password: it.login?.password || '',
      url: (it.login?.uris && it.login.uris[0]?.uri) || '',
      notes: it.notes || '',
    }));
  }

  /**
   * Parse KeePass-CSV-export.
   * Standaard kolommen: "Group","Title","Username","Password","URL","Notes"
   */
  function parseKeePassCsv(text) {
    const rows = parseCSV(text);
    if (rows.length < 1) return [];
    const header = rows[0].map(c => c.toLowerCase().trim());
    const idx = {
      title:    header.findIndex(c => c === 'title' || c === 'name'),
      username: header.findIndex(c => c === 'username' || c === 'user' || c === 'login'),
      password: header.findIndex(c => c === 'password'),
      url:      header.findIndex(c => c === 'url' || c === 'web site'),
      notes:    header.findIndex(c => c === 'notes' || c === 'comments'),
    };
    if (idx.title < 0 || idx.password < 0) {
      throw new Error('CSV mist verplichte kolommen "Title" + "Password"');
    }
    return rows.slice(1).filter(r => r.length > 1).map(r => ({
      title:    r[idx.title] || '(zonder naam)',
      username: idx.username >= 0 ? (r[idx.username] || '') : '',
      password: r[idx.password] || '',
      url:      idx.url >= 0 ? (r[idx.url] || '') : '',
      notes:    idx.notes >= 0 ? (r[idx.notes] || '') : '',
    }));
  }

  /** Minimale CSV-parser (RFC 4180-compatible, double-quote-escaped). */
  function parseCSV(text) {
    const rows = [];
    let row = [];
    let cell = '';
    let i = 0;
    let inQuotes = false;
    while (i < text.length) {
      const c = text[i];
      if (inQuotes) {
        if (c === '"') {
          if (text[i + 1] === '"') { cell += '"'; i += 2; continue; }
          inQuotes = false; i++; continue;
        }
        cell += c; i++; continue;
      }
      if (c === '"') { inQuotes = true; i++; continue; }
      if (c === ',') { row.push(cell); cell = ''; i++; continue; }
      if (c === '\n' || c === '\r') {
        row.push(cell); cell = '';
        if (row.length > 0 && !(row.length === 1 && row[0] === '')) rows.push(row);
        row = [];
        // Skip \r\n
        if (c === '\r' && text[i + 1] === '\n') i++;
        i++; continue;
      }
      cell += c; i++;
    }
    if (cell || row.length > 0) { row.push(cell); rows.push(row); }
    return rows;
  }

  /**
   * Parse XLSX (.xlsx) workbook ArrayBuffer → entries. Eerste sheet gelezen.
   * Header-row matched case-insensitive op Title/Username/Password/URL/Notes.
   * Vereist window.XLSX (SheetJS) geladen.
   */
  function parseXlsx(arrayBuffer) {
    if (!window.XLSX) throw new Error('SheetJS (window.XLSX) niet geladen');
    const wb = window.XLSX.read(arrayBuffer, { type: 'array' });
    const sheetName = wb.SheetNames[0];
    if (!sheetName) throw new Error('Geen sheets gevonden in xlsx');
    const sheet = wb.Sheets[sheetName];
    const rows = window.XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
    if (rows.length < 2) return [];
    const header = rows[0].map((c) => String(c || '').toLowerCase().trim());
    const idx = {
      title:    header.findIndex((c) => c === 'title' || c === 'name'),
      username: header.findIndex((c) => c === 'username' || c === 'user' || c === 'login'),
      password: header.findIndex((c) => c === 'password'),
      url:      header.findIndex((c) => c === 'url' || c === 'web site'),
      notes:    header.findIndex((c) => c === 'notes' || c === 'comments'),
    };
    if (idx.title < 0 || idx.password < 0) {
      throw new Error('XLSX mist verplichte kolommen "Title" + "Password"');
    }
    return rows.slice(1).filter((r) => r.length > 1).map((r) => ({
      title:    String(r[idx.title] || '(zonder naam)'),
      username: idx.username >= 0 ? String(r[idx.username] || '') : '',
      password: String(r[idx.password] || ''),
      url:      idx.url >= 0 ? String(r[idx.url] || '') : '',
      notes:    idx.notes >= 0 ? String(r[idx.notes] || '') : '',
    }));
  }

  // ─── Export builders ───

  function buildCSV(entries) {
    const esc = (s) => {
      const str = String(s ?? '');
      if (/[",\n\r]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
      return str;
    };
    const rows = [['Title', 'Username', 'Password', 'URL', 'Notes']];
    for (const e of entries) {
      rows.push([e.title, e.username, e.password, e.url, e.notes]);
    }
    return rows.map(r => r.map(esc).join(',')).join('\r\n');
  }

  function buildJSON(entries) {
    // Bitwarden-compatible schema (encrypted: false)
    return JSON.stringify({
      encrypted: false,
      folders: [],
      items: entries.map((e, i) => ({
        id: String(i),
        name: e.title,
        type: 1,
        login: {
          username: e.username,
          password: e.password,
          uris: e.url ? [{ uri: e.url }] : [],
        },
        notes: e.notes || null,
        favorite: false,
        secureNote: null,
        organizationId: null,
      })),
    }, null, 2);
  }

  /**
   * Bouw XLSX-workbook → Uint8Array (download-able).
   * Vereist window.XLSX (SheetJS) geladen.
   */
  function buildXlsx(entries) {
    if (!window.XLSX) throw new Error('SheetJS (window.XLSX) niet geladen');
    const rows = [['Title', 'Username', 'Password', 'URL', 'Notes']];
    for (const e of entries) {
      rows.push([e.title || '', e.username || '', e.password || '', e.url || '', e.notes || '']);
    }
    const ws = window.XLSX.utils.aoa_to_sheet(rows);
    const wb = window.XLSX.utils.book_new();
    window.XLSX.utils.book_append_sheet(wb, ws, 'HorseSafe');
    // type:'array' → Uint8Array (browser-friendly download)
    return window.XLSX.write(wb, { type: 'array', bookType: 'xlsx' });
  }

  // ─── Merge in kdbxweb-Kdbx ───

  function mergeEntriesInto(db, entries, conflictStrategy) {
    // conflictStrategy: 'skip' | 'overwrite' | 'duplicate'
    const kdb = window.kdbxweb;
    const root = db.getDefaultGroup();
    const existing = new Map();
    for (const e of root.entries) {
      existing.set((e.fields.get('Title') || '') + '|' + (e.fields.get('UserName') || ''), e);
    }
    let added = 0;
    let skipped = 0;
    for (const entry of entries) {
      const key = entry.title + '|' + entry.username;
      const conflict = existing.get(key);
      if (conflict) {
        if (conflictStrategy === 'skip') { skipped++; continue; }
        if (conflictStrategy === 'overwrite') db.remove(conflict);
        // 'duplicate' → ga door, voeg met suffix
        if (conflictStrategy === 'duplicate') {
          entry.title = entry.title + ' (geïmporteerd)';
        }
      }
      const newEntry = db.createEntry(root);
      if (entry.title) newEntry.fields.set('Title', entry.title);
      if (entry.username) newEntry.fields.set('UserName', entry.username);
      if (entry.password) newEntry.fields.set('Password', kdb.ProtectedValue.fromString(entry.password));
      if (entry.url) newEntry.fields.set('URL', entry.url);
      if (entry.notes) newEntry.fields.set('Notes', entry.notes);
      added++;
    }
    return { added, skipped };
  }

  // ─── Extract for export ───

  function extractEntries(db) {
    const out = [];
    function walk(group) {
      for (const e of group.entries) {
        const pw = e.fields.get('Password');
        out.push({
          title:    e.fields.get('Title') || '',
          username: e.fields.get('UserName') || '',
          password: (pw && pw.getText) ? pw.getText() : (pw || ''),
          url:      e.fields.get('URL') || '',
          notes:    e.fields.get('Notes') || '',
        });
      }
      for (const sub of group.groups) walk(sub);
    }
    walk(db.getDefaultGroup());
    return out;
  }

  function downloadBlob(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  window.HorseSafeImportExport = {
    parseBitwardenJson,
    parseKeePassCsv,
    parseCSV,
    buildCSV,
    buildJSON,
    parseXlsx,
    buildXlsx,
    mergeEntriesInto,
    extractEntries,
    downloadBlob,
  };
})();
