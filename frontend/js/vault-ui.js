/* HorseSafe Vault UI v0.2.0-Koblitz (sinds v0.0.2-Hellman)
 * State per pagina-load: { db, vaultId, etag, currentEntry, secret }
 */
(function () {
  'use strict';

  const state = {
    db: null,
    vaultId: null,
    etag: null,
    currentEntry: null,
    totpTimer: null,
    // v0.2.0-Koblitz: ontgrendelmateriaal {ph, kh} als kdbxweb.ProtectedValue (of null), nooit het
    // leesbare wachtwoord of de keyfile. Alleen tab-RAM, alleen zolang de vault open is.
    secret: null,
    idleTimer: null,
    // v0.3.5-Miller: categorie + zoeken (alleen weergave; niets hiervan gaat naar de server)
    groupId: 'all',
    query: '',
    inGroupOnly: false,
    expanded: new Set(),
    groups: [],
  };

  // Automatisch vergrendelen na inactiviteit (v0.2.0-Koblitz)
  const AUTO_LOCK_MS = 15 * 60 * 1000;
  const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'];

  function resetIdleTimer() {
    if (state.idleTimer) clearTimeout(state.idleTimer);
    state.idleTimer = state.db ? setTimeout(() => { if (state.db) lockVault(); }, AUTO_LOCK_MS) : null;
  }
  ACTIVITY_EVENTS.forEach((ev) => document.addEventListener(ev, resetIdleTimer, { passive: true }));

  function wipeSecret() {
    if (state.secret && window.HorseSafeHwKeys) window.HorseSafeHwKeys.wipeSecret(state.secret);
    state.secret = null;
  }

  function clearUnlockInputs() {
    $('vault-pw').value = '';
    const kf = $('vault-keyfile');
    if (kf) kf.value = '';
  }

  function stopTotpLoop() {
    if (state.totpTimer) {
      clearInterval(state.totpTimer);
      state.totpTimer = null;
    }
  }

  async function renderTotpOnce(uri) {
    try {
      const r = await window.HorseSafeTotp.generateTotp(uri);
      const codeEl = $('d-totp-code');
      const cdEl = $('d-totp-countdown');
      if (codeEl) codeEl.textContent = r.code.replace(/(.{3})(.{3,5})/, '$1 $2');
      if (cdEl) cdEl.textContent = r.secondsLeft + 's';
    } catch (e) {
      const codeEl = $('d-totp-code');
      if (codeEl) codeEl.textContent = 'TOTP-fout';
      console.error('[HorseSafe] TOTP-render fout:', e);
    }
  }

  function startTotpLoop(uri) {
    stopTotpLoop();
    renderTotpOnce(uri);
    state.totpTimer = setInterval(() => renderTotpOnce(uri), 1000);
  }

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

  // ───────────── v0.3.5-Miller: categorieën + zoeken ─────────────
  function VI() { return window.HorseSafeVaultIndex; }

  /** Gekozen categorie bestaat niet meer (bv. na import)? Dan terug naar "Alle". */
  function currentGroupNode() {
    if (state.groupId === 'all') return null;
    const n = VI().findNode(state.groups, state.groupId);
    if (!n) state.groupId = 'all';
    return n;
  }

  /** Categorie waarin "+ Nieuwe entry" landt: de gekozen groep, nooit de prullenbak. */
  function newEntryGroup() {
    const n = currentGroupNode();
    return n && !n.isRecycleBin ? n : null;
  }

  function prepareNewEntry() {
    const n = newEntryGroup();
    setText('e-group-label', n ? VI().pathLabel(n.path) : 'hoofdmap');
  }

  /** Weergavenaam; de prullenbak zelf heet altijd "Prullenbak" (KeePass noemt hem "Recycle Bin"). */
  function groupName(g) {
    const isBinRoot = g.isRecycleBin && (g.path || []).length === 1;
    return isBinRoot ? 'Prullenbak' : (g.name || g.label || '(naamloos)');
  }

  function renderTree(counts, total) {
    const tree = $('group-tree');
    const sel = $('group-select');
    tree.innerHTML = '';
    sel.innerHTML = '';

    const opt = (value, label) => {
      const o = document.createElement('option');
      o.value = value;
      o.textContent = label;
      sel.appendChild(o);
    };
    opt('all', `Alle entries (${total})`);
    for (const g of VI().flatten(state.groups)) {
      opt(g.uuid, `${' '.repeat(g.depth)}${groupName(g)} (${counts.get(g.uuid) || 0})`);
    }
    sel.value = state.groupId;

    const item = (uuid, label, n, opts = {}) => {
      const li = document.createElement('li');
      li.setAttribute('role', 'treeitem');
      const row = document.createElement('div');
      row.className = 'group-row';
      const tog = document.createElement('button');
      tog.type = 'button';
      tog.className = 'group-toggle';
      if (opts.children && opts.children.length) {
        const open = state.expanded.has(uuid);
        tog.textContent = open ? '▾' : '▸';
        tog.setAttribute('aria-label', (open ? 'Inklappen: ' : 'Uitklappen: ') + label);
        li.setAttribute('aria-expanded', String(open));
        tog.addEventListener('click', () => {
          if (state.expanded.has(uuid)) state.expanded.delete(uuid); else state.expanded.add(uuid);
          renderEntries();
        });
      } else {
        tog.hidden = true;
        tog.tabIndex = -1;
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'group-btn' + (opts.bin ? ' bin' : '');
      btn.dataset.group = uuid;
      if (state.groupId === uuid) btn.setAttribute('aria-current', 'true');
      const name = document.createElement('span');
      name.textContent = label;
      const cnt = document.createElement('span');
      cnt.className = 'count';
      cnt.textContent = String(n);
      btn.append(name, cnt);
      btn.addEventListener('click', () => chooseGroup(uuid));
      row.append(tog, btn);
      li.appendChild(row);
      if (opts.children && opts.children.length && state.expanded.has(uuid)) {
        const ul = document.createElement('ul');
        ul.setAttribute('role', 'group');
        for (const c of opts.children) ul.appendChild(groupItem(c));
        li.appendChild(ul);
      }
      return li;
    };
    const groupItem = (g) => item(g.uuid, groupName(g), counts.get(g.uuid) || 0,
      { children: g.children, bin: g.isRecycleBin });

    tree.appendChild(item('all', 'Alle entries', total));
    // Prullenbak onderaan
    const normal = state.groups.filter((g) => !g.isRecycleBin);
    const bins = state.groups.filter((g) => g.isRecycleBin);
    for (const g of normal.concat(bins)) tree.appendChild(groupItem(g));
  }

  function chooseGroup(uuid) {
    state.groupId = uuid || 'all';
    // Pad naar de gekozen groep openklappen, zodat hij zichtbaar blijft in de boom
    const n = VI().findNode(state.groups, state.groupId);
    if (n) {
      for (const g of VI().flatten(state.groups)) {
        if (n.path.length > g.path.length && g.path.every((x, i) => x === n.path[i])) state.expanded.add(g.uuid);
      }
    }
    renderEntries();
  }

  function renderEntries() {
    const all = window.HorseSafeCrypto.listEntries(state.db);
    state.groups = window.HorseSafeCrypto.listGroups(state.db);
    const node = currentGroupNode();
    const { total, counts } = VI().countEntries(all);
    renderTree(counts, total);

    const searching = VI().terms(state.query).length > 0;
    const entries = VI().filterEntries(all, state.groups, {
      groupUuid: state.groupId, query: state.query, inGroupOnly: state.inGroupOnly,
    });
    const scopeLabel = node ? VI().pathLabel(node.path) : 'Alle entries';
    setText('list-title', searching && !(state.inGroupOnly && node) ? 'Zoekresultaten' : scopeLabel);
    setText('entry-count', entries.length);
    setText('entry-total', searching || node ? ` van ${total}` : '');
    $('search-scope-label').hidden = !node;
    // Categoriekolom alleen als de lijst meerdere categorieën kan bevatten
    $('entries-table').classList.toggle('no-group-col', !!node && !(searching && !state.inGroupOnly));
    prepareNewEntry();

    // Detailvenster alleen voor een entry die in de lijst staat
    if (state.currentEntry && !entries.some((e) => e.uuid === state.currentEntry.uuid)) {
      stopTotpLoop();
      state.currentEntry = null;
      hide('detail-pane');
    }

    const tbody = $('entries-body');
    tbody.innerHTML = '';
    if (entries.length === 0) {
      const msg = searching ? 'Niets gevonden'
        : (all.length === 0 ? 'Geen entries — klik "+ Nieuwe entry"' : 'Geen entries in deze categorie');
      tbody.innerHTML = `<tr><td colspan="4" class="muted">${escapeHtml(msg)}</td></tr>`;
      return;
    }
    for (const e of entries) {
      const tr = document.createElement('tr');
      tr.className = 'selectable';
      tr.dataset.uuid = e.uuid;
      tr.innerHTML = `<td>${escapeHtml(e.title)}</td><td>${escapeHtml(e.username)}</td>`
        + `<td>${escapeHtml(e.url)}</td><td class="col-group">${escapeHtml(VI().pathLabel(e.groupPath) || 'hoofdmap')}</td>`;
      tr.addEventListener('click', () => selectEntry(e));
      if (state.currentEntry && state.currentEntry.uuid === e.uuid) tr.classList.add('selected');
      tbody.appendChild(tr);
    }
  }

  function resetView() {
    state.groupId = 'all';
    state.query = '';
    state.inGroupOnly = false;
    state.expanded = new Set();
    state.groups = [];
    $('entry-search').value = '';
    $('search-in-group').checked = false;
    $('group-tree').innerHTML = '';
    $('group-select').innerHTML = '';
    $('entries-body').innerHTML = '';
  }

  (function wireViewControls() {
    let t = null;
    $('entry-search').addEventListener('input', (ev) => {
      clearTimeout(t);
      t = setTimeout(() => { state.query = ev.target.value; if (state.db) renderEntries(); }, 120);
    });
    $('entry-search').addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') {
        ev.target.value = '';
        state.query = '';
        if (state.db) renderEntries();
      }
    });
    $('search-in-group').addEventListener('change', (ev) => {
      state.inGroupOnly = ev.target.checked;
      if (state.db) renderEntries();
    });
    $('group-select').addEventListener('change', (ev) => { if (state.db) chooseGroup(ev.target.value); });
    // "/" springt naar het zoekveld (niet tijdens typen in een ander veld)
    document.addEventListener('keydown', (ev) => {
      if (ev.key !== '/' || !state.db || $('vault-section').hidden) return;
      const tag = (document.activeElement && document.activeElement.tagName) || '';
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag) || (document.activeElement && document.activeElement.isContentEditable)) return;
      ev.preventDefault();
      $('entry-search').focus();
    });
  })();

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

    // TOTP — toon alleen als entry een geldig otpauth-veld heeft
    stopTotpLoop();
    if (entry.otp && window.HorseSafeTotp) {
      show('d-totp-label');
      show('d-totp-cell');
      startTotpLoop(entry.otp);
    } else {
      hide('d-totp-label');
      hide('d-totp-cell');
    }

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
      // PUT /vault/{id} geeft de nieuwe etag in de JSON-body (geen ETag-header); zonder dit liep de
      // tweede save op rij op 422 (If-Match ontbrak). Gevonden in reviewronde 2.
      state.etag = r.etag || (r.data && r.data.etag) || null;
      clearError('global-error');
      return true;
    } catch (e) {
      showError('global-error', 'Save mislukt: ' + e.message);
      return false;
    }
  }

  /**
   * Open de vault met het formulier, of — v0.2.0-Koblitz — met een kdbxweb.Credentials-object uit een
   * hardware-sleutel (override = {credentials}, zie HorseSafeHwKeys.credentialsFromHashes).
   * Returnt true bij succes.
   */
  async function unlockOrCreate(override) {
    const viaKey = !!(override && typeof override === 'object' && !(override instanceof Event) && override.credentials);
    let pw = '';
    let keyFileBuffer = null;
    if (!viaKey) {
      pw = $('vault-pw').value;
      const keyFileInput = $('vault-keyfile');
      if (keyFileInput && keyFileInput.files && keyFileInput.files[0]) {
        keyFileBuffer = await keyFileInput.files[0].arrayBuffer();
      }
    }
    if (!viaKey && !pw && !keyFileBuffer) {
      showError('unlock-error', 'Voer een vault-wachtwoord of keyfile in (of beide).');
      return false;
    }
    if (!viaKey && pw && pw.length > 0 && pw.length < 6) {
      showError('unlock-error', 'Vault-wachtwoord moet minimaal 6 tekens zijn (POC; productie ≥12).');
      return false;
    }
    clearError('unlock-error');
    $('unlock-submit').disabled = true;
    $('unlock-status').hidden = false;

    try {
      const listRes = await window.HorseSafeAPI.listVaults();
      if (!listRes.ok) {
        if (listRes.status === 401) {
          window.location.href = 'login.html';
          return false;
        }
        if (listRes.status === 403 && listRes.data?.detail?.error === 'mfa_required') {
          window.location.href = 'mfa.html';
          return false;
        }
        showError('unlock-error', `Fout bij vault-list: ${listRes.status}`);
        return false;
      }

      if (listRes.data.length === 0 && viaKey) {
        showError('unlock-error', 'Er is nog geen vault om met een sleutel te openen.');
        return false;
      }
      if (listRes.data.length === 0) {
        // Geen vault — maak nieuwe aan
        $('unlock-status').textContent = 'Nog geen vault — nieuwe wordt aangemaakt met dit wachtwoord...';
        const { db } = await window.HorseSafeCrypto.createDatabase(pw, 'default');
        const blob = await window.HorseSafeCrypto.saveDatabase(db);
        const createRes = await window.HorseSafeAPI.createVault('default', blob);
        if (!createRes.ok) {
          showError('unlock-error', `Vault create-fout: ${createRes.status}`);
          return false;
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
          return false;
        }
        try {
          state.db = viaKey
            ? await window.HorseSafeCrypto.openDatabaseWithCredentials(readRes.blob, override.credentials)
            : await window.HorseSafeCrypto.openDatabase(readRes.blob, pw, keyFileBuffer);
          state.vaultId = meta.id;
          state.etag = readRes.etag;
        } catch (e) {
          const detail = (e && (e.code || e.name || e.message)) || 'onbekende fout';
          console.error('[HorseSafe] openDatabase failed:', e);
          if (detail === 'InvalidKey' && viaKey) {
            // De kopie ging open, maar de KDBX weigert: wachtwoord/keyfile is buiten HorseSafe gewijzigd.
            showError('unlock-error', window.HorseSafeHwKeys.MESSAGES.stale_copy);
            document.dispatchEvent(new CustomEvent('horsesafe:stale-copy'));
          } else if (detail === 'InvalidKey') {
            showError('unlock-error', 'Verkeerd wachtwoord of verkeerde keyfile.');
          } else {
            showError('unlock-error', `Vault openen mislukt: ${detail}. Check pw + keyfile.`);
          }
          return false;
        }
      }

      // Het wachtwoordveld direct legen; het leesbare wachtwoord blijft niet bewaard.
      clearUnlockInputs();
      pw = '';
      keyFileBuffer = null;

      // Ontgrendelmateriaal {ph, kh} in tab-RAM houden zolang de vault open is: nodig om een
      // hardware-sleutel te koppelen of opnieuw te verzegelen (v0.2.0-Koblitz, P-CRYPT-09).
      // Afgeleid uit de Credentials waarmee de KDBX écht open ging. Wordt bij vergrendelen gewist.
      wipeSecret();
      if (window.HorseSafeHwKeys) {
        try {
          state.secret = await window.HorseSafeHwKeys.secretFromCredentials(state.db.credentials);
        } catch (e) {
          console.warn('[HorseSafe] ontgrendelmateriaal niet beschikbaar:', e && e.code);
          state.secret = null;
        }
      }
      resetIdleTimer();

      // Switch UI
      hide('unlock-section');
      show('vault-section');
      $('vault-name').textContent = listRes.data[0]?.name || 'default';
      $('vault-stats').textContent = ' — zero-knowledge (server ziet alleen ciphertext)';
      renderEntries();
      document.dispatchEvent(new CustomEvent('horsesafe:unlocked'));
      return true;
    } catch (e) {
      showError('unlock-error', 'Onverwachte fout: ' + e.message);
      return false;
    } finally {
      $('unlock-submit').disabled = false;
    }
  }

  function lockVault() {
    stopTotpLoop();
    state.db = null;
    state.vaultId = null;
    state.etag = null;
    state.currentEntry = null;
    wipeSecret();
    resetIdleTimer();
    clearUnlockInputs();
    resetView();
    hide('vault-section');
    show('unlock-section');
    document.dispatchEvent(new CustomEvent('horsesafe:locked'));
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
    const target = newEntryGroup();
    window.HorseSafeCrypto.addEntry(state.db, data, target ? target.uuid : null);
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

  async function copyTotp() {
    if (!state.currentEntry || !state.currentEntry.otp) return;
    try {
      const r = await window.HorseSafeTotp.generateTotp(state.currentEntry.otp);
      await navigator.clipboard.writeText(r.code);
      const btn = $('d-totp-copy');
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => { btn.textContent = orig; }, 1500);
      }
    } catch (e) {
      console.error('[HorseSafe] TOTP-copy fout:', e);
    }
  }

  /**
   * v0.2.0-Koblitz: wissel het ontgrendelmateriaal na een geslaagde /rekey. De kluis is al met de nieuwe
   * Credentials opgeslagen; hier alleen de etag en {ph, kh} in RAM bijwerken.
   */
  async function adoptRekey(etag) {
    state.etag = etag;
    wipeSecret();
    state.secret = await window.HorseSafeHwKeys.secretFromCredentials(state.db.credentials);
  }

  /**
   * v0.2.0-Koblitz (reviewronde 2): leg de publieke sleutel van een nieuw gekoppelde hardware-sleutel
   * vast in de versleutelde kluis en sla de kluis op. Gooit als opslaan mislukt (dan niet koppelen).
   */
  async function pinKey(keyId, publicKey) {
    if (!state.db) throw new window.HorseSafeHwKeys.HwKeyError('no_secret');
    window.HorseSafeHwKeys.pinKey(state.db, state.vaultId, keyId, publicKey);
    if (!(await persist())) throw new window.HorseSafeHwKeys.HwKeyError('pin_save_failed');
  }

  /** Vastgelegde {key_id: public_key} uit de geopende kluis (leeg als die dicht is). */
  function pins() {
    return state.db ? window.HorseSafeHwKeys.readPins(state.db, state.vaultId) : {};
  }

  window.HorseSafeVaultUI = {
    state,
    adoptRekey,
    pinKey,
    pins,
    unlockOrCreate,
    lockVault,
    addNewEntry,
    deleteCurrent,
    togglePwDisplay,
    copyPassword,
    copyTotp,
    generatePw,
    renderEntries,
    prepareNewEntry,
  };
})();
