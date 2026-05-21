/* HorseSafe admin UI v0.0.4-Rivest */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }

  function bytesHuman(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
    return (n / (1024 * 1024)).toFixed(1) + ' MiB';
  }

  function fmtTs(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleString('nl-NL');
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  async function fetchJSON(method, path, body) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(window.HorseSafeAPI.base + path, opts);
    if (res.status === 401) {
      window.location.href = 'login.html';
      throw new Error('Unauthenticated');
    }
    if (res.status === 403) {
      const data = await res.json().catch(() => ({}));
      if (data?.detail?.error === 'mfa_required') {
        window.location.href = 'mfa.html';
        throw new Error('MFA required');
      }
      alert('Geen toegang (geen admin-rechten?)');
      throw new Error('Forbidden');
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(data)}`);
    }
    if (res.status === 204) return null;
    return res.json();
  }

  async function loadStats() {
    const s = await fetchJSON('GET', '/admin/stats');
    $('s-users').textContent = s.users_total;
    $('s-vaults').textContent = s.vaults_total;
    $('s-storage').textContent = bytesHuman(s.storage_bytes);
    $('s-logins').textContent = s.logins_24h;
    $('s-failed').textContent = s.failed_logins_24h;
  }

  async function loadUsers() {
    const users = await fetchJSON('GET', '/admin/users');
    const tbody = $('users-body');
    tbody.innerHTML = '';
    for (const u of users) {
      const isAdmin = !!u.is_admin;
      const hasTotp = !!u.has_totp;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(u.email)} ${isAdmin ? '<span class="badge badge-admin">ADMIN</span>' : ''}</td>
        <td>${fmtTs(u.created_at)}</td>
        <td>${fmtTs(u.last_login_at)}</td>
        <td>${u.vault_count}</td>
        <td>${bytesHuman(u.storage_bytes)}</td>
        <td>${hasTotp ? `<span class="badge badge-totp">TOTP</span> ${u.backup_codes_remaining} codes` : '—'}</td>
        <td class="row-actions">
          ${hasTotp ? `<button data-action="disable-mfa" data-uid="${u.id}">MFA reset</button>` : ''}
          <button data-action="magic-link" data-uid="${u.id}" class="secondary">Magic-link</button>
          <button data-action="delete" data-uid="${u.id}" data-email="${escapeHtml(u.email)}" class="danger">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', () => handleAction(btn));
    });
  }

  async function handleAction(btn) {
    const uid = btn.dataset.uid;
    const action = btn.dataset.action;
    const reason = prompt(`Reden (verplicht, min. 10 chars) voor "${action}":`);
    if (!reason || reason.length < 10) {
      alert('Reden is verplicht (minimaal 10 tekens).');
      return;
    }
    try {
      if (action === 'delete') {
        const email = btn.dataset.email;
        const conf = prompt(`Typ "${email}" om te bevestigen:`);
        if (conf !== email) { alert('Bevestiging niet gematcht.'); return; }
        await fetchJSON('DELETE', `/admin/users/${encodeURIComponent(uid)}`, { reason });
      } else if (action === 'disable-mfa') {
        await fetchJSON('POST', `/admin/users/${encodeURIComponent(uid)}/disable-mfa`, { reason });
      } else if (action === 'magic-link') {
        await fetchJSON('POST', `/admin/users/${encodeURIComponent(uid)}/send-magic-link`, { reason });
        alert('Magic-link verzonden naar user.');
      }
      await loadUsers();
      await loadStats();
      await loadAudit();
    } catch (e) {
      alert('Fout: ' + e.message);
    }
  }

  let auditOffset = 0;
  async function loadAudit() {
    const event = $('f-event').value.trim();
    const user = $('f-user').value.trim();
    const limit = parseInt($('f-limit').value, 10) || 50;
    const params = new URLSearchParams({ limit: String(limit), offset: String(auditOffset) });
    if (event) params.set('event', event);
    if (user) params.set('user', user);
    const rows = await fetchJSON('GET', '/admin/audit?' + params.toString());
    const tbody = $('audit-body');
    tbody.innerHTML = '';
    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">Geen events</td></tr>';
    } else {
      for (const r of rows) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${fmtTs(r.ts)}</td>
          <td>${escapeHtml((r.user_id || '').substring(0, 8))}</td>
          <td>${escapeHtml(r.event)}</td>
          <td>${escapeHtml(r.ip || '')}</td>
          <td>${escapeHtml(r.detail || '').substring(0, 60)}</td>
          <td>${escapeHtml(r.reason || '')}</td>
        `;
        tbody.appendChild(tr);
      }
    }
    $('audit-pagination').textContent = `Offset ${auditOffset}, ${rows.length} rijen`;
  }

  $('f-apply').addEventListener('click', () => { auditOffset = 0; loadAudit(); });
  $('f-export-csv').addEventListener('click', () => {
    const event = $('f-event').value.trim();
    const user = $('f-user').value.trim();
    const params = new URLSearchParams();
    if (event) params.set('event', event);
    if (user) params.set('user', user);
    const url = window.HorseSafeAPI.base + '/admin/audit/export?' + params.toString();
    // Trigger download via navigatie (cookie wordt automatisch meegestuurd)
    window.location.href = url;
  });
  $('audit-prev').addEventListener('click', () => {
    auditOffset = Math.max(0, auditOffset - (parseInt($('f-limit').value, 10) || 50));
    loadAudit();
  });
  $('audit-next').addEventListener('click', () => {
    auditOffset += parseInt($('f-limit').value, 10) || 50;
    loadAudit();
  });

  // Init — check is-admin via /auth/me
  (async () => {
    try {
      const me = await fetchJSON('GET', '/auth/me');
      if (!me.is_admin) {
        alert('Geen admin-rechten.');
        window.location.href = 'vault.html';
        return;
      }
      await loadStats();
      await loadUsers();
      await loadAudit();
    } catch (e) {
      // fetchJSON heeft al redirect/alert gedaan voor 401/403
    }
  })();
})();
