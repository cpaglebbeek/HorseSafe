/* HorseSafe backup-codes UI v0.0.4-Rivest */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }

  let codes = [];

  $('generate-btn').addEventListener('click', async () => {
    if (!confirm('Hierdoor worden eventueel eerder gegenereerde codes ongeldig. Doorgaan?')) {
      return;
    }
    $('generate-btn').disabled = true;
    try {
      const r = await fetch(window.HorseSafeAPI.base + '/auth/backup-codes/generate', {
        method: 'POST', credentials: 'include',
      });
      if (r.status === 401) { window.location.href = 'login.html'; return; }
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        alert('Fout: ' + (data?.detail?.error || r.status));
        return;
      }
      const body = await r.json();
      codes = body.codes;
      const grid = $('codes-grid');
      grid.innerHTML = '';
      for (const code of codes) {
        const div = document.createElement('div');
        div.textContent = code;
        grid.appendChild(div);
      }
      $('generate-pane').hidden = true;
      $('show-pane').hidden = false;
    } finally {
      $('generate-btn').disabled = false;
    }
  });

  $('ack').addEventListener('change', () => {
    $('confirm-btn').disabled = !$('ack').checked;
  });

  $('copy-btn').addEventListener('click', async () => {
    await navigator.clipboard.writeText(codes.join('\n'));
    $('copy-btn').firstChild.textContent = '✓ Gekopieerd';
    setTimeout(() => { $('copy-btn').firstChild.textContent = '📋 Kopieer alle codes'; }, 2000);
  });

  $('confirm-btn').addEventListener('click', () => {
    codes = [];
    window.location.href = 'settings.html';
  });

  // Reload-warning zolang codes onthouden worden
  window.addEventListener('beforeunload', (e) => {
    if (codes.length > 0 && !$('ack').checked) {
      e.preventDefault();
      e.returnValue = 'Codes zijn nog niet bevestigd — ze gaan verloren bij refresh!';
    }
  });
})();
