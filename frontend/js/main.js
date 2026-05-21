/* HorseSafe main wiring v0.0.2-Hellman — vault.html */
(function () {
  'use strict';

  const UI = window.HorseSafeVaultUI;

  function $(id) { return document.getElementById(id); }

  $('unlock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await UI.unlockOrCreate();
  });

  $('logout-from-unlock').addEventListener('click', () => window.HorseSafeAuth?.logout?.());
  $('logout-from-vault').addEventListener('click', () => window.HorseSafeAuth?.logout?.());

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
  $('d-delete').addEventListener('click', () => UI.deleteCurrent());

  // Reload-warning bij open vault
  window.addEventListener('beforeunload', (e) => {
    if (UI.state.db) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
})();
