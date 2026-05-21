/* HorseSafe page-init voor index.html v0.0.7-Bellare
 * CSP-compliant: geen inline scripts in HTML (script-src 'self' only).
 */
(function () {
  'use strict';

  document.getElementById('show-register').addEventListener('click', () => {
    document.getElementById('register-card').hidden = false;
    document.getElementById('reg-email').focus();
  });

  document.getElementById('register-cancel').addEventListener('click', () => {
    document.getElementById('register-card').hidden = true;
  });

  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await window.HorseSafeAuth.handleRegister();
  });
})();
