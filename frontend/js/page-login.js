/* HorseSafe page-init voor login.html v0.0.7-Bellare (CSP-compliant) */
(function () {
  'use strict';
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await window.HorseSafeAuth.handleLogin();
  });
})();
