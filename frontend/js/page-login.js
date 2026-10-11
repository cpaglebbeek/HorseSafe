/* HorseSafe page-init voor login.html v0.0.7-Bellare (CSP-compliant) */
(function () {
  'use strict';
  // v0.2.0-Koblitz: foutmelding na een geweigerde magic-link (?error=…)
  const LINK_ERRORS = {
    invalid_link: 'Deze link is ongeldig, verlopen of al gebruikt. Log in en vraag een nieuwe aan.',
    magic_link_login_first: 'Log eerst in deze browser in met je wachtwoord en open de link daarna opnieuw. '
      + 'De link is een tweede stap en logt niet zelf in; hij is nog niet gebruikt.',
  };
  const err = new URLSearchParams(window.location.search).get('error');
  if (err && LINK_ERRORS[err]) {
    const el = document.getElementById('login-error');
    el.textContent = LINK_ERRORS[err];
    el.hidden = false;
  }
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await window.HorseSafeAuth.handleLogin();
  });
})();
