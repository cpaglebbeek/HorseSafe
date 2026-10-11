/* HorseSafe step-up v0.2.0-Koblitz — contract: docs/HARDWARE_KEYS.md §12.8
 *
 * Gevoelige acties (sleutel koppelen als er al sleutels zijn, opnieuw verzegelen, wachtwoord/keyfile
 * wijzigen, blokkade noodsleutel opheffen) vragen een verse bevestiging. De server antwoordt dan
 * 403 stepup_required (of stepup_bio_required). withStepUp() toont deze dialoog en herhaalt de
 * oorspronkelijke actie daarna precies één keer.
 *
 *   - Heeft de gebruiker een YubiKey Bio: alleen de Bio (de server weigert dan TOTP).
 *   - Geen Bio (409 no_bio_keys): code uit de authenticator-app (TOTP).
 *   - Browser/host zonder hardware-sleutelsteun (Safari, geen X25519, andere host): meteen de code;
 *     de server weigert TOTP toch als er een actieve Bio is (stepup_method_not_allowed).
 *   - Opheffen van een blokkade: altijd alleen de Bio (besluit 3), nooit TOTP of wachtwoord.
 */
(function () {
  'use strict';

  const HK = window.HorseSafeHwKeys;
  let pending = null; // { resolve, bioOnly }
  // Fouten waarbij de Bio in deze browser/op deze host niet kan; dan is de code het alternatief.
  const SUPPORT_ERRORS = ['browser_unsupported', 'safari', 'wrong_host', 'no_prf'];

  function $(id) { return document.getElementById(id); }

  function msg(text) {
    const el = $('stepup-error');
    el.textContent = text || '';
    el.hidden = !text;
  }

  function finish(ok) {
    $('stepup-section').hidden = true;
    $('stepup-code').value = '';
    msg('');
    const p = pending;
    pending = null;
    if (p) p.resolve(ok);
  }

  function showTotp(intro) {
    $('stepup-intro').textContent = intro || 'Je hebt geen YubiKey Bio gekoppeld. Bevestig met de code uit je authenticator-app.';
    $('stepup-bio-actions').hidden = true;
    $('stepup-totp-form').hidden = false;
    $('stepup-code').focus();
  }

  async function tryBio() {
    if (!pending) return;
    msg('');
    $('stepup-bio').disabled = true;
    try {
      await HK.stepUp({ method: 'bio' });
      finish(true);
    } catch (e) {
      if (e && e.code === 'no_bio_keys' && pending && !pending.bioOnly) {
        showTotp();
      } else if (e && SUPPORT_ERRORS.includes(e.code) && pending && !pending.bioOnly) {
        showTotp(`${HK.messageFor(e)} Bevestig met de code uit je authenticator-app.`);
      } else if (e && e.code === 'no_bio_keys') {
        msg('Opheffen kan alleen met een gekoppelde YubiKey Bio. Koppel eerst een YubiKey Bio.');
      } else {
        msg(HK.messageFor(e));
      }
    } finally {
      $('stepup-bio').disabled = false;
    }
  }

  async function submitTotp(ev) {
    ev.preventDefault();
    if (!pending) return;
    msg('');
    const code = $('stepup-code').value.replace(/\s+/g, '');
    if (!/^\d{6,8}$/.test(code)) {
      msg('Voer de 6-cijferige code in.');
      return;
    }
    try {
      await HK.stepUp({ method: 'totp', code });
      finish(true);
    } catch (e) {
      msg(HK.messageFor(e));
    }
  }

  /** Toon de dialoog; resolve true na een geslaagde step-up, false bij annuleren. */
  function open({ bioOnly = false } = {}) {
    if (pending) finish(false);
    return new Promise((resolve) => {
      pending = { resolve, bioOnly };
      $('stepup-intro').textContent = bioOnly
        ? 'Opheffen kan alleen met je YubiKey Bio. Raak je YubiKey Bio aan.'
        : 'Bevestig deze actie. Raak je YubiKey Bio aan.';
      $('stepup-bio-actions').hidden = false;
      $('stepup-totp-form').hidden = true;
      msg('');
      $('stepup-section').hidden = false;
      $('stepup-section').scrollIntoView({ block: 'center' });
      start(bioOnly);
    });
  }

  async function start(bioOnly) {
    const support = await HK.checkSupport();
    if (!pending) return;
    if (support.ok) { tryBio(); return; }
    const why = HK.messageFor({ code: support.reason });
    if (bioOnly) {
      msg(why);
      return;
    }
    showTotp(`${why} Bevestig met de code uit je authenticator-app.`);
  }

  /** Voer fn uit; bij 403 stepup_required/stepup_bio_required eerst step-up, dan fn één keer opnieuw. */
  async function withStepUp(fn, { bioOnly = false } = {}) {
    try {
      return await fn();
    } catch (e) {
      if (!e || (e.code !== 'stepup_required' && e.code !== 'stepup_bio_required')) throw e;
      const ok = await open({ bioOnly: bioOnly || e.code === 'stepup_bio_required' });
      if (!ok) throw new HK.HwKeyError('cancelled', 'Bevestiging geannuleerd.');
      return fn();
    }
  }

  $('stepup-bio').addEventListener('click', tryBio);
  $('stepup-totp-form').addEventListener('submit', submitTotp);
  $('stepup-cancel').addEventListener('click', () => finish(false));

  window.HorseSafeStepUp = { open, withStepUp };
})();
