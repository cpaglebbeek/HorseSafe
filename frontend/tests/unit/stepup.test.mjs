// v0.2.0-Koblitz — stepup.js (§12.8), reviewronde 1 bevinding 6: zonder hardware-sleutelsteun
// (Safari, geen X25519, andere host) moet de TOTP-route bereikbaar zijn; opheffen blijft Bio-only.
// Node ≥ 20, nep-DOM. Draai: node --test tests/unit/
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const src = readFileSync(new URL('../../js/stepup.js', import.meta.url), 'utf8');
const IDS = ['stepup-error', 'stepup-section', 'stepup-code', 'stepup-intro', 'stepup-bio-actions',
  'stepup-totp-form', 'stepup-bio', 'stepup-cancel'];

let els;
let calls;
let support;

class FakeError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function load() {
  els = {};
  for (const id of IDS) {
    els[id] = {
      id, textContent: '', hidden: true, value: '', disabled: false, listeners: {},
      focus() {}, scrollIntoView() {},
      addEventListener(t, fn) { this.listeners[t] = fn; },
    };
  }
  calls = [];
  globalThis.document = { getElementById: (id) => els[id] };
  globalThis.window = globalThis;
  globalThis.HorseSafeHwKeys = {
    HwKeyError: FakeError,
    checkSupport: async () => support,
    messageFor: (e) => `melding:${e.code}`,
    stepUp: async (o) => { calls.push(o); throw new FakeError(o.method === 'bio' ? support.reason || 'x' : 'x'); },
  };
  vm.runInThisContext(src);
  return globalThis.HorseSafeStepUp;
}

const tick = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => { support = { ok: true, reason: null }; });

test('zonder hardware-sleutelsteun: meteen het TOTP-veld, geen Bio-poging', async () => {
  support = { ok: false, reason: 'safari' };
  const SU = load();
  SU.open();
  await tick();
  assert.equal(els['stepup-totp-form'].hidden, false);
  assert.equal(els['stepup-bio-actions'].hidden, true);
  assert.match(els['stepup-intro'].textContent, /melding:safari.*authenticator-app/);
  assert.deepEqual(calls, []);
});

test('opheffen (bioOnly) zonder steun: geen TOTP-veld, wel de reden', async () => {
  support = { ok: false, reason: 'wrong_host' };
  const SU = load();
  SU.open({ bioOnly: true });
  await tick();
  assert.equal(els['stepup-totp-form'].hidden, true);
  assert.equal(els['stepup-error'].textContent, 'melding:wrong_host');
});

test('steunfout pas tijdens de Bio-poging (bijv. no_prf): alsnog het TOTP-veld', async () => {
  const SU = load();
  globalThis.HorseSafeHwKeys.stepUp = async (o) => { calls.push(o); throw new FakeError('no_prf'); };
  SU.open();
  await tick(); await tick();
  assert.deepEqual(calls, [{ method: 'bio' }]);
  assert.equal(els['stepup-totp-form'].hidden, false);
});

test('met steun: eerst de Bio', async () => {
  const SU = load();
  globalThis.HorseSafeHwKeys.stepUp = async (o) => { calls.push(o); };
  const p = SU.open();
  await tick(); await tick();
  assert.deepEqual(calls, [{ method: 'bio' }]);
  assert.equal(await p, true);
});
