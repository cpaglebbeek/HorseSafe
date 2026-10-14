// v0.3.5-Miller — categorieën en zoeken (js/vault-index.js). Draai: node --test tests/unit/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

vm.runInThisContext(readFileSync(new URL('../../js/vault-index.js', import.meta.url), 'utf8'));
const VI = globalThis.HorseSafeVaultIndex;

// Boom: A (A1), Werk, Prullenbak (Oud)
const groups = [
  { uuid: 'A', name: '5 Eigen apps & diensten', path: ['5 Eigen apps & diensten'], isRecycleBin: false, children: [
    { uuid: 'A1', name: 'FODMAP', path: ['5 Eigen apps & diensten', 'FODMAP'], isRecycleBin: false, children: [] },
  ] },
  { uuid: 'W', name: '8 Werk', path: ['8 Werk'], isRecycleBin: false, children: [] },
  { uuid: 'B', name: 'Prullenbak', path: ['Prullenbak'], isRecycleBin: true, children: [
    { uuid: 'B1', name: 'Oud', path: ['Prullenbak', 'Oud'], isRecycleBin: true, children: [] },
  ] },
];
const E = (title, chain, path, extra = {}) => ({
  uuid: title, title, username: '', url: '', notes: '', groupChain: chain, groupPath: path,
  inRecycleBin: chain[0] === 'B', password: { secret: 'NIET-ZOEKBAAR' }, ...extra,
});
const entries = [
  E('Root-entry', [], []),
  E('FODMAP backend', ['A', 'A1'], ['5 Eigen apps & diensten', 'FODMAP'], { username: 'admin' }),
  E('ArchPortal', ['A'], ['5 Eigen apps & diensten'], { url: 'https://icthorsecloud.nl/archportal/' }),
  E('Staff Café', ['W'], ['8 Werk'], { notes: 'Gebruikt in: staffcloud' }),
  E('Weggegooid', ['B'], ['Prullenbak']),
  E('Heel oud', ['B', 'B1'], ['Prullenbak', 'Oud']),
];
const titles = (list) => list.map((e) => e.title);

test('Alle: alles behalve de prullenbak, gesorteerd op titel', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups)), ['ArchPortal', 'FODMAP backend', 'Root-entry', 'Staff Café']);
});

test('groep toont ook subgroepen', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'A' })), ['ArchPortal', 'FODMAP backend']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'A1' })), ['FODMAP backend']);
});

test('prullenbak alleen als je hem kiest (ook subgroep)', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'B' })), ['Heel oud', 'Weggegooid']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'B1' })), ['Heel oud']);
});

test('zoeken: hoofdletters en accenten tellen niet, alle woorden moeten voorkomen', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'cafe' })), ['Staff Café']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'STAFF  café' })), ['Staff Café']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'staff fodmap' })), []);
});

test('zoeken in gebruikersnaam, URL, notities en categorienaam', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'admin' })), ['FODMAP backend']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'icthorsecloud' })), ['ArchPortal']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'staffcloud' })), ['Staff Café']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'eigen apps' })), ['ArchPortal', 'FODMAP backend']);
});

test('nooit zoeken in wachtwoorden', () => {
  assert.deepEqual(VI.filterEntries(entries, groups, { query: 'niet-zoekbaar' }), []);
});

test('zoeken standaard in de hele kluis, met vinkje alleen in de groep', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'W', query: 'fodmap' })), ['FODMAP backend']);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'W', query: 'fodmap', inGroupOnly: true })), []);
});

test('zoeken buiten de prullenbak, tenzij die gekozen is', () => {
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { query: 'heel' })), []);
  assert.deepEqual(titles(VI.filterEntries(entries, groups, { groupUuid: 'B', query: 'heel', inGroupOnly: true })), ['Heel oud']);
});

test('tellingen inclusief subgroepen, totaal zonder prullenbak', () => {
  const { total, counts } = VI.countEntries(entries);
  assert.equal(total, 4);
  assert.equal(counts.get('A'), 2);
  assert.equal(counts.get('A1'), 1);
  assert.equal(counts.get('B'), 2);
});

test('pathLabel en flatten', () => {
  assert.equal(VI.pathLabel(['5 Eigen apps & diensten', 'FODMAP']), '5 Eigen apps & diensten › FODMAP');
  assert.equal(VI.pathLabel([]), '');
  assert.deepEqual(VI.flatten(groups).map((g) => [g.uuid, g.depth]), [['A', 0], ['A1', 1], ['W', 0], ['B', 0], ['B1', 1]]);
});
