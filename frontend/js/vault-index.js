/* HorseSafe kluis-index v0.3.5-Miller — categorieën en zoeken (UI_DESIGN S7, docs/screens/S07_vault.md)
 *
 * Pure functies over de uitvoer van HorseSafeCrypto.listEntries/listGroups; geen DOM, geen netwerk.
 * Zoeken gebeurt alleen in deze tab, over titel, gebruikersnaam, URL, notities en categorienaam —
 * nooit over wachtwoorden of andere beveiligde velden.
 */
(function () {
  'use strict';

  const ALL = 'all';

  /** Kleine letters, zonder accenten (é → e), witruimte samengevoegd. */
  function normalize(s) {
    return String(s || '')
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
  }

  /** Zoekwoorden uit de invoer; leeg = geen zoekopdracht. */
  function terms(query) {
    const q = normalize(query);
    return q ? q.split(' ') : [];
  }

  function haystack(e) {
    return normalize([e.title, e.username, e.url, e.notes, (e.groupPath || []).join(' ')].join('\n'));
  }

  function inGroup(e, groupUuid) {
    return (e.groupChain || []).includes(groupUuid);
  }

  /** Is groupUuid (of een voorouder) de prullenbak? */
  function isBinGroup(groups, groupUuid) {
    const n = findNode(groups, groupUuid);
    return !!(n && n.isRecycleBin);
  }

  function findNode(groups, groupUuid) {
    for (const g of groups || []) {
      if (g.uuid === groupUuid) return g;
      const hit = findNode(g.children, groupUuid);
      if (hit) return hit;
    }
    return null;
  }

  /**
   * Welke entries tonen.
   *   groupUuid   'all' of een groep-uuid (de groep inclusief subgroepen)
   *   query       zoektekst; alle woorden moeten voorkomen
   *   inGroupOnly bij zoeken: alleen binnen de gekozen groep (anders de hele kluis)
   * De prullenbak telt alleen mee als je hem zelf kiest.
   */
  function filterEntries(entries, groups, { groupUuid = ALL, query = '', inGroupOnly = false } = {}) {
    const words = terms(query);
    const binChosen = groupUuid !== ALL && isBinGroup(groups, groupUuid);
    const scopeGroup = words.length && !inGroupOnly ? ALL : groupUuid;
    const out = entries.filter((e) => {
      if (scopeGroup === ALL) {
        if (e.inRecycleBin && !binChosen) return false;
      } else if (!inGroup(e, scopeGroup)) {
        return false;
      }
      if (!words.length) return true;
      const h = haystack(e);
      return words.every((w) => h.includes(w));
    });
    return out.sort((a, b) => String(a.title).localeCompare(String(b.title), 'nl', { sensitivity: 'base' }));
  }

  /**
   * Aantallen per groep (inclusief subgroepen) en het totaal zonder prullenbak.
   * Geeft {total, counts: Map<uuid, n>}.
   */
  function countEntries(entries) {
    const counts = new Map();
    let total = 0;
    for (const e of entries) {
      if (!e.inRecycleBin) total++;
      for (const g of e.groupChain || []) counts.set(g, (counts.get(g) || 0) + 1);
    }
    return { total, counts };
  }

  /** Naam van een categorie voor weergave ("5 Eigen apps & diensten › FODMAP"); '' = hoofdmap. */
  function pathLabel(path) {
    return (path || []).join(' › ');
  }

  /** Platte lijst voor de keuzelijst op smalle schermen: [{uuid, label, depth, isRecycleBin}]. */
  function flatten(groups, depth = 0, out = []) {
    for (const g of groups || []) {
      out.push({ uuid: g.uuid, label: g.name, path: g.path, depth, isRecycleBin: g.isRecycleBin });
      flatten(g.children, depth + 1, out);
    }
    return out;
  }

  const api = { ALL, normalize, terms, filterEntries, countEntries, pathLabel, flatten, findNode };
  if (typeof window !== 'undefined') window.HorseSafeVaultIndex = api;
  if (typeof globalThis !== 'undefined') globalThis.HorseSafeVaultIndex = api;
})();
