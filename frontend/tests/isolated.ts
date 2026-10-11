import { test as base, expect } from '@playwright/test';
import { startStack, type Stack } from './e2e-stack';

/**
 * v0.2.1-Koblitz — fixture voor de oudere specs (admin, mfa, smoke): elke worker krijgt een eigen
 * backend (tijdelijke DB, vrije poort) via e2e-stack.ts; de pagina's praten daarmee via
 * localStorage 'horsesafe.devApiPort'. De frontend blijft op http://localhost:8000 (playwright-webServer).
 *
 * Vangnet: elk verzoek naar poort 3997 (= LIVE productie-backend op HC55) wordt afgebroken en laat de
 * test falen, zodat een e2e-run nooit tegen productie schrijft.
 */
const WEB_ORIGIN = 'http://localhost:8000';

export const test = base.extend<{ prodGuard: void }, { stack: Stack }>({
  stack: [
    async ({}, use) => {
      const s = await startStack('hs-e2e-', () => ({
        HORSESAFE_CORS_ORIGINS: WEB_ORIGIN,
        HORSESAFE_PUBLIC_URL: WEB_ORIGIN,
      }));
      await use(s);
      s.stop();
    },
    { scope: 'worker' },
  ],
  context: async ({ context, stack }, use) => {
    await context.addInitScript((port) => {
      localStorage.setItem('horsesafe.devApiPort', String(port));
    }, stack.apiPort);
    await use(context);
  },
  prodGuard: [
    async ({ context }, use) => {
      const hits: string[] = [];
      await context.route(/^https?:\/\/(localhost|127\.0\.0\.1):3997\//, (route) => {
        hits.push(route.request().url());
        return route.abort();
      });
      await use();
      expect(hits, 'e2e mag nooit de productie-backend op :3997 raken').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
