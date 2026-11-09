// Static checks on web/: the pages keep to the CSP (no inline script or style, no third-party
// scripts, styles or fonts) and the page scripts never write markup from strings.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const WEB = join(import.meta.dirname, '..', 'web');
const pages = readdirSync(WEB).filter((f) => f.endsWith('.html'));
const read = (p: string) => readFileSync(p, 'utf8');

describe('web pages', () => {
  test('the landing and the console both exist', () => {
    assert.ok(pages.includes('index.html'));
    assert.ok(pages.includes('console.html'));
  });

  for (const page of pages) {
    const html = read(join(WEB, page));
    test(`${page}: no inline scripts, styles or handlers`, () => {
      for (const m of html.matchAll(/<script\b([^>]*)>/gi)) assert.match(m[1]!, /\bsrc=/, `inline <script> in ${page}`);
      assert.doesNotMatch(html, /<style\b/i, `<style> in ${page}`);
      assert.doesNotMatch(html, /\sstyle\s*=/i, `style= in ${page}`);
      assert.doesNotMatch(html, /<[^>]+\son[a-z]+\s*=/i, `on*= handler in ${page}`);
    });
    test(`${page}: scripts, stylesheets and fonts are same-origin`, () => {
      for (const m of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/gi)) assert.doesNotMatch(m[1]!, /^(https?:)?\/\//i, m[1]);
      for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
        if (!/\brel="(stylesheet|preload|modulepreload|icon)"/i.test(m[0])) continue;
        const href = m[0].match(/\bhref="([^"]+)"/i)?.[1] ?? '';
        assert.doesNotMatch(href, /^(https?:)?\/\//i, href);
      }
    });
  }

  test('page scripts never write markup from strings', () => {
    const assets = join(WEB, 'assets');
    const files = (readdirSync(assets, { recursive: true }) as string[])
      .filter((f) => f.endsWith('.js'))
      .map((f) => join(assets, f));
    files.push(join(WEB, 'app.js'));
    const kit = join(assets, 'kit');
    let scanned = 0;
    for (const f of files) {
      if (!existsSync(f)) continue;
      scanned++;
      const src = read(f);
      if (!f.startsWith(kit)) {
        assert.doesNotMatch(src, /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML/, f);
        continue;
      }
      // the vendored kit (MIT, kept byte-identical) sets fixed icon markup only: no interpolation, no concatenation
      assert.doesNotMatch(src, /insertAdjacentHTML|\.outerHTML\s*=/, f);
      for (const m of src.matchAll(/\.innerHTML\s*=([^;]*);/g)) {
        assert.doesNotMatch(m[1]!, /\$\{|\+|`/, `${f}: ${m[0]}`);
      }
    }
    assert.ok(scanned > 5, 'scanned the page scripts, kit included');
  });

  test('self-hosted fonts ship with their licence', () => {
    const fonts = join(WEB, 'fonts');
    const woff = readdirSync(fonts).filter((f) => f.endsWith('.woff2'));
    assert.ok(woff.length > 0);
    assert.ok(existsSync(join(fonts, 'OFL.txt')));
  });

  test('the landing makes no claims the project cannot back', () => {
    const html = read(join(WEB, 'index.html'));
    assert.match(html, /Not audited/);
    assert.match(html, /Mainnet not deployed/);
    assert.doesNotMatch(html, /8 of 8 attacks|canary tokens/i);
  });
});
