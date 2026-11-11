import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { checkProject, contrast } from '../scripts/brand-check.mjs';

const ROOT = process.cwd();
const made = [];
function project({ add = {}, edit = {}, remove = [] } = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'brand-'));
  made.push(dir);
  for (const item of ['src', 'public', 'brand', 'package.json', 'tailwind.config.js', 'index.html']) cpSync(path.join(ROOT, item), path.join(dir, item), { recursive: true });
  for (const [file, change] of Object.entries(edit)) writeFileSync(path.join(dir, file), change(readFileSync(path.join(dir, file), 'utf8')));
  for (const [file, content] of Object.entries(add)) {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), content);
  }
  for (const file of remove) rmSync(path.join(dir, file));
  return dir;
}
const rulesOf = (options) => [...new Set(checkProject(project(options)).map((p) => p.rule))];
const component = (body, name = 'Bad.jsx') => ({ add: { [`src/components/ui/${name}`]: `export default function Bad() {\n  return ${body};\n}\n` } });
afterAll(() => made.forEach((dir) => rmSync(dir, { recursive: true, force: true })));

describe('the brand check', () => {
  it('passes on the real project', () => {
    expect(checkProject(ROOT)).toEqual([]);
  });

  it.each([
    ['a hex colour', component('<p style={{ color: "#FF0000" }} />'), 'colour'],
    ['a raw colour function', component('<p className="x" data-c="rgb(1, 2, 3)" />'), 'colour'],
    ['a default Tailwind colour', component('<p className="bg-red-500" />'), 'palette'],
    ['white text', component('<p className="text-white" />'), 'palette'],
    ['pure black', component('<p className="bg-black" />'), 'palette'],
    ['a px size', component('<p className="w-[13px]" />'), 'px'],
    ['a px utility', component('<p className="translate-y-px" />'), 'px'],
    ['a Tailwind radius', component('<p className="rounded-lg" />'), 'radius'],
    ['a plain rounded', component('<p className="rounded" />'), 'radius'],
    ['an arbitrary radius', component('<p className="rounded-[0.5rem]" />'), 'radius'],
    ['a CSS radius', { edit: { 'src/index.css': (t) => `${t}\n.x { border-radius: 12px; }` } }, 'radius'],
    ['a gradient', component('<p className="bg-gradient-to-r" />'), 'gradient'],
    ['a radial gradient without a reason', { edit: { 'src/index.css': (t) => `${t}\n.x { background: radial-gradient(red, blue); }` } }, 'gradient'],
    ['an emoji', component('<p>Done ✅</p>'), 'emoji'],
    ['100vh', component('<p className="min-h-screen" />'), 'viewport'],
    ['a raw timing', component('<p data-t="300ms" />'), 'motion'],
    ['a raw easing', component('<p data-e="cubic-bezier(0, 0, 1, 1)" />'), 'motion'],
    ['an inline style', component('<p style={{ margin: 0 }} />'), 'inline-style'],
    ['the favicon in the page', component('<img src="favicon.ico" />'), 'logo'],
    ['a changed root font size', { edit: { 'src/index.css': (t) => t.replace('html { font-size: 100%; }', 'html { font-size: 14px; }') } }, 'root-size'],
    ['a dark block outside the allowed files', component('<p className="bg-ink text-cream" />'), 'dark'],
    ['a navy block outside the AI avatar', component('<p className="bg-navy" />'), 'dark'],
    ['a second icon library', { add: { 'src/components/ui/Bad.jsx': "import { Foo } from 'react-icons/fa';\nexport default Foo;\n" } }, 'icons'],
    ['secondary ink on a pastel', component('<p className="bg-pastel-gold text-ink-soft" />'), 'contrast'],
    ['an edited token file', { edit: { 'src/tokens.css': (t) => `${t}\n/* tweaked */` } }, 'brand-file'],
    ['an edited logo', { edit: { 'src/assets/logo/flwn-wordmark-navy.svg': (t) => t.replace('<svg', '<svg data-x="1"') } }, 'brand-file'],
    ['a missing favicon', { remove: ['public/favicon.ico'] }, 'brand-file'],
    ['a colour in Tailwind that tokens.css does not have', { edit: { 'tailwind.config.js': (t) => t.replace("cream: '#F7F3EA'", "cream: '#F7F3EB'") } }, 'palette'],
    ['a token colour missing from Tailwind', { edit: { 'tailwind.config.js': (t) => t.replace("navy: '#001F55',", '') } }, 'palette'],
  ])('catches %s', (_name, options, rule) => {
    expect(rulesOf(options)).toContain(rule);
  });

  it('catches an icon library in package.json', () => {
    const rules = rulesOf({ edit: { 'package.json': (t) => t.replace('"dependencies": {', '"dependencies": {\n    "@heroicons/react": "^2.0.0",') } });
    expect(rules).toContain('icons');
  });

  it('allows the things the rules allow: hairlines, overlays, tokens, the allowed dark files, and a stated exception', () => {
    expect(rulesOf(component('<p className="border-[1.5px] bg-ink/40 rounded-flwn bg-pastel-gold text-ink-72 p-6 min-h-dvh duration-fast" />'))).toEqual([]);
    expect(rulesOf(component('<p className="bg-ink text-cream" />', 'Button.jsx'))).toEqual([]);
    expect(rulesOf(component('<p data-c="#FF0000" /> /* brand-ok: a test of the opt-out */'))).toEqual([]);
  });

  it('computes the contrast the skill promises', () => {
    expect(contrast('#14131A', '#F8DB99')).toBeCloseTo(13.7, 1);   // ink on gold
    expect(contrast('#14131A', '#F5B3AC')).toBeCloseTo(10.5, 1);   // ink on salmon
    expect(contrast('#001F55', '#F5B3AC')).toBeCloseTo(9.0, 0);    // navy on salmon
    expect(contrast('#6B6875', '#F7F3EA')).toBeCloseTo(4.9, 1);    // ink soft on cream
    expect(contrast('#6B6875', '#F5B3AC')).toBeLessThan(4);        // which is why ink soft is never used on a pastel
  });
});
