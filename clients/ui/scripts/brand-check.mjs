// Fails the build when something breaks the Flwn design rules (SKILL.md): a colour outside the palette, px outside hairlines, a third radius, a gradient, an emoji, a second icon
// library, a default Tailwind colour, 100vh, a raw timing, a changed token file or logo, and dark elements outside the two allowed. A line can opt out with `brand-ok` and a reason.
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ICON_LIBRARIES = /^(react-icons|@heroicons\/|@fortawesome\/|@tabler\/|phosphor-react|@phosphor-icons\/|feather-icons|react-feather|@radix-ui\/react-icons|ionicons|bootstrap-icons|material-icons|@mui\/icons-material)/;
const TAILWIND_COLOURS = /\b(bg|text|border|ring|fill|stroke|from|to|via|outline|divide|placeholder|decoration|accent|caret|shadow)-(slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|black)(-\d{2,3})?\b/;
const RADIUS_OK = /^rounded(-(t|b|l|r|tl|tr|bl|br))?-(flwn|flwn-sm|full|none)$/;   // a size is required: a bare `rounded` is Tailwind's own 0.25rem, a third radius
const DARK_FILES = { 'bg-ink': ['Button.jsx', 'ThinkingIndicator.jsx', 'Toast.jsx', 'Checkbox.jsx'], 'bg-navy': ['AiAvatar.jsx'] };   // the primary button, the AI avatar, and small ink marks (dots, countdown line, ticked box)

const walk = (dir, out = []) => {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist') continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
};
const sha = (file) => createHash('sha256').update(readFileSync(file)).digest('hex').slice(0, 16);
const luminance = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
export const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

/** Returns a list of { file, line, rule, text } for everything that breaks the rules. An empty list is a pass. */
export function checkProject(root) {
  const found = [];
  const rel = (file) => path.relative(root, file).split(path.sep).join('/');
  const flag = (file, line, rule, text) => found.push({ file: rel(file), line, rule, text: String(text).trim().slice(0, 120) });

  const sources = walk(path.join(root, 'src')).filter((f) => /\.(jsx?|css)$/.test(f) && !f.endsWith('src/tokens.css'));
  if (existsSync(path.join(root, 'index.html'))) sources.push(path.join(root, 'index.html'));

  for (const file of sources) {
    const name = path.basename(file);
    const lines = readFileSync(file, 'utf8').split('\n');
    lines.forEach((text, index) => {
      const n = index + 1;
      const ok = text.includes('brand-ok') || (lines[index + 1] ?? '').includes('brand-ok:');
      if (/#[0-9a-fA-F]{3,8}\b/.test(text) && !ok && !/&#|href="#|\burl\(#/.test(text)) flag(file, n, 'colour', 'A hex colour: use a token (bg-pastel-gold, text-ink, var(--cream)).');
      if (/\b(rgb|rgba|hsl|hsla)\(/.test(text) && !ok) flag(file, n, 'colour', 'A raw colour function: use a token.');
      if (TAILWIND_COLOURS.test(text) && !ok) flag(file, n, 'palette', `A default Tailwind colour (${TAILWIND_COLOURS.exec(text)[0]}): only the Flwn palette is allowed.`);
      if (/\b(text-white|bg-black|text-black|border-black)\b/.test(text) && !ok) flag(file, n, 'palette', 'No white text, no pure black: ink on pastel.');
      for (const match of text.matchAll(/(?<![\w.-])(\d+(?:\.\d+)?)px\b/g)) {
        if (![1, 1.5, 2].includes(Number(match[1])) && !ok) flag(file, n, 'px', `${match[0]}: sizes are rem. Only hairlines (1, 1.5, 2px) may be px.`);
      }
      if (/(^|[\s"'`:])-?[a-z-]*-px\b/.test(text) && !ok) flag(file, n, 'px', 'A px utility: use rem (translate-y-[0.0625rem]).');
      const code = /^\s*(\/\*|\*|\/\/)/.test(text) ? '' : text.replace(/\/\*.*?\*\//g, '').replace(/\s\/\/.*$/, '');   // prose in comments may say "rounded"
      for (const match of code.matchAll(/\brounded[\w[\].-]*/g)) {
        if (!RADIUS_OK.test(match[0]) && !ok) flag(file, n, 'radius', `${match[0]}: only rounded-flwn, rounded-flwn-sm and rounded-full.`);
      }
      const borderRadius = /border-radius:\s*([^;]+);/.exec(text);
      if (borderRadius && !/^(var\(--r(-sm)?\)|50%|999px|0)$/.test(borderRadius[1].trim()) && !ok) flag(file, n, 'radius', `border-radius ${borderRadius[1]}: only --r, --r-sm, 50%, 999px.`);
      if (/gradient/.test(text) && !ok) flag(file, n, 'gradient', 'No gradients (the dotted grid carries brand-ok).');
      if (/\p{Extended_Pictographic}/u.test(text)) flag(file, n, 'emoji', 'No emoji: icons are Lucide.');
      if (/\b(100vh|min-h-screen|h-screen)\b/.test(text) && !ok) flag(file, n, 'viewport', 'Use dvh, not vh.');
      if (/\b\d+ms\b|cubic-bezier\(/.test(text) && !ok && name !== 'index.css') flag(file, n, 'motion', 'A raw timing: use the duration and easing tokens.');
      if (/style=\{\{/.test(text) && !ok) flag(file, n, 'inline-style', 'No inline style except computed values (mark them brand-ok).');
      if (/(favicon|apple-touch)/.test(text) && name.endsWith('.jsx')) flag(file, n, 'logo', 'The favicon belongs in the browser tab only, never in the page.');
      const rootSize = /\bhtml\s*\{[^}]*font-size:\s*([^;}]+)/.exec(text);
      if (rootSize && rootSize[1].trim() !== '100%') flag(file, n, 'root-size', `The root font size stays 100%, not ${rootSize[1].trim()}.`);
      for (const [dark, allowed] of Object.entries(DARK_FILES)) {
        if (new RegExp(`(?<![\\w-])${dark}(?![\\w/-])`).test(text) && name.endsWith('.jsx') && !allowed.includes(name)) flag(file, n, 'dark', `${dark} is only for ${allowed.join(', ')}: one dark anchor per view.`);
      }
      for (const match of text.matchAll(/from\s+'([^']+)'/g)) {
        if (ICON_LIBRARIES.test(match[1])) flag(file, n, 'icons', `${match[1]}: Lucide is the only icon library.`);
      }
      if (/text-ink-soft/.test(text) && /bg-pastel-/.test(text)) flag(file, n, 'contrast', 'text-ink-soft on a pastel fails contrast: use text-ink-72.');
    });
  }

  // package.json: one icon library
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const dep of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
    if (ICON_LIBRARIES.test(dep)) flag(path.join(root, 'package.json'), 1, 'icons', `${dep}: Lucide is the only icon library.`);
  }

  // the token file and the logo files are the owner's: they must be exactly as delivered
  const sums = readFileSync(path.join(root, 'brand', 'brand-files.sha'), 'utf8').trim().split('\n').map((l) => l.trim().split(/\s+/));
  const locations = { 'tokens.css': 'src/tokens.css', 'flwn-wordmark-navy.svg': 'src/assets/logo/flwn-wordmark-navy.svg', 'flwn-favicon-gold.svg': 'public/flwn-favicon-gold.svg', 'favicon.ico': 'public/favicon.ico', 'apple-touch-icon-180.png': 'public/apple-touch-icon-180.png' };
  for (const [file, hash] of sums) {
    const where = path.join(root, locations[file]);
    if (!existsSync(where)) flag(where, 1, 'brand-file', `${file} is missing.`);
    else if (sha(where) !== hash) flag(where, 1, 'brand-file', `${file} was changed. Brand files are used as delivered, never edited.`);
  }

  // Tailwind carries the same colours as tokens.css
  const tokens = readFileSync(path.join(root, 'src', 'tokens.css'), 'utf8');
  const tokenHex = new Set([...tokens.matchAll(/#[0-9A-Fa-f]{6}\b/g)].map((m) => m[0].toUpperCase()));
  const config = readFileSync(path.join(root, 'tailwind.config.js'), 'utf8');
  for (const hex of new Set([...config.matchAll(/#[0-9A-Fa-f]{6}\b/g)].map((m) => m[0].toUpperCase()))) {
    if (!tokenHex.has(hex)) flag(path.join(root, 'tailwind.config.js'), 1, 'palette', `${hex} is not in tokens.css.`);
  }
  for (const hex of tokenHex) {
    if (!config.toUpperCase().includes(hex)) flag(path.join(root, 'tailwind.config.js'), 1, 'palette', `${hex} is in tokens.css but not in the Tailwind colours.`);
  }
  if (!config.includes('rgba(20, 19, 26, 0.72)') || !/--ink-72:\s*rgba\(20, 19, 26, \.72\)/.test(tokens)) flag(path.join(root, 'tailwind.config.js'), 1, 'palette', '--ink-72 differs between tokens.css and Tailwind.');

  // contrast the skill promises, from the real colours
  const colour = (name) => new RegExp(`--${name}:\\s*(#[0-9A-Fa-f]{6})`).exec(tokens)?.[1];
  for (const pastel of ['pastel-green', 'pastel-lavender', 'pastel-gold', 'pastel-salmon', 'pastel-blue']) {
    if (contrast(colour('ink'), colour(pastel)) < 10) flag(path.join(root, 'src/tokens.css'), 1, 'contrast', `ink on ${pastel} is below 10:1.`);
    if (contrast(colour('navy'), colour(pastel)) < 8.9) flag(path.join(root, 'src/tokens.css'), 1, 'contrast', `navy on ${pastel} is below the 9:1 the skill promises.`);   // 8.97 on salmon, which the skill rounds to 9.0
  }
  if (contrast(colour('ink-soft'), colour('cream')) < 4.5) flag(path.join(root, 'src/tokens.css'), 1, 'contrast', 'ink-soft on cream is below 4.5:1.');
  return found;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const problems = checkProject(root);
  if (problems.length === 0) {
    console.log('brand check OK: palette, radii, rem, motion tokens, icons, logo and token files all follow the Flwn design rules');
  } else {
    for (const p of problems) console.error(`${p.file}:${p.line}  [${p.rule}]  ${p.text}`);
    console.error(`\nbrand check FAILED: ${problems.length} problem(s)`);
    process.exit(1);
  }
}
