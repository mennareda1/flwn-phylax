# Phylax UI

The security review as a Flwn board: **Found**, **Needs your decision**, **Fixed**. You scan, tick the findings you want corrected, look at each correction (what Phylax
checked and the exact diff), and apply it only by pressing **Apply correction**. Phylax never changes a file by itself.

This is built to the Flwn design rules (`SKILL.md`): cream dotted canvas, five pastels, the navy wordmark, rem everywhere, two radii, Lucide icons, motion on every state.

## Run it

```
npm install          once
npm run dev          the app, with live reload, on http://127.0.0.1:5173
npm run build        ONE file: dist/index.html (scripts, styles and fonts inside). Double-click it: it works offline, from any folder.
npm test             the tests
npm run lint         eslint and the brand check
npm run check        all of it
```

## The demo

The app opens in **demo mode**. Everything it shows was recorded from the real Phylax on a small vulnerable sample project (`scripts/sample-project.mjs`): the real scanner's
findings and reasons, the real corrections as diffs, the real checks and verifications. The correction model was played by the test stand-in. The recording is
`src/api/demo/recorded.json`; `npm run record-demo` makes it again (it starts the real service, so it needs Python with the Phylax packages and the TypeScript client built).
`python -m tests.check_ui` validates the recording against the OpenAPI contract and fails if it was made against another contract version.

The screen says so: a "Demo data" label explains it, and offers "Start over" and "Show an error" (to show the error state in a meeting). Applying a correction changes a
copy kept in the page, not any file on disk.

## Going live

Every screen gets its data from a backend object with five methods: `info()`, `scan()`, `propose(keys)`, `apply(id)`, `reset()` (and the demo's `failNext()`). The demo is
`src/api/demoBackend.js`. A live backend, talking to a small local server that uses the review client in `clients/typescript`, replaces that one file; no screen changes.
It is not built yet. The consent rule travels with it: `apply` is only ever called from the Apply correction button.

## What is checked

`scripts/brand-check.mjs` fails the build on a colour outside the palette, px outside hairlines, a third radius, a gradient, an emoji, a second icon library, a default Tailwind
colour, `100vh`, a raw timing, an inline style, a changed token or logo file, a Tailwind colour that differs from `tokens.css`, and contrast below the skill's numbers.
Its own tests break each rule on purpose. The component tests drive the screen the way a person would, including the consent rules.

## Not done

- The live backend (above), and a folder picker for your own projects.
- Dark mode: the brand does not define one, so there is none.
- The sample is JavaScript and TypeScript. Python and later languages work in the service; the demo does not show them.
