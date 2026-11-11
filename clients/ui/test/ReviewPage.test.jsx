import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import { createDemoBackend } from '../src/api/demoBackend.js';
import ReviewPage from '../src/pages/review/ReviewPage.jsx';

function setup() {
  const backend = createDemoBackend({ latency: 0 });
  const apply = vi.spyOn(backend, 'apply');
  const user = userEvent.setup();
  render(<ReviewPage backend={backend} />);
  return { backend, apply, user };
}
const column = (name) => screen.getByRole('region', { name });
const scan = async (user) => {
  await user.click(screen.getByRole('button', { name: 'Scan project' }));
  await within(column('Found')).findAllByRole('article');
};
const tickAll = async (user) => {
  for (const box of within(column('Found')).getAllByRole('checkbox')) await user.click(box);
};
const prepare = async (user, count = 2) => {
  await user.click(screen.getByRole('button', { name: `Prepare corrections (${count})` }));
  await within(column('Needs your decision')).findAllByRole('article');
};
const openFirst = async (user) => {
  await user.click(within(column('Needs your decision')).getAllByRole('button', { name: 'Review correction' })[0]);
  return screen.findByRole('dialog', { name: /^Fix src\// });
};
const summary = () => screen.getAllByText(/^(Ready when|The last scan|Something stopped)/)[0].textContent;

describe('the review screen', () => {
  it('starts empty and plain: the headline, three columns, one dark action, the wordmark, and a label saying this is demo data', async () => {
    setup();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('What Phylax found.');
    for (const name of ['Found', 'Needs your decision', 'Fixed']) expect(column(name)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'flwn' })).toBeInTheDocument();
    expect(screen.getByText(/never changes a file until you approve that correction/)).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Demo data' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scan project' })).toBeEnabled();
    expect(within(column('Found')).getByText(/Nothing yet\. Scan the project/)).toBeInTheDocument();
    expect(summary()).toBe('Ready when you are. Scan the sample project.');
  });

  it('while scanning it shows the thinking indicator and the shape of what is coming, then the findings, most serious first', async () => {
    const { backend, user } = setup();
    const real = backend.scan.bind(backend);
    let release;
    backend.scan = () => new Promise((resolve) => { release = async () => resolve(await real()); });
    await user.click(screen.getByRole('button', { name: 'Scan project' }));
    expect(screen.getByRole('button', { name: 'Scan project' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByRole('button', { name: 'Scan project' })).toBeDisabled();
    expect(await screen.findByText('Reading the files')).toBeInTheDocument();
    expect(within(column('Found')).queryAllByRole('article')).toHaveLength(0);
    expect(column('Found').querySelectorAll('[aria-hidden="true"].anim-skeleton').length).toBeGreaterThanOrEqual(3);
    await act(async () => release());
    const cards = await within(column('Found')).findAllByRole('article');
    expect(cards).toHaveLength(5);
    expect(cards.map((c) => within(c).getByRole('heading', { level: 3 }).textContent.slice(0, 22))).toEqual(['A value in the format ', 'A shell command from c', 'A value that looks lik', 'A SQL statement is bui', 'Math.random() is predi']);
    expect(summary()).toBe('The last scan blocked this review. 2 corrections can be requested. 3 findings are reported only.');
    expect(screen.queryByText('Reading the files')).not.toBeInTheDocument();
  });

  it('only findings that can be corrected have a checkbox; the others say why, in the service\'s words', async () => {
    const { user } = setup();
    await scan(user);
    const boxes = within(column('Found')).getAllByRole('checkbox');
    expect(boxes).toHaveLength(2);
    expect(boxes.map((b) => b.getAttribute('aria-label'))).toEqual([expect.stringMatching(/command injection in src\/run\.js:5/), expect.stringMatching(/sql injection in src\/db\.ts:4/)]);
    expect(within(column('Found')).getAllByRole('img', { name: /Reported only/ })).toHaveLength(3);
    expect(within(column('Found')).getAllByText(/hardcoded secret is not fixed automatically/i)).toHaveLength(2);   // the AWS key in code and the SMTP password in a configuration file
    expect(within(column('Found')).getByText(/Low and informational findings are reported, not corrected by default/)).toBeInTheDocument();
    expect(within(column('Found')).queryByText(/AKIA/)).not.toBeInTheDocument();   // the secret itself never appears
  });

  it('ticking findings turns the one dark action into "Prepare corrections (n)", and unticking turns it back', async () => {
    const { user } = setup();
    await scan(user);
    const [first, second] = within(column('Found')).getAllByRole('checkbox');
    await user.click(first);
    expect(screen.getByRole('button', { name: 'Prepare corrections (1)' })).toBeInTheDocument();
    await user.click(second);
    expect(screen.getByRole('button', { name: 'Prepare corrections (2)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeInTheDocument();
    await user.click(first);
    await user.click(second);
    expect(screen.queryByRole('button', { name: /Prepare corrections/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeInTheDocument();
  });

  it('preparing corrections moves them to "Needs your decision", and applies NOTHING', async () => {
    const { user, apply } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);
    expect(within(column('Needs your decision')).getAllByRole('article')).toHaveLength(2);
    expect(within(column('Found')).getAllByRole('article')).toHaveLength(3);
    expect(within(column('Fixed')).queryAllByRole('article')).toHaveLength(0);
    expect(apply).not.toHaveBeenCalled();
  });

  it('closing the drawer by any route, or pressing "Not now", never applies anything', async () => {
    const { user, apply } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);

    let dialog = await openFirst(user);
    expect(apply).not.toHaveBeenCalled();
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    dialog = await openFirst(user);
    await user.click(within(dialog).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(within(column('Needs your decision')).getAllByRole('article')).toHaveLength(2);   // closing leaves the correction waiting

    dialog = await openFirst(user);
    await user.click(within(dialog).getByRole('button', { name: 'Not now' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(within(column('Needs your decision')).getAllByRole('article')).toHaveLength(1);   // "Not now" sends it back
    expect(within(column('Found')).getAllByRole('article')).toHaveLength(4);
    expect(within(column('Fixed')).queryAllByRole('article')).toHaveLength(0);
    expect(apply).not.toHaveBeenCalled();
  });

  it('the drawer shows what was checked and the exact change before anyone decides', async () => {
    const { user } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);
    const dialog = await openFirst(user);
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(within(dialog).getByRole('heading', { level: 2, name: 'Fix src/run.js.' })).toBeInTheDocument();
    const checked = within(dialog).getByRole('list', { name: 'What Phylax checked' });
    expect(within(checked).getAllByRole('listitem')).toHaveLength(4);
    expect(within(checked).getAllByText(/Passed\./)).toHaveLength(4);
    const change = within(dialog).getByRole('group', { name: 'Changes to src/run.js' });
    expect(change).toHaveTextContent('execFile("ls", [dir]);');
    expect(within(change).getAllByText('Removed:').length).toBeGreaterThan(0);
    expect(within(change).getAllByText('Added:').length).toBeGreaterThan(0);
    expect(within(dialog).getByText(/Phylax never changes a file by itself\. Nothing is applied until you press Apply correction\./)).toBeInTheDocument();
    expect(dialog).toHaveFocus();
  });

  it('Apply correction applies exactly that correction, moves it to Fixed with its verification, and says so', async () => {
    const { user, apply } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);
    const dialog = await openFirst(user);
    await user.click(within(dialog).getByRole('button', { name: 'Apply correction' }));
    const fixed = await within(column('Fixed')).findAllByRole('article');
    expect(fixed).toHaveLength(1);
    expect(apply).toHaveBeenCalledTimes(1);
    expect(fixed[0]).toHaveTextContent('src/run.js');
    expect(fixed[0]).toHaveTextContent('Command injection resolved.');
    expect(fixed[0]).toHaveTextContent('Verification passed on the file as it is now.');
    expect(within(column('Needs your decision')).getAllByRole('article')).toHaveLength(1);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await screen.findByText(/Applied the correction to src\/run\.js\. Verification passed\./)).toBeInTheDocument();
    expect(summary()).toMatch(/1 correction applied\. Scan again to confirm\./);
  });

  it('while a correction is being applied the drawer cannot be dismissed, and then it is done', async () => {
    const { backend, user } = setup();
    const real = backend.apply.bind(backend);
    let release;
    backend.apply = (id) => new Promise((resolve) => { release = async () => resolve(await real(id)); });
    await scan(user);
    await tickAll(user);
    await prepare(user);
    const dialog = await openFirst(user);
    await user.click(within(dialog).getByRole('button', { name: 'Apply correction' }));
    expect(within(dialog).getByRole('button', { name: 'Apply correction' })).toHaveAttribute('aria-busy', 'true');
    expect(within(dialog).getByRole('button', { name: 'Close' })).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Not now' })).toBeDisabled();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await act(async () => release());
    await within(column('Fixed')).findAllByRole('article');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('applying both, then scanning again, ends with only the findings that are reported and the corrections confirmed', async () => {
    const { user } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);
    for (let i = 1; i <= 2; i += 1) {
      const dialog = await openFirst(user);
      await user.click(within(dialog).getByRole('button', { name: 'Apply correction' }));
      await waitFor(() => expect(within(column('Fixed')).getAllByRole('article')).toHaveLength(i));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    }
    await user.click(screen.getByRole('button', { name: 'Scan again' }));
    await waitFor(() => expect(summary()).toMatch(/applied and confirmed by that scan/));
    expect(summary()).toBe('The last scan found things that need a person. 2 corrections applied and confirmed by that scan. 3 findings are reported only.');
    expect(within(column('Found')).getAllByRole('article')).toHaveLength(3);
    expect(within(column('Found')).queryAllByRole('checkbox')).toHaveLength(0);
    expect(within(column('Fixed')).getAllByRole('article')).toHaveLength(2);
  });

  it('an error is shown in words, says nothing was changed, and Try again repeats the same thing', async () => {
    const { user } = setup();
    await user.click(await screen.findByRole('button', { name: 'Demo data' }));
    await user.click(screen.getByRole('button', { name: 'Show an error' }));
    await user.click(screen.getByRole('button', { name: 'Scan project' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not reach Phylax. Check the address and that the service is running. Nothing was changed.');
    expect(summary()).toBe('Something stopped the review. Nothing was changed.');
    await user.click(within(alert).getByRole('button', { name: 'Try again' }));
    await within(column('Found')).findAllByRole('article');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('a failed request for corrections keeps the board and the ticks\' findings, and can be retried', async () => {
    const { backend, user } = setup();
    await scan(user);
    await tickAll(user);
    backend.failNext();
    await user.click(screen.getByRole('button', { name: 'Prepare corrections (2)' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Nothing was changed.');
    expect(within(column('Found')).getAllByRole('article')).toHaveLength(5);
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await within(column('Needs your decision')).findAllByRole('article');
    expect(within(column('Found')).getAllByRole('article')).toHaveLength(3);
  });

  it('starting over puts the sample back, and the project switcher is honest that the demo has one project', async () => {
    const { user } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);
    await user.click(screen.getByRole('button', { name: 'Demo data' }));
    await user.click(screen.getByRole('button', { name: 'Start over' }));
    await waitFor(() => expect(within(column('Found')).getByText(/Nothing yet/)).toBeInTheDocument());
    expect(within(column('Needs your decision')).queryAllByRole('article')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: /sample-app/ }));
    expect(await screen.findByRole('dialog', { name: 'Projects' })).toHaveTextContent('The demo has one project');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Projects' })).not.toBeInTheDocument());
  });

  it('the coverage panel opens and closes, and says what was and was not checked', async () => {
    const { user } = setup();
    await scan(user);
    const toggle = screen.getByRole('button', { name: /^Coverage 6 files scanned/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    const panel = document.getElementById('coverage-body');
    expect(panel).toHaveTextContent('src/config.js');
    expect(panel).toHaveTextContent('config/mail.yaml');
    expect(panel).toHaveTextContent('Checked for secrets only');
    expect(panel).toHaveTextContent('configuration and text files are checked for hardcoded secrets and nothing else');
    expect(panel).toHaveTextContent('Every file that was sent was scanned.');
    expect(panel).toHaveTextContent('jsrules, secrets. None failed.');
    expect(panel).toHaveTextContent('authentication and authorization logic');
  });

  it('keeps Tab inside the open drawer', async () => {
    const { user } = setup();
    await scan(user);
    await tickAll(user);
    await prepare(user);
    const dialog = await openFirst(user);
    const apply = within(dialog).getByRole('button', { name: 'Apply correction' });
    apply.focus();
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Close' }));
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(apply);
  });

  it('gives the screen reader a live summary of the review\'s state', async () => {
    const { user } = setup();
    await scan(user);
    expect(screen.getAllByRole('status').some((el) => /The last scan blocked this review/.test(el.textContent))).toBe(true);
  });
});

describe('the styles', () => {
  const css = readFileSync(path.resolve(process.cwd(), 'src/index.css'), 'utf8');
  it('respect reduced motion: no movement, scaling or pulsing, and the loaders stay', () => {
    expect(css).toMatch(/@media \(prefers-reduced-motion: reduce\)/);
    const block = css.slice(css.indexOf('@media (prefers-reduced-motion: reduce)'));
    expect(block).toMatch(/\.anim-pulse-ring, \.anim-dot, \.anim-shake \{ animation: none; \}/);
    expect(block).toMatch(/\.lift, \.press:active \{ transform: none !important; \}/);
    expect(block).not.toMatch(/anim-spin|anim-skeleton/);
  });

  it('use only the motion tokens for time and easing', () => {
    const definitions = css.slice(0, css.indexOf('@keyframes')).split('\n').filter((l) => /^\s*\.anim-(enter|exit|fade|slide-in|slide-out|scrim-in|scrim-out|toast-in) \{/.test(l));
    expect(definitions).toHaveLength(8);
    for (const rule of definitions) expect(rule).toMatch(/var\(--dur(-fast|-slow)?\)/);
    for (const rule of definitions) expect(rule).toMatch(/var\(--ease-(out|in)\)/);
  });
});
