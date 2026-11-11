import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { initial, reducer } from '../src/api/useReview.js';
import { createDemoBackend } from '../src/api/demoBackend.js';
import ReviewPage from '../src/pages/review/ReviewPage.jsx';

const eligible = { key: 'a', status: 'found', fix: { eligible: true } };
const reportOnly = { key: 'b', status: 'found', fix: { eligible: false } };
const sent = { key: 'c', status: 'proposed', fix: { eligible: true } };
const proposal = (extra = {}) => ({ id: 'p1', path: 'src/x.js', findingKeys: ['c'], state: 'ready', ...extra });
const state = (extra = {}) => ({ ...initial, phase: 'ready', findings: [eligible, reportOnly, sent], scan: { decision: 'block' }, ...extra });

describe('the rules in the state machine itself, not only as the screen happens to show them', () => {
  it('only an open finding that can be corrected can be ticked, and ticking twice unticks', () => {
    expect(reducer(state(), { type: 'toggle', key: 'b' }).selected).toEqual([]);      // report-only
    expect(reducer(state(), { type: 'toggle', key: 'c' }).selected).toEqual([]);      // already sent for correction
    expect(reducer(state(), { type: 'toggle', key: 'nope' }).selected).toEqual([]);   // unknown
    const once = reducer(state(), { type: 'toggle', key: 'a' });
    expect(once.selected).toEqual(['a']);
    expect(reducer(once, { type: 'toggle', key: 'a' }).selected).toEqual([]);
  });

  it('a refused or stale apply is NOT shown as fixed, and the findings stay as they were', () => {
    const before = state({ proposals: [proposal({ state: 'applying' })] });
    const after = reducer(before, { type: 'apply/done', id: 'p1', result: { status: 'stale', message: 'gone' } });
    expect(after.proposals[0]).toMatchObject({ state: 'failed', result: { status: 'stale' } });
    expect(after.findings.find((f) => f.key === 'c').status).toBe('proposed');
    const ok = reducer(before, { type: 'apply/done', id: 'p1', result: { status: 'applied' } });
    expect(ok.proposals[0].state).toBe('applied');
    expect(ok.findings.find((f) => f.key === 'c').status).toBe('fixed');
    expect(ok.scannedSinceApply).toBe(false);
  });

  it('the ticks are cleared once corrections are prepared', () => {
    const after = reducer(state({ selected: ['a'] }), { type: 'propose/done', result: { proposals: [{ id: 'p9', findingKeys: ['a'], checks: [] }], notCorrected: [] } });
    expect(after.selected).toEqual([]);
    expect(after.findings.find((f) => f.key === 'a').status).toBe('proposed');
  });

  it('a new scan drops corrections nobody answered (they are about an old scan) and keeps the ones already applied', () => {
    const before = state({ proposals: [proposal({ id: 'waiting' }), proposal({ id: 'done', state: 'applied' })] });
    const after = reducer(before, { type: 'scan/done', scan: { findings: [], decision: 'pass' } });
    expect(after.proposals.map((p) => p.id)).toEqual(['done']);
    expect(after.scannedSinceApply).toBe(true);
  });

  it('opening a correction clears the passing messages, so nothing sits over its buttons', () => {
    const after = reducer(state({ toasts: [{ id: 1 }, { id: 2 }] }), { type: 'open', id: 'p1' });
    expect(after.toasts).toEqual([]);
    expect(after.openId).toBe('p1');
  });
});

function setup() {
  const backend = createDemoBackend({ latency: 0 });
  const apply = vi.spyOn(backend, 'apply');
  const user = userEvent.setup();
  render(<ReviewPage backend={backend} />);
  return { backend, apply, user };
}
const column = (name) => screen.getByRole('region', { name });
const getToTheDrawer = async (user) => {
  await user.click(screen.getByRole('button', { name: 'Scan project' }));
  await within(column('Found')).findAllByRole('article');
  for (const box of within(column('Found')).getAllByRole('checkbox')) await user.click(box);
  await user.click(screen.getByRole('button', { name: 'Prepare corrections (2)' }));
  await within(column('Needs your decision')).findAllByRole('article');
};
const settle = (ms = 350) => act(() => new Promise((resolve) => setTimeout(resolve, ms)));   // longer than the drawer's fade-out

describe('what the screen does about them', () => {
  it('once corrections are prepared the dark action goes back to Scan again: nothing is still ticked', async () => {
    const { user } = setup();
    await getToTheDrawer(user);
    expect(screen.queryByRole('button', { name: /Prepare corrections/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeInTheDocument();
  });

  it('scanning again while corrections wait removes them: they belonged to the old scan', async () => {
    const { user } = setup();
    await getToTheDrawer(user);
    await user.click(screen.getByRole('button', { name: 'Scan again' }));
    await waitFor(() => expect(within(column('Needs your decision')).queryAllByRole('article')).toHaveLength(0));
    expect(within(column('Found')).getAllByRole('article')).toHaveLength(5);
  });

  it('the drawer stays open, for real, while a correction is being applied: not even Escape or a click outside closes it', async () => {
    const { backend, user } = setup();
    const real = backend.apply.bind(backend);
    let release;
    backend.apply = (id) => new Promise((resolve) => { release = async () => resolve(await real(id)); });
    await getToTheDrawer(user);
    await user.click(within(column('Needs your decision')).getAllByRole('button', { name: 'Review correction' })[0]);
    const dialog = await screen.findByRole('dialog', { name: /^Fix src\// });
    await user.click(within(dialog).getByRole('button', { name: 'Apply correction' }));
    await user.keyboard('{Escape}');
    await user.click(dialog.previousElementSibling);          // the scrim behind the panel
    await settle();                                            // long enough for any fade-out to have finished
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await act(async () => release());
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('when nothing is being applied, a click on the scrim does close it, and nothing is applied', async () => {
    const { user, apply } = setup();
    await getToTheDrawer(user);
    await user.click(within(column('Needs your decision')).getAllByRole('button', { name: 'Review correction' })[0]);
    const dialog = await screen.findByRole('dialog', { name: /^Fix src\// });
    await user.click(dialog.previousElementSibling);
    await settle();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(apply).not.toHaveBeenCalled();
  });

  it('a toast that is up when a correction opens is gone, so it cannot cover the Apply button', async () => {
    const { user } = setup();
    await getToTheDrawer(user);
    expect(await screen.findByText(/corrections are ready for your decision/)).toBeInTheDocument();
    await user.click(within(column('Needs your decision')).getAllByRole('button', { name: 'Review correction' })[0]);
    await screen.findByRole('dialog', { name: /^Fix src\// });
    expect(screen.queryByText(/corrections are ready for your decision/)).not.toBeInTheDocument();
  });
});
