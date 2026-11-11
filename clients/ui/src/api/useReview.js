import { useCallback, useEffect, useReducer, useRef, useState } from 'react';

import { bySeverity } from '../lib/severity.js';

export const SCAN_LINES = ['Reading the files', 'Running the checks', 'Writing the report'];
export const PROPOSE_LINES = ['Asking for corrections', 'Checking each correction', 'Preparing the diffs'];

export const initial = { phase: 'idle', error: null, scan: null, scannedSinceApply: false, findings: [], selected: [], proposals: [], notes: [], openId: null, toasts: [] };

const patchProposal = (proposals, id, change) => proposals.map((p) => (p.id === id ? { ...p, ...change } : p));
const patchFindings = (findings, keys, status) => findings.map((f) => (keys.includes(f.key) ? { ...f, status } : f));

export function reducer(state, action) {
  switch (action.type) {
    case 'scan/start':
      return { ...state, phase: 'scanning', error: null };
    case 'scan/done':
      return {
        ...state,
        phase: 'ready',
        error: null,
        scan: action.scan,
        scannedSinceApply: true,
        findings: [...action.scan.findings].sort(bySeverity).map((f) => ({ ...f, status: 'found' })),
        selected: [],
        notes: [],
        proposals: state.proposals.filter((p) => p.state === 'applied'),   // corrections already applied stay on the board; unanswered ones are stale after a new scan
        openId: null,
      };
    case 'propose/start':
      return { ...state, phase: 'proposing', error: null };
    case 'propose/done': {
      const keys = action.result.proposals.flatMap((p) => p.findingKeys);
      return {
        ...state,
        phase: 'ready',
        findings: patchFindings(state.findings, keys, 'proposed'),
        selected: [],
        notes: action.result.notCorrected,
        proposals: [...state.proposals, ...action.result.proposals.map((p) => ({ ...p, state: 'ready', result: null }))],
      };
    }
    case 'fail':
      return { ...state, phase: state.scan ? 'ready' : 'idle', error: action.message };
    case 'toggle': {
      const finding = state.findings.find((f) => f.key === action.key);
      if (!finding || finding.status !== 'found' || !finding.fix.eligible) return state;
      const selected = state.selected.includes(action.key) ? state.selected.filter((k) => k !== action.key) : [...state.selected, action.key];
      return { ...state, selected };
    }
    case 'open':
      return { ...state, openId: action.id, toasts: [] };   // opening a correction clears passing messages, so nothing sits over its buttons
    case 'close':
      return { ...state, openId: null };
    case 'apply/start':
      return { ...state, error: null, proposals: patchProposal(state.proposals, action.id, { state: 'applying' }) };
    case 'apply/done': {
      const proposal = state.proposals.find((p) => p.id === action.id);
      const applied = action.result.status === 'applied';
      return {
        ...state,
        openId: null,
        scannedSinceApply: applied ? false : state.scannedSinceApply,   // a correction was applied: only a new scan confirms it
        findings: applied && proposal ? patchFindings(state.findings, proposal.findingKeys, 'fixed') : state.findings,
        proposals: patchProposal(state.proposals, action.id, { state: applied ? 'applied' : 'failed', result: action.result }),
      };
    }
    case 'apply/fail':
      return { ...state, error: action.message, proposals: patchProposal(state.proposals, action.id, { state: 'ready' }) };
    case 'dismiss': {
      const proposal = state.proposals.find((p) => p.id === action.id);
      return {
        ...state,
        openId: null,
        findings: proposal ? patchFindings(state.findings, proposal.findingKeys, 'found') : state.findings,
        proposals: state.proposals.filter((p) => p.id !== action.id),
      };
    }
    case 'toast/add':
      return { ...state, toasts: [...state.toasts, action.toast] };
    case 'toast/remove':
      return { ...state, toasts: state.toasts.filter((t) => t.id !== action.id) };
    case 'reset':
      return initial;
    default:
      return state;
  }
}

/**
 * The review's state and the only things a person can do to it. Screens call these and nothing else; nothing is written to a file except by apply(), which a person
 * triggers by pressing Apply correction.
 */
export function useReview(backend) {
  const [state, dispatch] = useReducer(reducer, initial);
  const [info, setInfo] = useState(null);
  const last = useRef(null);
  const counter = useRef(0);
  const busy = state.phase === 'scanning' || state.phase === 'proposing';

  useEffect(() => {
    let alive = true;
    backend.info().then((value) => alive && setInfo(value));
    return () => {
      alive = false;
    };
  }, [backend]);

  const toast = useCallback((tone, text) => dispatch({ type: 'toast/add', toast: { id: ++counter.current, tone, text } }), []);
  const dismissToast = useCallback((id) => dispatch({ type: 'toast/remove', id }), []);
  const messageOf = (error) => (error instanceof Error && error.message ? error.message : 'Something went wrong.');

  const scan = useCallback(async () => {
    if (busy) return;
    last.current = 'scan';
    dispatch({ type: 'scan/start' });
    try {
      dispatch({ type: 'scan/done', scan: await backend.scan() });
    } catch (error) {
      dispatch({ type: 'fail', message: messageOf(error) });
    }
  }, [backend, busy]);

  const prepare = useCallback(async () => {
    if (busy || state.selected.length === 0) return;
    last.current = 'prepare';
    dispatch({ type: 'propose/start' });
    try {
      const result = await backend.propose(state.selected);
      dispatch({ type: 'propose/done', result });
      if (result.proposals.length > 0) toast('info', `${result.proposals.length === 1 ? 'A correction is' : `${result.proposals.length} corrections are`} ready for your decision.`);
    } catch (error) {
      dispatch({ type: 'fail', message: messageOf(error) });
    }
  }, [backend, busy, state.selected, toast]);

  const apply = useCallback(async (id) => {
    const proposal = state.proposals.find((p) => p.id === id);
    if (!proposal || proposal.state === 'applying') return;
    dispatch({ type: 'apply/start', id });
    try {
      const result = await backend.apply(id);
      dispatch({ type: 'apply/done', id, result });
      if (result.status === 'applied') toast('success', `${result.message} Verification ${result.verification.outcome}.`);
      else toast('error', result.message);
    } catch (error) {
      dispatch({ type: 'apply/fail', id, message: messageOf(error) });
    }
  }, [backend, state.proposals, toast]);

  const reset = useCallback(async () => {
    await backend.reset();
    dispatch({ type: 'reset' });
    toast('info', 'The sample project is back to how it started.');
  }, [backend, toast]);

  const simulateError = useCallback(() => {
    backend.failNext?.();
    toast('info', 'The next request will fail, to show the error state.');
  }, [backend, toast]);

  const retry = useCallback(() => (last.current === 'prepare' ? prepare() : scan()), [prepare, scan]);   // try the same thing again

  const open = state.proposals.find((p) => p.id === state.openId) ?? null;
  return {
    state,
    info,
    busy,
    openProposal: open,
    columns: {
      found: state.findings.filter((f) => f.status === 'found'),
      decide: state.proposals.filter((p) => p.state !== 'applied'),
      fixed: state.proposals.filter((p) => p.state === 'applied'),
    },
    actions: {
      scan,
      prepare,
      apply,
      retry,
      reset,
      simulateError,
      dismissToast,
      toggle: (key) => dispatch({ type: 'toggle', key }),
      open: (id) => dispatch({ type: 'open', id }),
      close: () => dispatch({ type: 'close' }),
      dismiss: (id) => dispatch({ type: 'dismiss', id }),
    },
  };
}
