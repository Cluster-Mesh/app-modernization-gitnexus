/**
 * Unit tests for analyzeWorkerBranch — which index slot POST /api/analyze
 * pins the worker to. Tested directly (not via a booted server) since the
 * route is otherwise only reachable through createServer.
 *
 * A server-owned clone has one working tree checked out on the requested
 * branch, so it must reclaim the flat (primary) slot instead of pinning a
 * `branches/<slug>/` sub-index behind the first-cloned branch.
 */
import { describe, it, expect } from 'vitest';
import { analyzeWorkerBranch } from '../../src/server/api.js';

describe('analyzeWorkerBranch', () => {
  it('indexes a server-owned clone into the flat slot, whatever branch was requested', () => {
    expect(analyzeWorkerBranch('Migration_dev/Sc104', true)).toBeUndefined();
    expect(analyzeWorkerBranch('main', true)).toBeUndefined();
    expect(analyzeWorkerBranch(undefined, true)).toBeUndefined();
  });

  it('keeps the explicit branch pin for caller-supplied paths', () => {
    expect(analyzeWorkerBranch('feature/x', false)).toBe('feature/x');
    expect(analyzeWorkerBranch(undefined, false)).toBeUndefined();
  });
});
