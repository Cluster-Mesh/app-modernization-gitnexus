/**
 * Unit Tests: download_repo_file (raw bytes of repository assets)
 *
 * Tests the callTool dispatch logic, resolveRepo, init/disconnect,
 * error cases, and silent failure patterns — all with mocked LadybugDB.
 *
 * These are pure unit tests that mock the LadybugDB layer to test
 * the dispatch and error handling logic in isolation.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';

// We need to mock the LadybugDB adapter and repo-manager BEFORE importing LocalBackend.
// local-backend.ts imports from core/lbug/pool-adapter.js; the mcp/core/lbug-adapter.js
// re-exports from the same module, so we mock the canonical source.
// vi.hoisted runs before vi.mock hoisting, making the fns available to both factories.
const { lbugMocks } = vi.hoisted(() => ({
  lbugMocks: {
    initLbug: vi.fn().mockResolvedValue(undefined),
    executeQuery: vi.fn().mockResolvedValue([]),
    executeParameterized: vi.fn().mockResolvedValue([]),
    closeLbug: vi.fn().mockResolvedValue(undefined),
    isLbugReady: vi.fn().mockReturnValue(true),
  },
}));

vi.mock('../../src/core/lbug/pool-adapter.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, ...lbugMocks };
});

// Re-export shim must resolve to the same mocks
vi.mock('../../src/mcp/core/lbug-adapter.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, ...lbugMocks };
});

vi.mock('../../src/storage/repo-manager.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/storage/repo-manager.js')>();
  return {
    ...actual,
    listRegisteredRepos: vi.fn().mockResolvedValue([]),
    cleanupOldKuzuFiles: vi.fn().mockResolvedValue({ found: false, needsReindex: false }),
    findSiblingClones: vi.fn().mockResolvedValue([]),
    // U2: expose loadMeta as a spy that delegates to the REAL implementation by
    // default (so branch-scope resolution, #2106, is unaffected). The
    // impact-mode block overrides it per-test to stamp a READY PDG layer, so the
    // U2 layer-presence probe falls THROUGH to the post-check surface (the
    // `_runImpactPDG` delegate / ambiguous fan-out) those tests assert. The
    // four-state degradation contract itself is covered in
    // test/integration/impact-pdg-degradation.test.ts.
    loadMeta: vi.fn(actual.loadMeta),
  };
});

// `core/git-staleness` is also imported by `local-backend.ts` (for
// `checkStaleness` and `checkCwdMatch`). Stub it out here so unit
// tests don't shell out to git.
vi.mock('../../src/core/git-staleness.js', () => ({
  checkStaleness: vi.fn().mockReturnValue({ isStale: false, commitsBehind: 0 }),
  checkStalenessAsync: vi.fn().mockResolvedValue({ isStale: false, commitsBehind: 0 }),
  checkCwdMatch: vi.fn().mockResolvedValue({ match: 'none' }),
}));

vi.mock('../../src/storage/git.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/storage/git.js')>();
  return {
    ...actual,
    getGitRoot: vi.fn().mockReturnValue(null),
  };
});

// Also mock the search modules to avoid loading onnxruntime
vi.mock('../../src/core/search/bm25-index.js', () => ({
  searchFTSFromLbug: vi.fn().mockResolvedValue({ results: [], ftsAvailable: true }),
}));

vi.mock('../../src/mcp/core/embedder.js', () => ({
  embedQuery: vi.fn().mockResolvedValue([]),
  getEmbeddingDims: vi.fn().mockReturnValue(384),
}));

// #2175: lets the @group-forward path be exercised without real group.yaml infra.
// No existing test in this file uses an @repo, so this mock is inert for them.
const { resolveAtMemberMock } = vi.hoisted(() => ({ resolveAtMemberMock: vi.fn() }));
vi.mock('../../src/core/group/resolve-at-member.js', () => ({
  resolveAtGroupMemberRepoPath: resolveAtMemberMock,
}));

import { LocalBackend } from '../../src/mcp/local/local-backend.js';
import { listRegisteredRepos } from '../../src/storage/repo-manager.js';

describe('LocalBackend download_repo_file', () => {
  let repoDir: string;
  let backend: LocalBackend;
  const png = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0xff,
  ]);

  beforeEach(async () => {
    vi.clearAllMocks();
    repoDir = mkdtempSync(path.join(os.tmpdir(), 'gitnexus-download-'));
    mkdirSync(path.join(repoDir, 'assets'), { recursive: true });
    mkdirSync(path.join(repoDir, '.git'), { recursive: true });
    writeFileSync(path.join(repoDir, 'assets', 'logo.png'), png);
    writeFileSync(path.join(repoDir, '.git', 'config'), 'secret');
    (listRegisteredRepos as any).mockResolvedValue([
      {
        name: 'assets-repo',
        path: repoDir,
        storagePath: path.join(repoDir, '.gitnexus'),
        indexedAt: '2026-11-15T00:00:00Z',
        lastCommit: 'abc1234567890',
        stats: { files: 1, nodes: 1, edges: 0, communities: 0, processes: 0 },
      },
    ]);
    backend = new LocalBackend();
    await backend.init();
  });

  afterEach(() => {
    rmSync(repoDir, { recursive: true, force: true });
  });

  it('returns binary files base64-encoded with size, mime type and sha256', async () => {
    const result = await backend.callTool('download_repo_file', { path: 'assets/logo.png' });
    expect(result.error).toBeUndefined();
    expect(result).toMatchObject({
      path: 'assets/logo.png',
      size: png.length,
      mimeType: 'image/png',
      encoding: 'base64',
      offset: 0,
      length: png.length,
      complete: true,
      next_offset: null,
    });
    expect(Buffer.from(result.content, 'base64').equals(png)).toBe(true);
    expect(result.sha256).toBe(createHash('sha256').update(png).digest('hex'));
  });

  it('pages through the file with offset/length', async () => {
    const first = await backend.callTool('download_repo_file', {
      path: 'assets/logo.png',
      length: 5,
    });
    expect(first).toMatchObject({ offset: 0, length: 5, complete: false, next_offset: 5 });
    const second = await backend.callTool('download_repo_file', {
      path: 'assets/logo.png',
      offset: first.next_offset,
      length: 100,
    });
    expect(second).toMatchObject({ offset: 5, complete: true, next_offset: null });
    const joined = Buffer.concat([
      Buffer.from(first.content, 'base64'),
      Buffer.from(second.content, 'base64'),
    ]);
    expect(joined.equals(png)).toBe(true);
  });

  it.each(['../outside.png', '/etc/passwd', '.git/config', 'assets/../../x'])(
    'rejects unsafe path %s',
    async (unsafe) => {
      const result = await backend.callTool('download_repo_file', { path: unsafe });
      expect(result.error).toMatch(/Invalid "path"/);
    },
  );

  it('reports missing files and invalid offsets', async () => {
    expect(
      (await backend.callTool('download_repo_file', { path: 'assets/missing.png' })).error,
    ).toMatch(/Unable to read file/);
    expect(
      (await backend.callTool('download_repo_file', { path: 'assets/logo.png', offset: 999 }))
        .error,
    ).toMatch(/beyond the file size/);
  });
});
