import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ChildProcess } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';

const { spawnMock, mode } = vi.hoisted(() => ({
  spawnMock: vi.fn(),
  mode: { value: 'success' as 'success' | 'malformed' | 'unavailable' },
}));

vi.mock('node:child_process', () => ({ spawn: spawnMock }));

import {
  ensureSbom,
  readSbomFromStorage,
  type SbomFormat,
} from '../../src/core/sbom.js';

const CYCLONEDX_DOCUMENT = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  components: [{ type: 'library', name: 'example', version: '1.0.0' }],
};
const SPDX_DOCUMENT = {
  spdxVersion: 'SPDX-2.3',
  name: 'example',
  packages: [{ SPDXID: 'SPDXRef-Package-example', name: 'example', versionInfo: '1.0.0' }],
};

function fakeChild(): EventEmitter & {
  stdout: EventEmitter;
  stderr: EventEmitter;
  kill: ReturnType<typeof vi.fn>;
} {
  const child = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  return child;
}

function configureSpawnMock(): void {
  spawnMock.mockImplementation((_executable: string, args: string[]) => {
    const child = fakeChild();
    const outputPaths = new Map<SbomFormat, string>();
    for (let index = 0; index < args.length; index += 1) {
      const value = args[index];
      if (value !== '-o') continue;
      const [format, outputPath] = args[index + 1]!.split('=', 2) as [SbomFormat, string];
      outputPaths.set(format, outputPath);
    }

    queueMicrotask(async () => {
      if (mode.value === 'unavailable') {
        const error = Object.assign(new Error('spawn syft ENOENT'), { code: 'ENOENT' });
        child.emit('error', error);
        return;
      }

      await fs.writeFile(
        outputPaths.get('cyclonedx-json')!,
        JSON.stringify(mode.value === 'malformed' ? {} : CYCLONEDX_DOCUMENT),
      );
      await fs.writeFile(
        outputPaths.get('spdx-json')!,
        JSON.stringify(SPDX_DOCUMENT),
      );
      child.emit('close', 0, null);
    });

    return child as unknown as ChildProcess;
  });
}

describe('SBOM service', () => {
  let tempRoot: string;

  afterEach(async () => {
    spawnMock.mockReset();
    mode.value = 'success';
    if (tempRoot) await fs.rm(tempRoot, { recursive: true, force: true });
  });

  it('generates both formats, persists a receipt, and reuses a matching commit', async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-sbom-'));
    configureSpawnMock();

    const options = {
      repoPath: tempRoot,
      storageDir: path.join(tempRoot, '.gitnexus'),
      indexedCommit: 'a'.repeat(40),
      syftPath: '/usr/local/bin/syft',
    };
    const generated = await ensureSbom(options);

    expect(generated.receipt.status).toBe('ready');
    expect(generated.documents?.['cyclonedx-json']?.content).toEqual(CYCLONEDX_DOCUMENT);
    expect(generated.documents?.['spdx-json']?.content).toEqual(SPDX_DOCUMENT);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [, args] = spawnMock.mock.calls[0] as [string, string[]];
    expect(args).toEqual(
      expect.arrayContaining([
        '--exclude',
        './.git/**',
        '--exclude',
        './.gitnexus/**',
        '-o',
        expect.stringContaining('cyclonedx-json='),
        '-o',
        expect.stringContaining('spdx-json='),
      ]),
    );

    const receiptPath = path.join(options.storageDir, 'sbom', 'receipt.json');
    await expect(fs.access(receiptPath)).resolves.toBeUndefined();
    const reused = await ensureSbom(options);
    expect(reused.receipt.status).toBe('ready');
    expect(spawnMock).toHaveBeenCalledTimes(1);

    const spdx = await readSbomFromStorage(options.storageDir, {
      format: 'spdx-json',
    });
    expect(spdx?.documents?.['spdx-json']?.content).toEqual(SPDX_DOCUMENT);
    expect(spdx?.receipt.documents['spdx-json']?.sha256).toBe(
      createHash('sha256')
        .update(JSON.stringify(SPDX_DOCUMENT, null, 2), 'utf8')
        .digest('hex'),
    );
  });

  it('returns an explicit unavailable status when Syft cannot be started', async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-sbom-'));
    mode.value = 'unavailable';
    configureSpawnMock();

    const result = await ensureSbom({
      repoPath: tempRoot,
      storageDir: path.join(tempRoot, '.gitnexus'),
      indexedCommit: 'b'.repeat(40),
    });

    expect(result.receipt.status).toBe('unavailable');
    expect(result.receipt.error?.code).toBe('syft-not-found');
    expect(result.receipt.documents).toEqual({});
    const persisted = await readSbomFromStorage(path.join(tempRoot, '.gitnexus'), {
      includeContent: false,
    });
    expect(persisted?.receipt.status).toBe('unavailable');
  });

  it('does not publish a ready receipt when Syft output is malformed', async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-sbom-'));
    mode.value = 'malformed';
    configureSpawnMock();

    const result = await ensureSbom({
      repoPath: tempRoot,
      storageDir: path.join(tempRoot, '.gitnexus'),
      indexedCommit: 'c'.repeat(40),
    });

    expect(result.receipt.status).toBe('failed');
    expect(result.receipt.error?.code).toBe('invalid-output');
    expect(result.documents).toBeUndefined();
  });

  it('rejects unsupported formats before reading storage', async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-sbom-'));

    await expect(
      readSbomFromStorage(tempRoot, { format: 'xml' as never }),
    ).rejects.toThrow('Unsupported SBOM format');
  });

  it('preserves disabled behavior without replacing an existing receipt', async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-sbom-'));
    configureSpawnMock();
    const options = {
      repoPath: tempRoot,
      storageDir: path.join(tempRoot, '.gitnexus'),
      indexedCommit: 'd'.repeat(40),
    };
    await ensureSbom(options);

    const disabled = await ensureSbom({ ...options, enabled: false });
    expect(disabled.receipt.status).toBe('disabled');
    const persisted = await readSbomFromStorage(options.storageDir, { includeContent: false });
    expect(persisted?.receipt.status).toBe('ready');
  });
});
