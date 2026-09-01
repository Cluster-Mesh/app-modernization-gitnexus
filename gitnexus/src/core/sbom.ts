import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { access, lstat, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { getStoragePaths } from '../storage/repo-manager.js';
import { logger } from './logger.js';

export const SBOM_SCHEMA_VERSION = 1;
export const SBOM_FORMATS = ['cyclonedx-json', 'spdx-json'] as const;
export type SbomFormat = (typeof SBOM_FORMATS)[number];
export const SBOM_MAX_DOCUMENT_BYTES = 128 * 1024 * 1024;
export const SBOM_MAX_HTTP_BYTES = 32 * 1024 * 1024;

export const SBOM_STATUSES = [
  'ready',
  'disabled',
  'missing',
  'unavailable',
  'failed',
  'timed_out',
  'cancelled',
  'stale',
] as const;
export type SbomStatus = (typeof SBOM_STATUSES)[number];

export interface SbomDocument {
  format: SbomFormat;
  content: Record<string, unknown>;
  bytes: number;
  sha256: string;
}

export interface SbomDocumentReceipt {
  path: string;
  bytes: number;
  sha256: string;
}

export interface SbomAttempt {
  provider: 'syft';
  status: SbomStatus;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  errorCode?: string;
  error?: string;
}

export interface SbomReceipt {
  schemaVersion: typeof SBOM_SCHEMA_VERSION;
  provider: 'syft' | null;
  status: SbomStatus;
  indexedCommit: string;
  branch?: string;
  generatedAt: string;
  documents: Partial<Record<SbomFormat, SbomDocumentReceipt>>;
  attempts: SbomAttempt[];
  warnings: string[];
  error?: {
    code: string;
    message: string;
  };
}

export interface SbomResult {
  receipt: SbomReceipt;
  documents?: Partial<Record<SbomFormat, SbomDocument>>;
}

export interface EnsureSbomOptions {
  repoPath: string;
  storageDir: string;
  indexedCommit: string;
  branch?: string;
  enabled?: boolean;
  syftPath?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface ReadSbomOptions {
  branch?: string;
  format?: SbomFormat;
  includeContent?: boolean;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_STDERR_BYTES = 64 * 1024;
const MAX_STDOUT_BYTES = 64 * 1024;
const SBOM_DIR = 'sbom';
const DOCUMENT_PATHS: Record<SbomFormat, string> = {
  'cyclonedx-json': 'sbom.cdx.json',
  'spdx-json': 'sbom.spdx.json',
};

type ProcessResult = {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
  stdout: string;
  error?: Error;
  timedOut: boolean;
  cancelled: boolean;
};

function boundedAppend(current: string, chunk: Buffer, limit: number): string {
  if (current.length >= limit) return current;
  const remaining = limit - current.length;
  return current + chunk.toString('utf8', 0, remaining);
}

function sanitizeMessage(value: string, maxLength = 500): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, maxLength);
}

function validateExecutable(value: string | undefined): string {
  const executable = (value ?? process.env.GITNEXUS_SYFT_PATH ?? 'syft').trim();
  if (!executable || executable.length > 1024 || /[\u0000-\u001f\u007f]/u.test(executable)) {
    throw new Error('Syft executable path is invalid.');
  }
  if (!path.isAbsolute(executable) && !/^[A-Za-z0-9._-]+$/u.test(executable)) {
    throw new Error('Syft executable must be a command name or an absolute path.');
  }
  return executable;
}

function validateTimeout(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`SBOM timeout must be an integer between 1 and ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  return timeoutMs;
}

function isSbomFormat(value: string): value is SbomFormat {
  return (SBOM_FORMATS as readonly string[]).includes(value);
}

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function sbomDirectory(storageDir: string): string {
  return path.join(path.resolve(storageDir), SBOM_DIR);
}

function receiptPath(storageDir: string): string {
  return path.join(sbomDirectory(storageDir), 'receipt.json');
}

function documentPath(storageDir: string, format: SbomFormat): string {
  return path.join(sbomDirectory(storageDir), DOCUMENT_PATHS[format]);
}

function assertJsonDocument(format: SbomFormat, content: unknown): Record<string, unknown> {
  if (!content || typeof content !== 'object' || Array.isArray(content)) {
    throw new Error(`${format} output is not a JSON object.`);
  }
  const document = content as Record<string, unknown>;
  if (format === 'cyclonedx-json' && typeof document.bomFormat !== 'string') {
    throw new Error('CycloneDX output is missing bomFormat.');
  }
  if (format === 'spdx-json' && typeof document.spdxVersion !== 'string') {
    throw new Error('SPDX output is missing spdxVersion.');
  }
  return document;
}

async function writeAtomic(filePath: string, content: string): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp.${randomBytes(8).toString('hex')}`;
  const handle = await open(tempPath, 'wx', 0o600);
  try {
    await handle.writeFile(content, 'utf8');
  } finally {
    await handle.close();
  }
  try {
    await rename(tempPath, filePath);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
}

async function runSyft(
  repoPath: string,
  executable: string,
  outputPaths: Record<SbomFormat, string>,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<ProcessResult> {
  const args = [
    'scan',
    `dir:${repoPath}`,
    '--quiet',
    '--exclude',
    './.git/**',
    '--exclude',
    './.gitnexus/**',
    '-o',
    `cyclonedx-json=${outputPaths['cyclonedx-json']}`,
    '-o',
    `spdx-json=${outputPaths['spdx-json']}`,
  ];

  return await new Promise<ProcessResult>((resolve) => {
    let stderr = '';
    let stdout = '';
    let timedOut = false;
    let cancelled = signal?.aborted ?? false;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    const child = spawn(executable, args, {
      cwd: repoPath,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const terminate = (reason: 'timeout' | 'cancel'): void => {
      if (reason === 'timeout') timedOut = true;
      else cancelled = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => {
        if (!settled) child.kill('SIGKILL');
      }, 2_000);
    };

    const finish = (result: ProcessResult): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      signal?.removeEventListener('abort', onAbort);
      resolve(result);
    };

    const onAbort = (): void => terminate('cancel');
    signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout?.on('data', (chunk: Buffer) => {
      stdout = boundedAppend(stdout, chunk, MAX_STDOUT_BYTES);
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr = boundedAppend(stderr, chunk, MAX_STDERR_BYTES);
    });
    child.once('error', (error) => {
      finish({
        exitCode: null,
        signal: null,
        stderr,
        stdout,
        error,
        timedOut,
        cancelled,
      });
    });
    child.once('close', (exitCode, closeSignal) => {
      finish({
        exitCode,
        signal: closeSignal,
        stderr,
        stdout,
        timedOut,
        cancelled,
      });
    });

    if (cancelled) terminate('cancel');
    else timer = setTimeout(() => terminate('timeout'), timeoutMs);
  });
}

function baseReceipt(options: EnsureSbomOptions, status: SbomStatus): SbomReceipt {
  return {
    schemaVersion: SBOM_SCHEMA_VERSION,
    provider: status === 'disabled' || status === 'missing' ? null : 'syft',
    status,
    indexedCommit: options.indexedCommit,
    ...(options.branch ? { branch: options.branch } : {}),
    generatedAt: new Date().toISOString(),
    documents: {},
    attempts: [],
    warnings: [],
  };
}

function failureCode(result: ProcessResult): string {
  if (result.cancelled) return 'cancelled';
  if (result.timedOut) return 'timeout';
  if (result.error?.message.includes('ENOENT')) return 'syft-not-found';
  if (result.exitCode !== 0) return 'syft-exit';
  return 'syft-output';
}

async function persistReceipt(storageDir: string, receipt: SbomReceipt): Promise<void> {
  await writeAtomic(receiptPath(storageDir), JSON.stringify(receipt, null, 2));
}

async function loadReceipt(storageDir: string): Promise<SbomReceipt | null> {
  try {
    const raw = await readFile(receiptPath(storageDir), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    const receipt = parsed as Partial<SbomReceipt>;
    if (
      receipt.schemaVersion !== SBOM_SCHEMA_VERSION ||
      typeof receipt.status !== 'string' ||
      typeof receipt.indexedCommit !== 'string' ||
      !Array.isArray(receipt.attempts)
    ) {
      return null;
    }
    return receipt as SbomReceipt;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return null;
    throw error;
  }
}

async function loadDocument(
  storageDir: string,
  format: SbomFormat,
  receipt: SbomReceipt,
): Promise<SbomDocument> {
  const expected = receipt.documents[format];
  if (!expected || expected.path !== `${SBOM_DIR}/${DOCUMENT_PATHS[format]}`) {
    throw new Error(`${format} receipt entry is missing or unsafe.`);
  }
  const filePath = documentPath(storageDir, format);
  const fileStat = await stat(filePath);
  if (fileStat.size > SBOM_MAX_DOCUMENT_BYTES) {
    throw new Error(`${format} document exceeds the ${SBOM_MAX_DOCUMENT_BYTES}-byte limit.`);
  }
  const raw = await readFile(filePath, 'utf8');
  if (Buffer.byteLength(raw, 'utf8') !== expected.bytes || sha256(raw) !== expected.sha256) {
    throw new Error(`${format} document checksum does not match its receipt.`);
  }
  return {
    format,
    content: assertJsonDocument(format, JSON.parse(raw)),
    bytes: expected.bytes,
    sha256: expected.sha256,
  };
}

export function getSbomStorageDir(repoPath: string, branch?: string): string {
  const { metaPath } = getStoragePaths(repoPath, branch);
  return path.dirname(metaPath);
}

export async function readSbomFromStorage(
  storageDir: string,
  options: Pick<ReadSbomOptions, 'format' | 'includeContent'> = {},
): Promise<SbomResult | null> {
  const format = options.format ?? 'cyclonedx-json';
  if (!isSbomFormat(format)) throw new Error(`Unsupported SBOM format: ${String(format)}`);

  const receipt = await loadReceipt(storageDir);
  if (!receipt) return null;

  const result: SbomResult = { receipt };
  if (options.includeContent === false || receipt.status !== 'ready') return result;

  result.documents = { [format]: await loadDocument(storageDir, format, receipt) };
  return result;
}

export async function readSbom(
  repoPath: string,
  options: ReadSbomOptions = {},
): Promise<SbomResult | null> {
  return readSbomFromStorage(getSbomStorageDir(repoPath, options.branch), options);
}

export async function ensureSbom(options: EnsureSbomOptions): Promise<SbomResult> {
  if (options.enabled === false) {
    return { receipt: baseReceipt(options, 'disabled') };
  }

  const storageDir = path.resolve(options.storageDir);
  let existing: SbomResult | null = null;
  try {
    existing = await readSbomFromStorage(storageDir, { includeContent: false });
  } catch (error) {
    logger.warn(
      {
        repoPath: sanitizeMessage(options.repoPath, 300),
        error: sanitizeMessage(error instanceof Error ? error.message : String(error)),
      },
      'Could not read the existing SBOM receipt; regenerating',
    );
  }
  if (existing?.receipt.status === 'ready' && existing.receipt.indexedCommit === options.indexedCommit) {
    return existing;
  }

  const startedAt = new Date();
  const receipt = baseReceipt(options, 'failed');
  const attempt: SbomAttempt = {
    provider: 'syft',
    status: 'failed',
    startedAt: startedAt.toISOString(),
    completedAt: startedAt.toISOString(),
    durationMs: 0,
  };
  receipt.attempts.push(attempt);

  const outputDir = path.join(storageDir, '.tmp');
  const outputPaths: Record<SbomFormat, string> = {
    'cyclonedx-json': path.join(outputDir, `sbom.cdx.${randomBytes(8).toString('hex')}.json`),
    'spdx-json': path.join(outputDir, `sbom.spdx.${randomBytes(8).toString('hex')}.json`),
  };

  try {
    const executable = validateExecutable(options.syftPath);
    const timeoutMs = validateTimeout(options.timeoutMs);
    await mkdir(outputDir, { recursive: true });
    const processResult = await runSyft(
      options.repoPath,
      executable,
      outputPaths,
      timeoutMs,
      options.signal,
    );
    const completedAt = new Date();
    attempt.completedAt = completedAt.toISOString();
    attempt.durationMs = completedAt.getTime() - startedAt.getTime();

    if (processResult.error || processResult.exitCode !== 0 || processResult.timedOut || processResult.cancelled) {
      const code = failureCode(processResult);
      attempt.status =
        code === 'cancelled'
          ? 'cancelled'
          : code === 'timeout'
            ? 'timed_out'
            : code === 'syft-not-found'
              ? 'unavailable'
              : 'failed';
      attempt.errorCode = code;
      attempt.error = sanitizeMessage(
        processResult.error?.message ||
          processResult.stderr ||
          `Syft exited with code ${String(processResult.exitCode)}.`,
      );
      receipt.status = attempt.status;
      receipt.error = { code, message: attempt.error };
    } else {
      const documents: Partial<Record<SbomFormat, SbomDocument>> = {};
      for (const format of SBOM_FORMATS) {
        const raw = await readFile(outputPaths[format], 'utf8');
        if (Buffer.byteLength(raw, 'utf8') > SBOM_MAX_DOCUMENT_BYTES) {
          throw new Error(`${format} document exceeds the ${SBOM_MAX_DOCUMENT_BYTES}-byte limit.`);
        }
        const content = assertJsonDocument(format, JSON.parse(raw));
        const normalized = JSON.stringify(content, null, 2);
        const bytes = Buffer.byteLength(normalized, 'utf8');
        const digest = sha256(normalized);
        documents[format] = { format, content, bytes, sha256: digest };
        receipt.documents[format] = {
          path: `${SBOM_DIR}/${DOCUMENT_PATHS[format]}`,
          bytes,
          sha256: digest,
        };
      }
      for (const format of SBOM_FORMATS) {
        const document = documents[format]!;
        await writeAtomic(
          documentPath(storageDir, format),
          JSON.stringify(document.content, null, 2),
        );
      }
      receipt.status = 'ready';
      receipt.provider = 'syft';
      attempt.status = 'ready';
      await persistReceipt(storageDir, receipt);
      return { receipt, documents };
    }
  } catch (error) {
    const completedAt = new Date();
    attempt.completedAt = completedAt.toISOString();
    attempt.durationMs = completedAt.getTime() - startedAt.getTime();
    attempt.status = 'failed';
    attempt.errorCode = 'invalid-output';
    attempt.error = sanitizeMessage(error instanceof Error ? error.message : String(error));
    receipt.status = 'failed';
    receipt.error = { code: 'invalid-output', message: attempt.error };
  } finally {
    await Promise.all(
      Object.values(outputPaths).map((filePath) => rm(filePath, { force: true }).catch(() => {})),
    );
    await rm(outputDir, { recursive: true, force: true }).catch(() => {});
  }

  try {
    await persistReceipt(storageDir, receipt);
  } catch (error) {
    logger.warn(
      {
        repoPath: sanitizeMessage(options.repoPath, 300),
        error: sanitizeMessage(error instanceof Error ? error.message : String(error)),
      },
      'Failed to persist SBOM degraded receipt',
    );
  }
  logger.warn(
    {
      repoPath: sanitizeMessage(options.repoPath, 300),
      status: receipt.status,
      errorCode: receipt.error?.code,
      durationMs: attempt.durationMs,
    },
    'SBOM generation degraded; graph indexing remains available',
  );
  return { receipt };
}

export async function getSbomSummary(
  repoPath: string,
  options: Omit<ReadSbomOptions, 'includeContent'> = {},
): Promise<SbomResult | null> {
  return readSbom(repoPath, { ...options, includeContent: false });
}

export async function validateSyftExecutable(executablePath?: string): Promise<boolean> {
  const executable = validateExecutable(executablePath);
  if (!path.isAbsolute(executable)) return true;
  try {
    await access(executable);
    const fileStat = await lstat(executable);
    return fileStat.isFile() && !fileStat.isSymbolicLink();
  } catch {
    return false;
  }
}
