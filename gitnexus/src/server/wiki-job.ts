/**
 * Wiki Job Manager
 *
 * Tracks server-side wiki-generation jobs (triggered via POST /api/wiki).
 * Mirrors the analyze-job.ts pattern: in-memory map, single-slot concurrency
 * (one active wiki job at a time — generation is LLM-bound and sequential
 * per-repo anyway), same-repo dedup, and TTL cleanup for terminal jobs.
 */

import { randomUUID } from 'crypto';

export interface WikiJobProgress {
  phase: string;
  percent: number;
  message: string;
}

export interface WikiJobResult {
  pagesGenerated: number;
  mode: 'full' | 'incremental' | 'up-to-date';
  failedModules: string[];
}

export interface WikiJob {
  id: string;
  status: 'queued' | 'running' | 'complete' | 'failed';
  repoName: string;
  progress: WikiJobProgress;
  result?: WikiJobResult;
  error?: string;
  startedAt: number;
  completedAt?: number;
}

const JOB_TTL_MS = 60 * 60 * 1000; // 1 hour
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export class WikiJobManager {
  private jobs = new Map<string, WikiJob>();
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
    this.cleanupTimer.unref?.();
  }

  private isTerminal(status: WikiJob['status']): boolean {
    return status === 'complete' || status === 'failed';
  }

  /** Create a new job, or return the existing active job for the same repo. */
  createJob(repoName: string): WikiJob {
    for (const job of this.jobs.values()) {
      if (!this.isTerminal(job.status) && job.repoName === repoName) {
        return job;
      }
    }

    for (const job of this.jobs.values()) {
      if (!this.isTerminal(job.status)) {
        throw new Error(`Wiki generation already in progress (job ${job.id})`);
      }
    }

    const job: WikiJob = {
      id: randomUUID(),
      status: 'queued',
      repoName,
      progress: { phase: 'queued', percent: 0, message: 'Waiting to start...' },
      startedAt: Date.now(),
    };
    this.jobs.set(job.id, job);
    return job;
  }

  getJob(id: string): WikiJob | undefined {
    return this.jobs.get(id);
  }

  updateJob(
    id: string,
    update: Partial<Pick<WikiJob, 'status' | 'progress' | 'error' | 'result' | 'completedAt'>>,
  ): void {
    const job = this.jobs.get(id);
    if (!job) return;
    // Once terminal, ignore further updates (immutable outcome).
    if (this.isTerminal(job.status)) return;

    Object.assign(job, update);

    if (this.isTerminal(job.status)) {
      job.completedAt = job.completedAt ?? Date.now();
    }
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [id, job] of this.jobs) {
      if (this.isTerminal(job.status) && job.completedAt && now - job.completedAt > JOB_TTL_MS) {
        this.jobs.delete(id);
      }
    }
  }
}
