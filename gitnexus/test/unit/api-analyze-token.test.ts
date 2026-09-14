/**
 * Unit tests for validateAnalyzeToken — the optional `token` validation on
 * POST /api/analyze. Tested directly (not via a booted server) since the
 * route validation is otherwise only reachable through createServer.
 *
 * Locks provider-neutral HTTP(S) token validation and CRLF/charset guards.
 */
import { describe, it, expect } from 'vitest';
import { validateAnalyzeToken } from '../../src/server/api.js';

const GH = 'https://github.com/owner/repo';

describe('validateAnalyzeToken', () => {
  it('returns null when no token is provided', () => {
    expect(validateAnalyzeToken(undefined, GH)).toBeNull();
    expect(validateAnalyzeToken(undefined, undefined)).toBeNull();
  });

  it('accepts a well-formed token for GitHub, GitLab, and Azure DevOps URLs', () => {
    expect(validateAnalyzeToken('ghp_abc123', GH)).toBeNull();
    expect(validateAnalyzeToken('ghp_abc123', 'https://www.github.com/o/r')).toBeNull();
    expect(validateAnalyzeToken('glpat_abc123', 'https://gitlab.com/o/r')).toBeNull();
    expect(
      validateAnalyzeToken('ado_pat_abc123', 'https://dev.azure.com/o/p/_git/r'),
    ).toBeNull();
    expect(
      validateAnalyzeToken('ado_pat_abc123', 'https://tfs.corp.example/Collection/P/_git/r'),
    ).toBeNull();
  });

  it('accepts provider-specific Basic-auth usernames', () => {
    expect(validateAnalyzeToken('glpat_abc123', 'https://gitlab.com/o/r', 'oauth2')).toBeNull();
    expect(
      validateAnalyzeToken('job_token_123', 'https://gitlab.com/o/r', 'gitlab-ci-token'),
    ).toBeNull();
    expect(
      validateAnalyzeToken('bb_token_123', 'https://bitbucket.org/o/r', 'x-token-auth'),
    ).toBeNull();
    expect(
      validateAnalyzeToken('token_123', 'https://git.example.com/o/r', 'alice@example.com'),
    ).toBeNull();
  });

  it('rejects a non-string token', () => {
    expect(validateAnalyzeToken(123 as unknown, GH)).toEqual({
      status: 400,
      error: '"token" must be a string',
    });
  });

  it('rejects an empty or over-long token', () => {
    expect(validateAnalyzeToken('', GH)?.error).toBe('"token" length must be between 1 and 256');
    expect(validateAnalyzeToken('a'.repeat(257), GH)?.error).toBe(
      '"token" length must be between 1 and 256',
    );
  });

  it('rejects a token with characters that could smuggle a header (CRLF/space/colon)', () => {
    for (const bad of ['abc def', 'abc\r\nHost: x', 'x-access-token:abc', 'abc<script>']) {
      expect(validateAnalyzeToken(bad, GH)?.error).toBe('"token" contains invalid characters');
    }
  });

  it('rejects a token without a url', () => {
    expect(validateAnalyzeToken('ghp_abc123', undefined)?.error).toBe('"token" requires "url"');
    expect(validateAnalyzeToken('ghp_abc123', '')?.error).toBe('"token" requires "url"');
  });

  it('rejects an invalid or standalone username', () => {
    expect(validateAnalyzeToken(undefined, GH, 'oauth2')?.error).toBe(
      '"username" requires "token"',
    );
    expect(validateAnalyzeToken('token_123', GH, '')?.error).toBe(
      '"username" length must be between 1 and 256',
    );
    expect(validateAnalyzeToken('token_123', GH, 'user:name')?.error).toBe(
      '"username" contains invalid characters',
    );
    expect(validateAnalyzeToken('token_123', GH, 'bad user')?.error).toBe(
      '"username" contains invalid characters',
    );
  });

  it('accepts a token for any other valid public HTTP(S) host', () => {
    expect(validateAnalyzeToken('token_123', 'https://codeberg.org/o/r')).toBeNull();
    expect(validateAnalyzeToken('token_123', 'https://github.com.evil.com/o/r')).toBeNull();
  });

  it('rejects a token for unsupported non-HTTP(S) transport', () => {
    expect(validateAnalyzeToken('token_123', 'ssh://git@example.com/o/r')?.error).toBe(
      '"url" must use http:// or https:// when "token" is provided',
    );
  });

  it('rejects a token when the url is unparseable', () => {
    expect(validateAnalyzeToken('ghp_abc123', 'not-a-url')?.error).toBe(
      '"url" must be a valid URL when "token" is provided',
    );
  });
});
