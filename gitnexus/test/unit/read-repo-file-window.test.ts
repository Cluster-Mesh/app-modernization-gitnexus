import { describe, expect, it } from 'vitest';
import { selectRepoFileWindow } from '../../src/mcp/local/local-backend.js';

describe('selectRepoFileWindow', () => {
  it('returns the requested lines of a file larger than the byte budget', () => {
    const content = Array.from({ length: 20000 }, (_, i) => `line ${i + 1} ${'x'.repeat(40)}`).join('\n');
    expect(Buffer.byteLength(content)).toBeGreaterThan(256 * 1024);
    const window = selectRepoFileWindow(content, 15000, 15002);
    expect(window.lines.map((line) => line.split(' ')[1])).toEqual(['15000', '15001', '15002']);
    expect(window).toMatchObject({ totalLines: 20000, endLine: 15002, byteLimited: false });
  });

  it('cuts the window at the byte budget and reports where to continue', () => {
    const content = ['aaaa', 'bbbb', 'cccc', 'dddd'].join('\r\n');
    const window = selectRepoFileWindow(content, 1, 4, 10);
    expect(window.lines).toEqual(['aaaa', 'bbbb']);
    expect(window).toMatchObject({ endLine: 2, byteLimited: true, lineTruncated: false });
  });

  it('truncates a single line longer than the budget', () => {
    const window = selectRepoFileWindow(`short\n${'é'.repeat(100)}\nnext`, 2, 3, 11);
    expect(window.lines).toEqual(['é'.repeat(5)]);
    expect(window).toMatchObject({ endLine: 2, byteLimited: true, lineTruncated: true });
  });
});
