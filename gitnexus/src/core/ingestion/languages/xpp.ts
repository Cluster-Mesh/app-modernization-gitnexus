import { SupportedLanguages } from 'gitnexus-shared';
import { SaxesParser } from 'saxes';
import { createCallExtractor } from '../call-extractors/generic.js';
import { csharpCallConfig } from '../call-extractors/configs/csharp.js';
import { createClassExtractor } from '../class-extractors/generic.js';
import { csharpClassConfig } from '../class-extractors/configs/csharp.js';
import { createFieldExtractor } from '../field-extractors/generic.js';
import { csharpConfig as csharpFieldConfig } from '../field-extractors/configs/csharp.js';
import { createImportResolver } from '../import-resolvers/resolver-factory.js';
import { createStandardStrategy } from '../import-resolvers/standard.js';
import { createMethodExtractor } from '../method-extractors/generic.js';
import { csharpMethodConfig } from '../method-extractors/configs/csharp.js';
import { createVariableExtractor } from '../variable-extractors/generic.js';
import { csharpVariableConfig } from '../variable-extractors/configs/csharp.js';
import { CSHARP_QUERIES } from '../tree-sitter-queries.js';
import { csharpExportChecker } from '../export-detection.js';
import { typeConfig as csharpTypeConfig } from '../type-extractors/csharp.js';
import { createLeadingDocDescriptionExtractor } from '../utils/ast-helpers.js';
import { defineLanguage } from '../language-provider.js';
import { csharpScopeResolver } from './csharp/scope-resolver.js';
import {
  emitCsharpScopeCaptures,
  interpretCsharpImport,
  interpretCsharpTypeBinding,
  csharpBindingScopeFor,
  csharpImportOwningScope,
  csharpMergeBindings,
  csharpReceiverBinding,
  csharpArityCompatibility,
  resolveCsharpImportTarget,
} from './csharp/index.js';

const skipQuotedOrCommented = (source: string, start: number): number => {
  const marker = source[start];
  if (marker === '"' || marker === "'") {
    let index = start + 1;
    while (index < source.length) {
      if (source[index] === '\\') {
        index += 2;
      } else if (source[index] === marker) {
        return index + 1;
      } else {
        index++;
      }
    }
    return source.length;
  }
  if (source.startsWith('//', start)) {
    const newline = source.indexOf('\n', start + 2);
    return newline < 0 ? source.length : newline;
  }
  if (source.startsWith('/*', start)) {
    const close = source.indexOf('*/', start + 2);
    return close < 0 ? source.length : close + 2;
  }
  return start;
};

const findStatementEnd = (source: string, start: number): number => {
  let index = start;
  while (index < source.length) {
    const skipped = skipQuotedOrCommented(source, index);
    if (skipped !== index) {
      index = skipped;
      continue;
    }
    if (source[index] === ';' || source[index] === '{') return index;
    index++;
  }
  return -1;
};

function extractDynamicsSource(sourceText: string): string {
  const blank = sourceText.replace(/[^\r\n]/g, ' ');
  const masked = blank.split('');
  const parser = new SaxesParser({ position: true });
  const elements: {
    name: string;
    contentStart: number;
    text: string;
    methodName?: string;
    objectName?: string;
    nameStart?: number;
    closeClass?: boolean;
  }[] = [];
  let valid = true;
  parser.on('error', () => { valid = false; });
  parser.on('doctype', () => { valid = false; });
  parser.on('opentag', (tag) => {
    const name = tag.name.split(':').at(-1)!;
    if (!elements.length && !['AxClass', 'AxTable', 'AxForm'].includes(name)) valid = false;
    elements.push({ name, contentStart: parser.position, text: '' });
  });
  parser.on('text', (text) => {
    const element = elements.at(-1);
    if (element?.name === 'Name') element.text += text;
  });
  parser.on('cdata', () => {
    const frame = elements.at(-1)!;
    const element = frame.name;
    if (!elements.some((frame) => frame.name === 'SourceCode') ||
        (element !== 'Declaration' && element !== 'Source')) return;
    const start = sourceText.indexOf('<![CDATA[', frame.contentStart) + 9;
    const text = sourceText.slice(start, parser.position - 3);
    frame.contentStart = parser.position;
    for (let offset = 0; offset < text.length; offset++) masked[start + offset] = text[offset];
    if (element === 'Declaration' || elements.at(-2)?.methodName === 'classDeclaration') {
      let lastBrace = -1;
      for (let offset = 0; offset < text.length; offset++) {
        const skipped = skipQuotedOrCommented(text, offset);
        if (skipped !== offset) { offset = skipped - 1; continue; }
        if (text[offset] === '}') lastBrace = offset;
      }
      if (lastBrace >= 0) {
        masked[start + lastBrace] = ' ';
        const owner = element === 'Declaration'
          ? elements.at(-2)
          : elements.at(-4);
        if (owner) owner.closeClass = true;
      }
    }
  });
  parser.on('closetag', () => {
    const element = elements.pop()!;
    const parent = elements.at(-1);
    if (element.name === 'Name' && parent) {
      if (parent.name === 'Method') parent.methodName = element.text.trim();
      if (['DataSource', 'DataControl', 'Control', 'Field', 'Member'].includes(parent.name) &&
          elements.some((frame) => frame.name === 'SourceCode')) {
        parent.objectName = element.text.trim();
        parent.nameStart = element.contentStart + element.text.indexOf(parent.objectName);
      }
    }
    if (element.objectName && element.nameStart !== undefined && !element.closeClass &&
        /^[A-Za-z_]\w*$/.test(element.objectName)) {
      const header = `class ${element.objectName} {`;
      for (let offset = 0; offset < header.length; offset++) {
        masked[element.nameStart - 6 + offset] = header[offset];
      }
      element.closeClass = true;
    }
    if (element.closeClass) masked[parser.position - 1] = '}';
  });
  parser.write(sourceText).close();
  return valid ? masked.join('') : blank;
}

export function preprocessXppSource(sourceText: string, filePath = ''): string {
  if (filePath.toLowerCase().endsWith('.xml')) sourceText = extractDynamicsSource(sourceText);
  const masked = sourceText.split('');
  const statementKeyword = /\b(select|update_recordset|insert_recordset|delete_from|extends|implements|display|edit|client|server|ttsbegin|ttscommit|ttsabort)\b/iy;
  let index = 0;

  while (index < sourceText.length) {
    const skipped = skipQuotedOrCommented(sourceText, index);
    if (skipped !== index) {
      if (sourceText[index] === "'" && sourceText[skipped - 1] === "'") {
        masked[index] = '"';
        masked[skipped - 1] = '"';
        for (let cursor = index + 1; cursor < skipped - 1; cursor++) {
          if (masked[cursor] === '"') masked[cursor] = ' ';
        }
      }
      index = skipped;
      continue;
    }
    if (sourceText.startsWith('::', index)) {
      masked[index] = '.';
      masked[index + 1] = ' ';
      index += 2;
      continue;
    }

    statementKeyword.lastIndex = index;
    const match = statementKeyword.exec(sourceText);
    if (!match) {
      index++;
      continue;
    }

    const previous = sourceText.slice(0, index).match(/\S\s*$/)?.[0]?.trimEnd();
    const next = sourceText.slice(index + match[0].length).match(/^\s*(.)/)?.[1];
    if (previous?.endsWith('.') || next === '(') {
      index += match[0].length;
      continue;
    }

    const keyword = match[1].toLowerCase();
    if (['extends', 'implements', 'display', 'edit', 'client', 'server', 'ttsbegin', 'ttscommit', 'ttsabort'].includes(keyword)) {
      for (let offset = 0; offset < match[0].length; offset++) masked[index + offset] = ' ';
      if (keyword === 'extends') masked[index] = ':';
      if (keyword === 'implements') {
        const declaration = sourceText.slice(0, index).match(/\bclass\s+[^{}]*$/)?.[0] ?? '';
        masked[index] = /\bextends\b/.test(declaration) ? ',' : ':';
      }
      index += match[0].length;
      continue;
    }

    const end = findStatementEnd(sourceText, index + match[0].length);
    if (end < 0) {
      index += match[0].length;
      continue;
    }

    let start = index;
    if (match[1].toLowerCase() === 'select') {
      const whilePrefix = sourceText.slice(0, index).match(/\bwhile\s+$/i);
      if (whilePrefix) start = index - whilePrefix[0].length;
    }

    const maskEnd = sourceText[end] === '{' ? end : end + 1;
    for (let cursor = start; cursor < maskEnd; cursor++) {
      if (masked[cursor] !== '\n' && masked[cursor] !== '\r') masked[cursor] = ' ';
    }
    index = maskEnd;
  }

  return masked.join('');
}

export const xppProvider = defineLanguage({
  id: SupportedLanguages.Xpp,
  extensions: ['.xpp'],
  entryPointPatterns: [/^(main|run|execute|validate|init)$/i],
  astFrameworkPatterns: [],
  treeSitterQueries: CSHARP_QUERIES,
  preprocessSource: preprocessXppSource,
  typeConfig: csharpTypeConfig,
  exportChecker: csharpExportChecker,
  importResolver: createImportResolver({
    language: SupportedLanguages.Xpp,
    strategies: [createStandardStrategy(SupportedLanguages.Xpp)],
  }),
  mroStrategy: 'implements-split',
  callExtractor: createCallExtractor({ ...csharpCallConfig, language: SupportedLanguages.Xpp }),
  fieldExtractor: createFieldExtractor({ ...csharpFieldConfig, language: SupportedLanguages.Xpp }),
  methodExtractor: createMethodExtractor({ ...csharpMethodConfig, language: SupportedLanguages.Xpp }),
  variableExtractor: createVariableExtractor({
    ...csharpVariableConfig,
    language: SupportedLanguages.Xpp,
  }),
  classExtractor: createClassExtractor({ ...csharpClassConfig, language: SupportedLanguages.Xpp }),
  descriptionExtractor: createLeadingDocDescriptionExtractor(),
  emitScopeCaptures: emitCsharpScopeCaptures,
  interpretImport: interpretCsharpImport,
  interpretTypeBinding: interpretCsharpTypeBinding,
  bindingScopeFor: csharpBindingScopeFor,
  importOwningScope: csharpImportOwningScope,
  mergeBindings: (_scope, bindings) => csharpMergeBindings(bindings),
  receiverBinding: csharpReceiverBinding,
  arityCompatibility: csharpArityCompatibility,
  resolveImportTarget: resolveCsharpImportTarget,
});

export const xppScopeResolver = {
  ...csharpScopeResolver,
  language: SupportedLanguages.Xpp,
  languageProvider: xppProvider,
  importEdgeReason: 'xpp-scope',
  loadResolutionConfig: undefined,
};