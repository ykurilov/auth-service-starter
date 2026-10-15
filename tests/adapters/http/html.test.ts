import { describe, it, expect } from 'vitest';
import { escapeHtml } from '../../../src/adapters/http/html.js';

describe('escapeHtml', () => {
  it('экранирует опасные символы', () => {
    expect(escapeHtml(`<script>"&'`)).toBe('&lt;script&gt;&quot;&amp;&#39;');
  });

  it('не меняет обычный текст', () => {
    expect(escapeHtml('Аня 42')).toBe('Аня 42');
  });
});
