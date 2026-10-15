import { escapeHtml } from '../html.js';

export interface OidcParams {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  state?: string;
  nonce?: string;
}

export function hiddenFields(p: OidcParams): string {
  const f = (name: string, v?: string) =>
    v === undefined ? '' : `<input type="hidden" name="${name}" value="${escapeHtml(v)}">`;
  return [
    f('client_id', p.client_id),
    f('redirect_uri', p.redirect_uri),
    f('code_challenge', p.code_challenge),
    f('code_challenge_method', p.code_challenge_method),
    f('scope', p.scope),
    f('state', p.state),
    f('nonce', p.nonce),
  ].join('');
}
