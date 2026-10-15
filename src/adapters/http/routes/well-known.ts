import type { FastifyInstance } from 'fastify';
import type { HttpDeps } from '../deps.js';
import { toJwks } from '../../../domain/tokens/jwks.js';
import { SUPPORTED_SCOPES } from '../../../domain/tokens/scope.js';

export function registerWellKnown(app: FastifyInstance, deps: HttpDeps): void {
  const iss = deps.config.issuerUrl;
  app.get('/.well-known/openid-configuration', async () => ({
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/oauth/token`,
    userinfo_endpoint: `${iss}/userinfo`,
    end_session_endpoint: `${iss}/logout`,
    revocation_endpoint: `${iss}/oauth/revoke`,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: [...SUPPORTED_SCOPES],
    token_endpoint_auth_methods_supported: ['none'],
    claims_supported: ['sub', 'email', 'email_verified', 'name'],
  }));
  app.get('/.well-known/jwks.json', async () => toJwks(deps.signingKeys));
}
