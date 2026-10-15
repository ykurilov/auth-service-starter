// Любой провал refresh наружу выглядит одинаково (invalid_grant в OIDC).
// Reuse — подтип: отдельный тип для аудита, но instanceof InvalidRefreshTokenError.
export class InvalidRefreshTokenError extends Error {
  constructor(message = 'invalid refresh token') {
    super(message);
    this.name = 'InvalidRefreshTokenError';
  }
}

export class RefreshTokenReuseError extends InvalidRefreshTokenError {
  constructor(message = 'refresh token reuse detected') {
    super(message);
    this.name = 'RefreshTokenReuseError';
  }
}
