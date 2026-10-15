export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  roles: string[];
  // Space-delimited scope, выданный этому токену. /userinfo фильтрует ответ по нему.
  scope: string;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  auth_provider: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
}
