export interface ProviderProfile {
  name?: string;
  avatarUrl?: string;
}

export interface ProviderIdentity {
  provider: string;
  subject: string;
  email?: string;
  emailVerified: boolean;
  profile: ProviderProfile;
}

export interface IdentityProvider {
  readonly id: string;
  verify(credential: unknown): Promise<ProviderIdentity>;
}
