-- Legacy random tokens remain valid; new successors use versioned derivation.
alter table refresh_tokens add column derivation_version text;
alter table refresh_tokens add constraint refresh_tokens_derivation_version_check
  check (derivation_version is null or derivation_version = 'hmac-sha256-v1');
