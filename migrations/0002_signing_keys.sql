-- Хранилище ключей подписи (JWT). Ключи в PEM (PKCS8/SPKI). Ровно один ключ
-- со status='active' в любой момент — гарантируется partial-unique индексом.
create table signing_keys (
  kid text primary key,
  private_pem text not null,
  public_pem text not null,
  alg text not null,
  status text not null,
  created_at timestamptz not null,
  retired_at timestamptz
);
-- Не более одного активного ключа (аналогично where-индексам в 0001).
create unique index signing_keys_single_active on signing_keys(status) where status = 'active';
