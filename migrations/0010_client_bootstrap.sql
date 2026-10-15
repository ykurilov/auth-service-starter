create table bootstrap_state (
  name text primary key
);

-- Existing installations already have their client registry; never resurrect
-- clients from a stale CLIENTS_JSON during upgrade.
insert into bootstrap_state (name)
select 'initial-clients' where exists (select 1 from clients);
