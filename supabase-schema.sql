-- ============================================================================
-- Schéma Supabase pour l'application « Planning des gardes ».
-- ---------------------------------------------------------------------------
-- Le script est idempotent : il peut être relancé sans casser les données.
-- Il se charge de créer la structure minimale, d'harmoniser les valeurs par
-- défaut et d'installer des déclencheurs pour tenir à jour les horodatages.
-- ============================================================================

begin;

set search_path to public;

-- ---------------------------------------------------------------------------
-- Tables principales
-- ---------------------------------------------------------------------------
create table if not exists public.planning_state (
  id text primary key,
  state jsonb not null,
  updated_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.planning_admin_settings (
  planning_id text primary key references public.planning_state(id) on delete cascade,
  active_tour integer,
  year integer,
  month integer,
  month_two integer,
  holidays text default '',
  trade_enabled boolean default true,
  saisie_enabled boolean default true,
  access jsonb default '{}'::jsonb,
  tours jsonb default '[]'::jsonb,
  columns jsonb default '[]'::jsonb,
  updated_at timestamptz not null default timezone('utc', now())
);

-- ---------------------------------------------------------------------------
-- Tables dérivées
-- ---------------------------------------------------------------------------
create table if not exists public.planning_users (
  planning_id text references public.planning_state(id) on delete cascade,
  name text not null,
  role text not null check (role in ('associe', 'remplacant')),
  updated_at timestamptz not null default timezone('utc', now()),
  primary key (planning_id, name)
);

create table if not exists public.planning_passwords (
  planning_id text references public.planning_state(id) on delete cascade,
  name text not null,
  password text not null,
  updated_at timestamptz not null default timezone('utc', now()),
  primary key (planning_id, name)
);

create table if not exists public.planning_choices (
  planning_id text references public.planning_state(id) on delete cascade,
  "user" text not null,
  cell_key text not null,
  status text,
  category text,
  level integer,
  alternative integer,
  phase text,
  timestamp bigint,
  date_label text,
  day_label text,
  column_label text,
  hours_label text,
  updated_at timestamptz not null default timezone('utc', now()),
  primary key (planning_id, "user", cell_key)
);

create table if not exists public.planning_audit_log (
  planning_id text references public.planning_state(id) on delete cascade,
  idx integer not null,
  timestamp bigint,
  actor text,
  action text,
  payload jsonb,
  updated_at timestamptz not null default timezone('utc', now()),
  primary key (planning_id, idx)
);

-- ---------------------------------------------------------------------------
-- Harmonisation des valeurs par défaut lorsque les tables existent déjà
-- ---------------------------------------------------------------------------
alter table if exists public.planning_state
  alter column updated_at set default timezone('utc', now());

alter table if exists public.planning_admin_settings
  alter column holidays set default '';
alter table if exists public.planning_admin_settings
  alter column trade_enabled set default true;
alter table if exists public.planning_admin_settings
  alter column saisie_enabled set default true;
alter table if exists public.planning_admin_settings
  alter column access set default '{}'::jsonb;
alter table if exists public.planning_admin_settings
  alter column tours set default '[]'::jsonb;
alter table if exists public.planning_admin_settings
  alter column columns set default '[]'::jsonb;
alter table if exists public.planning_admin_settings
  alter column updated_at set default timezone('utc', now());

alter table if exists public.planning_users
  alter column updated_at set default timezone('utc', now());

alter table if exists public.planning_passwords
  alter column updated_at set default timezone('utc', now());

alter table if exists public.planning_choices
  alter column updated_at set default timezone('utc', now());

alter table if exists public.planning_audit_log
  alter column updated_at set default timezone('utc', now());

-- ---------------------------------------------------------------------------
-- Fonction utilitaire + déclencheurs pour la colonne updated_at
-- ---------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger as $$
begin
  new.updated_at = timezone('utc', now());
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_planning_state_updated_at on public.planning_state;
create trigger trg_planning_state_updated_at
  before update on public.planning_state
  for each row execute function public.set_updated_at();

drop trigger if exists trg_planning_admin_settings_updated_at on public.planning_admin_settings;
create trigger trg_planning_admin_settings_updated_at
  before update on public.planning_admin_settings
  for each row execute function public.set_updated_at();

drop trigger if exists trg_planning_users_updated_at on public.planning_users;
create trigger trg_planning_users_updated_at
  before update on public.planning_users
  for each row execute function public.set_updated_at();

drop trigger if exists trg_planning_passwords_updated_at on public.planning_passwords;
create trigger trg_planning_passwords_updated_at
  before update on public.planning_passwords
  for each row execute function public.set_updated_at();

drop trigger if exists trg_planning_choices_updated_at on public.planning_choices;
create trigger trg_planning_choices_updated_at
  before update on public.planning_choices
  for each row execute function public.set_updated_at();

drop trigger if exists trg_planning_audit_log_updated_at on public.planning_audit_log;
create trigger trg_planning_audit_log_updated_at
  before update on public.planning_audit_log
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Index utilisés par l'application pour les requêtes filtrées
-- ---------------------------------------------------------------------------
create index if not exists planning_choices_phase_idx
  on public.planning_choices (planning_id, phase);
create index if not exists planning_choices_status_idx
  on public.planning_choices (planning_id, status);
create index if not exists planning_choices_user_idx
  on public.planning_choices (planning_id, "user");
create index if not exists planning_choices_timestamp_idx
  on public.planning_choices (planning_id, timestamp);
create index if not exists planning_audit_log_action_idx
  on public.planning_audit_log (planning_id, action);
create index if not exists planning_audit_log_actor_idx
  on public.planning_audit_log (planning_id, actor);

-- ---------------------------------------------------------------------------
-- Valeur initiale : mot de passe administrateur « Melatonine »
-- ---------------------------------------------------------------------------
insert into public.planning_passwords (planning_id, name, password)
values ('planning_gardes_state_v080', 'admin', 'Melatonine')
on conflict (planning_id, name)
  do update set password = excluded.password,
                updated_at = timezone('utc', now());

commit;

-- Pour activer la synchronisation temps réel :
--   alter publication supabase_realtime add table public.planning_state;

-- ---------------------------------------------------------------------------
-- Jeu de données de démarrage : crée un planning avec un compte administrateur
-- "admin" (mot de passe « Melatonine ») pour initialiser l'application.
-- ---------------------------------------------------------------------------
with base_state as (
  select jsonb_build_object(
    'users', jsonb_build_object(
      'associes', jsonb_build_array('admin'),
      'remplacants', jsonb_build_array()
    ),
    'passwords', jsonb_build_object('admin', 'Melatonine'),
    'sessions', jsonb_build_object(),
    'progress', jsonb_build_object(),
    'draftSelections', jsonb_build_object(),
    'published', jsonb_build_object(),
    'audit', jsonb_build_array(),
    'loginLogs', jsonb_build_array(),
    'unavailabilities', jsonb_build_object(),
    'access', jsonb_build_object(
      'associes', jsonb_build_object('admin', true),
      'remplacants', jsonb_build_object()
    ),
    'tradeEnabled', true,
    'saisieEnabled', true,
    'meta', jsonb_build_object(
      'lastModifiedBy', 'seed-script',
      'lastModifiedAt', to_jsonb(floor(extract(epoch from now()) * 1000)::bigint)
    )
  ) as state
)
insert into public.planning_state (id, state)
select 'planning_gardes_state_v080', state
from base_state
on conflict (id) do update
set state = excluded.state,
    updated_at = timezone('utc', now());

insert into public.planning_users (planning_id, name, role)
values ('planning_gardes_state_v080', 'admin', 'associe')
on conflict (planning_id, name) do update
set role = excluded.role,
    updated_at = timezone('utc', now());

insert into public.planning_passwords (planning_id, name, password)
values ('planning_gardes_state_v080', 'admin', 'Melatonine')
on conflict (planning_id, name) do update
set password = excluded.password,
    updated_at = timezone('utc', now());
