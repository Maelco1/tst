-- Schema de référence pour l'application « Planning des gardes ».
-- Toutes les tables sont créées dans le schéma public par défaut.

create table if not exists public.planning_state (
  id text primary key,
  state jsonb not null,
  updated_at timestamptz default timezone('utc', now())
);

create table if not exists public.planning_admin_settings (
  planning_id text primary key references public.planning_state(id) on delete cascade,
  active_tour integer,
  year integer,
  month integer,
  month_two integer,
  holidays text,
  trade_enabled boolean default true,
  saisie_enabled boolean default true,
  access jsonb,
  tours jsonb,
  columns jsonb,
  updated_at timestamptz default timezone('utc', now())
);

create table if not exists public.planning_users (
  planning_id text references public.planning_state(id) on delete cascade,
  name text not null,
  role text not null,
  updated_at timestamptz default timezone('utc', now()),
  primary key (planning_id, name)
);

create table if not exists public.planning_passwords (
  planning_id text references public.planning_state(id) on delete cascade,
  name text not null,
  password text not null,
  updated_at timestamptz default timezone('utc', now()),
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
  updated_at timestamptz default timezone('utc', now()),
  primary key (planning_id, "user", cell_key)
);

create table if not exists public.planning_audit_log (
  planning_id text references public.planning_state(id) on delete cascade,
  idx integer not null,
  timestamp bigint,
  actor text,
  action text,
  payload jsonb,
  updated_at timestamptz default timezone('utc', now()),
  primary key (planning_id, idx)
);

create index if not exists planning_choices_phase_idx on public.planning_choices (planning_id, phase);
create index if not exists planning_choices_status_idx on public.planning_choices (planning_id, status);
create index if not exists planning_audit_log_action_idx on public.planning_audit_log (planning_id, action);

-- Activez Realtime sur la table principale pour bénéficier de la synchronisation instantanée :
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
