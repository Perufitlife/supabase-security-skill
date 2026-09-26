-- Oct 30 inbound engine: free check -> email report -> nurture -> Stripe.
-- Every table: RLS on, no policies, nothing for anon/authenticated, explicit grants to service_role only.
-- Only the edge functions (service_role) read or write these tables.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- leads
create table if not exists public.oct30_leads (
  id              uuid primary key default gen_random_uuid(),
  email           text not null,
  nombre          text,
  rol             text not null default 'owner' check (rol in ('owner', 'dev', 'agency')),
  repo_url        text,
  stack           text,
  descripcion     text,
  resultado       jsonb,
  resumen         text,
  semaforo        text check (semaforo in ('red', 'amber', 'green', 'grey')),
  fuente          text,
  utm             jsonb not null default '{}'::jsonb,
  referrer        text,
  ip_hash         text,
  consent         boolean not null default false,
  estado          text not null default 'new',
  unsubscribed    boolean not null default false,
  unsubscribed_at timestamptz,
  purchased       boolean not null default false,
  purchased_at    timestamptz,
  replied         boolean not null default false,
  replied_at      timestamptz,
  bounced         boolean not null default false,
  is_test         boolean not null default false,
  report_sent_at  timestamptz,
  last_email_at   timestamptz,
  seq_step        integer not null default 0,
  seq_sent        text[] not null default '{}',
  next_email_at   timestamptz,
  checks_count    integer not null default 0,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create unique index if not exists oct30_leads_email_key on public.oct30_leads (lower(email));
create index if not exists oct30_leads_next_email_idx on public.oct30_leads (next_email_at)
  where not unsubscribed and not purchased and not replied and not bounced;

-- ---------------------------------------------------------------- checks (one row per free check, for history + rate limiting)
create table if not exists public.oct30_checks (
  id          uuid primary key default gen_random_uuid(),
  lead_id     uuid references public.oct30_leads (id) on delete cascade,
  repo_url    text,
  branch      text,
  estado      text not null,
  semaforo    text,
  files       integer,
  summary     jsonb,
  ip_hash     text,
  email_hash  text,
  ms          integer,
  created_at  timestamptz not null default now()
);
create index if not exists oct30_checks_ip_idx on public.oct30_checks (ip_hash, created_at desc);
create index if not exists oct30_checks_email_idx on public.oct30_checks (email_hash, created_at desc);

-- ---------------------------------------------------------------- emails (log of every send)
create table if not exists public.oct30_emails (
  id           uuid primary key default gen_random_uuid(),
  lead_id      uuid references public.oct30_leads (id) on delete cascade,
  to_email     text not null,
  kind         text not null,
  subject      text,
  status       text not null default 'sent',
  message_id   text,
  error        text,
  opened_at    timestamptz,
  clicked_at   timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists oct30_emails_created_idx on public.oct30_emails (created_at desc);
create index if not exists oct30_emails_msg_idx on public.oct30_emails (message_id);

-- ---------------------------------------------------------------- orders (Stripe checkout sessions of the 3 Oct 30 payment links)
create table if not exists public.oct30_orders (
  id                 uuid primary key default gen_random_uuid(),
  short_id           text not null unique default upper(substr(md5(gen_random_uuid()::text), 1, 6)),
  stripe_session_id  text not null unique,
  stripe_event_id    text,
  payment_link       text,
  tier               text,
  status             text not null,
  amount_total       integer,
  currency           text,
  email              text,
  nombre             text,
  lead_id            uuid references public.oct30_leads (id) on delete set null,
  recovery_due_at    timestamptz,
  recovery_sent_at   timestamptz,
  raw                jsonb,
  is_test            boolean not null default false,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);
create index if not exists oct30_orders_recovery_idx on public.oct30_orders (recovery_due_at)
  where recovery_sent_at is null and status = 'expired';

-- ---------------------------------------------------------------- events (anonymous page analytics, no PII)
create table if not exists public.oct30_events (
  id          bigint generated always as identity primary key,
  tipo        text not null,
  page        text,
  target      text,
  session_id  text,
  utm_source  text,
  utm_medium  text,
  utm_campaign text,
  utm_content text,
  referrer    text,
  country     text,
  meta        jsonb,
  created_at  timestamptz not null default now()
);
create index if not exists oct30_events_created_idx on public.oct30_events (created_at desc);
create index if not exists oct30_events_tipo_idx on public.oct30_events (tipo, created_at desc);

-- ---------------------------------------------------------------- lock down
alter table public.oct30_leads  enable row level security;
alter table public.oct30_checks enable row level security;
alter table public.oct30_emails enable row level security;
alter table public.oct30_orders enable row level security;
alter table public.oct30_events enable row level security;

revoke all on table public.oct30_leads, public.oct30_checks, public.oct30_emails, public.oct30_orders, public.oct30_events
  from public, anon, authenticated;
grant select, insert, update, delete on table public.oct30_leads  to service_role;
grant select, insert, update, delete on table public.oct30_checks to service_role;
grant select, insert, update, delete on table public.oct30_emails to service_role;
grant select, insert, update, delete on table public.oct30_orders to service_role;
grant select, insert, update, delete on table public.oct30_events to service_role;
-- identity column: service_role needs no sequence grant for inserts; this project's default
-- privileges still hand new sequences to anon/authenticated, so take them back.
revoke all on sequence public.oct30_events_id_seq from public, anon, authenticated;

-- ---------------------------------------------------------------- funnel (service_role only)
create or replace view public.oct30_funnel with (security_invoker = on) as
with ev as (
  select * from public.oct30_events
), l as (
  select * from public.oct30_leads where not is_test
), o as (
  select * from public.oct30_orders where not is_test
), e as (
  select m.* from public.oct30_emails m left join public.oct30_leads x on x.id = m.lead_id
  where coalesce(x.is_test, false) = false and m.kind <> 'alert'
)
select
  (select count(distinct session_id) from ev where tipo = 'page_view')                 as visitantes,
  (select count(*) from ev where tipo = 'page_view')                                   as page_views,
  (select count(*) from ev where tipo = 'cta_click')                                   as cta_clicks,
  (select count(*) from ev where tipo = 'cta_click' and target like 'buy:%')           as clicks_comprar,
  (select count(*) from ev where tipo = 'check_submit')                                as checks_enviados,
  (select count(*) from public.oct30_checks c join l on l.id = c.lead_id)              as checks_procesados,
  (select count(*) from l)                                                             as leads,
  (select count(*) from l where rol = 'owner')                                         as leads_owner,
  (select count(*) from l where rol = 'dev')                                           as leads_dev,
  (select count(*) from l where rol = 'agency')                                        as leads_agency,
  (select count(*) from l where semaforo = 'red')                                      as leads_rojo,
  (select count(*) from l where semaforo = 'amber')                                    as leads_ambar,
  (select count(*) from l where semaforo = 'green')                                    as leads_verde,
  (select count(*) from l where estado = 'no_repo')                                    as leads_sin_repo,
  (select count(*) from l where unsubscribed)                                          as bajas,
  (select count(*) from l where replied)                                               as respondieron,
  (select count(*) from e where status = 'sent')                                       as emails_enviados,
  (select count(*) from e where opened_at is not null)                                 as emails_abiertos,
  (select count(*) from e where clicked_at is not null)                                as emails_clic,
  (select count(*) from e where status = 'sent' and created_at > now() - interval '24 hours') as emails_24h,
  (select count(*) from o where status = 'expired')                                    as checkouts_abandonados,
  (select count(*) from o where status = 'paid')                                       as ventas,
  (select coalesce(sum(amount_total), 0) / 100.0 from o where status = 'paid')         as ingresos_usd;

create or replace view public.oct30_funnel_diario with (security_invoker = on) as
select d::date as dia,
  (select count(distinct session_id) from public.oct30_events where tipo = 'page_view' and created_at::date = d::date) as visitantes,
  (select count(*) from public.oct30_events where tipo = 'check_submit' and created_at::date = d::date) as checks,
  (select count(*) from public.oct30_leads where not is_test and created_at::date = d::date) as leads_nuevos,
  (select count(*) from public.oct30_emails where status = 'sent' and created_at::date = d::date) as emails,
  (select count(*) from public.oct30_orders where not is_test and status = 'paid' and created_at::date = d::date) as ventas
from generate_series(date '2026-09-26', (now() at time zone 'utc')::date, interval '1 day') d
order by 1 desc;

revoke all on table public.oct30_funnel, public.oct30_funnel_diario from public, anon, authenticated;
grant select on table public.oct30_funnel, public.oct30_funnel_diario to service_role;
