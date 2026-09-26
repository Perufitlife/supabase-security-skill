-- "permission denied for table" after Oct 30? Paste this and move on. (Don't.)
create table public.notes (id uuid primary key default gen_random_uuid(), body text);
create table public.secrets (id uuid primary key, api_key text);
alter table public.secrets enable row level security;

create table public.posts (id uuid primary key, author uuid, body text);
alter table public.posts enable row level security;
create policy "read posts" on public.posts for select to anon, authenticated using (true);

grant all on all tables in schema public to anon, authenticated, service_role;
grant usage, select on all sequences in schema public to anon, authenticated, service_role;
grant execute on all functions in schema public to anon;

alter default privileges for role postgres in schema public
  grant select, insert, update, delete on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon;
