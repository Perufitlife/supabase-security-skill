-- A typical "it worked on my project" schema: relies on the old auto-grants.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique,
  avatar_url text
);
alter table public.profiles enable row level security;
create policy "Public profiles are viewable by everyone" on public.profiles for select using (true);
create policy "Users can update own profile" on public.profiles for update to authenticated using (auth.uid() = id);
grant select on public.profiles to anon;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.profiles to service_role;

-- No grants at all: fine today, 42501 after Oct 30.
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users,
  total numeric(10,2) not null
);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select to authenticated using (auth.uid() = user_id);
create policy "insert own orders" on public.orders for insert to authenticated with check (auth.uid() = user_id);

-- The lazy fix: grant without RLS.
create table public.leads (
  id serial primary key,
  email text not null
);
grant select, insert on public.leads to anon;

-- RLS + grants, but serial sequence never granted: inserts fail on fresh projects.
create table public.comments (
  id bigserial primary key,
  body text
);
alter table public.comments enable row level security;
create policy "anyone can comment" on public.comments for insert to authenticated with check (true);
grant insert on public.comments to authenticated;
grant all on public.comments to service_role;
