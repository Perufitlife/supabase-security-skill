CREATE OR REPLACE FUNCTION public.get_all_emails()
RETURNS SETOF text
LANGUAGE sql
SECURITY DEFINER
AS $$
  select email from auth.users;
$$;
GRANT EXECUTE ON FUNCTION public.get_all_emails() TO anon;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;

create function public.add_numbers(a integer, b integer default 1) returns integer
  language sql immutable as 'select a + b';

create view public.order_totals as
  select user_id, sum(total) as total from public.orders group by user_id;
grant select on public.order_totals to authenticated;

create view public.safe_profiles with (security_invoker = true) as
  select id, username from public.profiles;
grant select on public.safe_profiles to anon, authenticated;

create materialized view public.leaderboard as select username from public.profiles;

create sequence public.invoice_number_seq;
