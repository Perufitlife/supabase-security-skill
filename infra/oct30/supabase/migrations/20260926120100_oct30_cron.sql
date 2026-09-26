-- Nurture scheduler: every 15 minutes pg_cron calls the oct30-nurture edge function through pg_net.
-- The shared secret lives in Vault (name 'oct30_cron_secret'), created out of band:
--   select vault.create_secret('<random>', 'oct30_cron_secret');
-- and the same value is set as the OCT30_CRON_SECRET function secret.

create extension if not exists pg_cron;
create extension if not exists pg_net with schema extensions;

select cron.unschedule(jobid) from cron.job where jobname = 'oct30-nurture';

select cron.schedule(
  'oct30-nurture',
  '*/15 * * * *',
  $$
  select net.http_post(
    url     := 'https://mknvxxhaatnqsrkcjydc.supabase.co/functions/v1/oct30-nurture',
    headers := jsonb_build_object(
      'content-type', 'application/json',
      'x-cron-secret', (select decrypted_secret from vault.decrypted_secrets where name = 'oct30_cron_secret' limit 1)
    ),
    body    := '{"source":"pg_cron"}'::jsonb,
    timeout_milliseconds := 55000
  );
  $$
);
