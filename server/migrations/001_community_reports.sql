-- Apply once in the Supabase SQL editor. Only the backend service key can call
-- these routines; browser roles have no direct access to community tables.
create table if not exists public.community_reports (
  id uuid primary key default gen_random_uuid(),
  domain text not null,
  category text not null check (category in (
    'phishing', 'impersonation', 'crypto_scam', 'fake_airdrop',
    'malicious_wallet_connection', 'suspicious_investment_platform', 'other'
  )),
  description text not null check (char_length(description) between 12 and 500),
  evidence_url text,
  duplicate_hash text not null unique,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'removed')),
  submitted_at timestamptz not null default now(),
  moderated_at timestamptz
);

create index if not exists community_reports_public_domain_recent
  on public.community_reports (domain, submitted_at desc) where status = 'approved';
create index if not exists community_reports_moderation_queue
  on public.community_reports (submitted_at asc) where status = 'pending';

create table if not exists public.community_rate_limits (
  reporter_hash text primary key,
  window_started_at timestamptz not null,
  request_count integer not null check (request_count >= 0)
);

alter table public.community_reports enable row level security;
alter table public.community_rate_limits enable row level security;
revoke all on public.community_reports, public.community_rate_limits from anon, authenticated;
revoke all on public.community_reports, public.community_rate_limits from public;

create or replace function public.community_submit_report(
  p_domain text,
  p_category text,
  p_description text,
  p_evidence_url text,
  p_reporter_hash text,
  p_duplicate_hash text
) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  v_window timestamptz;
  v_count integer;
  v_report_id uuid;
  v_created_at timestamptz;
begin
  delete from public.community_rate_limits
    where window_started_at < now() - interval '2 days';
  insert into public.community_rate_limits(reporter_hash, window_started_at, request_count)
    values (p_reporter_hash, now(), 1)
    on conflict (reporter_hash) do update set
      window_started_at = case
        when public.community_rate_limits.window_started_at <= now() - interval '1 hour' then now()
        else public.community_rate_limits.window_started_at end,
      request_count = case
        when public.community_rate_limits.window_started_at <= now() - interval '1 hour' then 1
        else public.community_rate_limits.request_count + 1 end
    returning window_started_at, request_count into v_window, v_count;

  if v_count > 5 then return jsonb_build_object('error', 'rate_limited'); end if;

  insert into public.community_reports(domain, category, description, evidence_url, duplicate_hash)
    values (p_domain, p_category, p_description, p_evidence_url, p_duplicate_hash)
    on conflict (duplicate_hash) do nothing
    returning id, submitted_at into v_report_id, v_created_at;

  if v_report_id is null then return jsonb_build_object('error', 'duplicate_report'); end if;
  return jsonb_build_object('id', v_report_id, 'status', 'pending', 'submittedAt', v_created_at);
end;
$$;

create or replace function public.community_public_summary(p_domain text)
returns jsonb language sql stable security definer set search_path = '' as $$
  select jsonb_build_object(
    'domain', p_domain,
    'totalApproved', (
      select count(*) from public.community_reports
      where domain = p_domain and status = 'approved'
    ),
    'categoryCounts', coalesce((
      select jsonb_object_agg(category, category_count)
      from (select category, count(*) as category_count
            from public.community_reports where domain = p_domain and status = 'approved'
            group by category) counts
    ), '{}'::jsonb),
    'recentReports', coalesce((
      select jsonb_agg(jsonb_build_object(
        'category', category, 'description', description,
        'evidenceUrl', evidence_url, 'submittedAt', submitted_at
      ) order by submitted_at desc)
      from (select category, description, evidence_url, submitted_at
            from public.community_reports where domain = p_domain and status = 'approved'
            order by submitted_at desc limit 10) recent
    ), '[]'::jsonb)
  )
$$;

create or replace function public.community_moderation_queue(p_limit integer default 100)
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', id, 'domain', domain, 'category', category,
    'description', description, 'evidenceUrl', evidence_url, 'submittedAt', submitted_at
  ) order by submitted_at asc), '[]'::jsonb)
  from (select id, domain, category, description, evidence_url, submitted_at
        from public.community_reports where status = 'pending'
        order by submitted_at asc limit greatest(1, least(p_limit, 100))) pending
$$;

create or replace function public.community_moderate_report(p_report_id uuid, p_action text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_status text;
begin
  if p_action not in ('approve', 'reject', 'remove') then
    raise exception 'invalid_action' using errcode = '22023';
  end if;
  if p_action = 'remove' then
    delete from public.community_reports where id = p_report_id;
    if not found then raise exception 'report_not_found' using errcode = 'P0002'; end if;
    return jsonb_build_object('id', p_report_id, 'status', 'removed');
  end if;
  v_status := case when p_action = 'approve' then 'approved' else 'rejected' end;
  update public.community_reports set status = v_status, moderated_at = now()
    where id = p_report_id and status = 'pending';
  if not found then raise exception 'report_not_found' using errcode = 'P0002'; end if;
  return jsonb_build_object('id', p_report_id, 'status', v_status);
end;
$$;

revoke all on function public.community_submit_report(text, text, text, text, text, text) from public, anon, authenticated;
revoke all on function public.community_public_summary(text) from public, anon, authenticated;
revoke all on function public.community_moderation_queue(integer) from public, anon, authenticated;
revoke all on function public.community_moderate_report(uuid, text) from public, anon, authenticated;
grant execute on function public.community_submit_report(text, text, text, text, text, text) to service_role;
grant execute on function public.community_public_summary(text) to service_role;
grant execute on function public.community_moderation_queue(integer) to service_role;
grant execute on function public.community_moderate_report(uuid, text) to service_role;
