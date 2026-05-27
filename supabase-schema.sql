-- ══════════════════════════════════════════════════════════
--  RNG SPINNER — Jalankan SEMUA di Supabase SQL Editor
--  Copy semua, paste, klik RUN
-- ══════════════════════════════════════════════════════════

-- 1. Aktifkan pgcrypto (WAJIB untuk hash password)
--    Jika error "already exists" → tidak apa-apa, lanjutkan
create extension if not exists pgcrypto with schema extensions;

-- 2. Hapus tabel & fungsi lama jika ada
drop function if exists public.register_player(text, text);
drop function if exists public.login_player(text, text);
drop function if exists public.save_player(uuid, bigint, bigint, bigint, jsonb, jsonb, bigint);
drop table if exists public.players cascade;

-- 3. Buat tabel players
create table public.players (
  id          uuid primary key default gen_random_uuid(),
  username    text not null,
  pass_hash   text not null,
  tokens      bigint not null default 0,
  spins       bigint not null default 0,
  rares       bigint not null default 0,
  upgrades    jsonb not null default '{"fastRoll":0,"doubleRoll":0,"luckRoll":0}',
  best_block  jsonb default null,
  best_score  bigint not null default 0,
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

-- 4. Index
create unique index idx_players_username_ci on public.players (lower(username));
create index        idx_players_score       on public.players (best_score desc);

-- 5. RLS
alter table public.players enable row level security;
drop policy if exists "rng_select" on public.players;
drop policy if exists "rng_insert" on public.players;
drop policy if exists "rng_update" on public.players;
create policy "rng_select" on public.players for select using (true);
create policy "rng_insert" on public.players for insert with check (true);
create policy "rng_update" on public.players for update using (true);

-- ══════════════════════════════════════════════════════════
--  RPC register_player
-- ══════════════════════════════════════════════════════════
create function public.register_player(p_username text, p_password text)
returns json
language plpgsql security definer
set search_path = public, extensions
as $$
declare
  v_low  text := lower(trim(p_username));
  v_new  public.players;
begin
  if length(trim(p_username)) < 2 then
    return json_build_object('ok', false, 'msg', 'Username minimal 2 karakter');
  end if;
  if length(trim(p_username)) > 20 then
    return json_build_object('ok', false, 'msg', 'Username maksimal 20 karakter');
  end if;
  if length(p_password) < 6 then
    return json_build_object('ok', false, 'msg', 'Password minimal 6 karakter');
  end if;
  if exists (select 1 from public.players where lower(username) = v_low) then
    return json_build_object('ok', false, 'msg', 'Username sudah dipakai');
  end if;

  insert into public.players (username, pass_hash)
  values (trim(p_username), extensions.crypt(p_password, extensions.gen_salt('bf', 8)))
  returning * into v_new;

  return json_build_object('ok', true, 'id', v_new.id, 'username', v_new.username);
end;
$$;

-- ══════════════════════════════════════════════════════════
--  RPC login_player
-- ══════════════════════════════════════════════════════════
create function public.login_player(p_username text, p_password text)
returns json
language plpgsql security definer
set search_path = public, extensions
as $$
declare
  v_row public.players;
begin
  select * into v_row
  from public.players
  where lower(username) = lower(trim(p_username))
  limit 1;

  if not found then
    return json_build_object('ok', false, 'msg', 'Username tidak ditemukan');
  end if;

  if v_row.pass_hash <> extensions.crypt(p_password, v_row.pass_hash) then
    return json_build_object('ok', false, 'msg', 'Password salah');
  end if;

  update public.players set updated_at = now() where id = v_row.id;

  return json_build_object(
    'ok',         true,
    'id',         v_row.id,
    'username',   v_row.username,
    'tokens',     v_row.tokens,
    'spins',      v_row.spins,
    'rares',      v_row.rares,
    'upgrades',   v_row.upgrades,
    'best_block', v_row.best_block,
    'best_score', v_row.best_score
  );
end;
$$;

-- ══════════════════════════════════════════════════════════
--  RPC save_player
-- ══════════════════════════════════════════════════════════
create function public.save_player(
  p_id         uuid,
  p_tokens     bigint,
  p_spins      bigint,
  p_rares      bigint,
  p_upgrades   jsonb,
  p_best_block jsonb,
  p_best_score bigint
)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  update public.players set
    tokens     = p_tokens,
    spins      = p_spins,
    rares      = p_rares,
    upgrades   = p_upgrades,
    best_block = p_best_block,
    best_score = p_best_score,
    updated_at = now()
  where id = p_id;
end;
$$;

-- ══════════════════════════════════════════════════════════
-- SELESAI ✅
-- Cek: Table Editor → harus ada tabel "players"
-- ══════════════════════════════════════════════════════════
