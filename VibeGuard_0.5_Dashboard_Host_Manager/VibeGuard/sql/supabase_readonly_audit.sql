-- VibeGuard read-only Supabase database posture review.
-- Run in Supabase SQL Editor. SELECT-only; does not alter schema, grants, or policies.
-- Review output manually. This does not replace testing with separate dummy users.

-- 1) Tables and whether RLS is enabled.
select n.nspname as schema_name, c.relname as table_name,
       c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p')
  and n.nspname not in ('pg_catalog','information_schema')
order by 1,2;

-- 2) Policies: roles, commands, USING, WITH CHECK.
select schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname not in ('pg_catalog','information_schema')
order by schemaname, tablename, policyname;

-- 3) Table privileges granted to anon/authenticated/PUBLIC.
select grantee, table_schema, table_name, privilege_type
from information_schema.role_table_grants
where grantee in ('anon','authenticated','PUBLIC')
order by grantee, table_schema, table_name, privilege_type;

-- 4) Security-definer functions. Review search_path and execute grants.
select n.nspname as schema_name, p.proname as function_name,
       pg_get_userbyid(p.proowner) as owner,
       p.prosecdef as security_definer,
       pg_get_function_identity_arguments(p.oid) as arguments,
       p.proconfig as function_settings
from pg_proc p join pg_namespace n on n.oid=p.pronamespace
where n.nspname not in ('pg_catalog','information_schema')
  and p.prosecdef
order by 1,2;

-- 5) Function execute grants to public-facing roles.
select routine_schema, routine_name, grantee, privilege_type
from information_schema.routine_privileges
where grantee in ('anon','authenticated','PUBLIC')
order by routine_schema, routine_name, grantee;
