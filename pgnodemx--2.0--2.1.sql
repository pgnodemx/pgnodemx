/* contrib/pgnodemx/pgnodemx--2.0--2.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pgnodemx UPDATE TO '2.1'" to load this file. \quit

-- pgcrypto 1.4 (PostgreSQL 18) has its own fips_mode(); drop ours there so
-- both extensions can live in the same schema.
DO $$
BEGIN
  IF current_setting('server_version_num')::int >= 180000 THEN
    DROP FUNCTION fips_mode();
  END IF;
END
$$;
