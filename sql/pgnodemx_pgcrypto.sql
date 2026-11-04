/* pgnodemx and pgcrypto in the same schema */

\pset pager off

DROP EXTENSION IF EXISTS pgnodemx;
DROP EXTENSION IF EXISTS pgcrypto;

-- pgcrypto 1.4 (PostgreSQL 18) also defines fips_mode(): both orders must work
CREATE EXTENSION pgnodemx;
CREATE EXTENSION pgcrypto;
DROP EXTENSION pgnodemx;
CREATE EXTENSION pgnodemx;

-- exactly one fips_mode(), from pgcrypto on 18+ and from pgnodemx before
SELECT count(*) AS fips_mode_functions FROM pg_proc WHERE proname = 'fips_mode';
SELECT e.extname = CASE WHEN current_setting('server_version_num')::int >= 180000
                        THEN 'pgcrypto' ELSE 'pgnodemx' END AS expected_owner
FROM pg_depend d
JOIN pg_extension e ON e.oid = d.refobjid
WHERE d.classid = 'pg_proc'::regclass
  AND d.objid = 'fips_mode()'::regprocedure
  AND d.refclassid = 'pg_extension'::regclass;
SELECT fips_mode() IS NOT NULL AS fips_mode_works;

DROP EXTENSION pgcrypto;
DROP EXTENSION pgnodemx;
