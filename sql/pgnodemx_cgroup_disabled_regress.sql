/* pgnodemx regression test with cgroup_enabled = false */

\pset pager off
\x auto

DROP EXTENSION IF EXISTS pgnodemx;

CREATE EXTENSION pgnodemx;

-- cgroup mode should be 'disabled'
SELECT cgroup_mode();

-- cgroup is disabled
SELECT current_setting('pgnodemx.cgroup_enabled');

-- proc functions should still work with cgroup disabled
SELECT count(*) > 0 AS has_meminfo FROM proc_meminfo();

-- load averages should be non-negative
SELECT load1 >= 0 AND load5 >= 0 AS loadavg_valid FROM proc_loadavg();
