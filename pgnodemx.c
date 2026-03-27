/*
 * pgnodemx
 *
 * SQL functions that allow capture of node OS metrics from PostgreSQL
 * Joe Conway <mail@joeconway.com>
 *
 * This code is released under the PostgreSQL license.
 *
 * Portions Copyright 2020-2022 Crunchy Data Solutions, Inc.
 * Portions Copyright 2025, PostgreSQL Global Development Group
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written
 * agreement is hereby granted, provided that the above copyright notice
 * and this paragraph and the following two paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL CRUNCHY DATA SOLUTIONS, INC. BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
 * INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE CRUNCHY DATA SOLUTIONS, INC. HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE CRUNCHY DATA SOLUTIONS, INC. SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE CRUNCHY DATA SOLUTIONS, INC. HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include "postgres.h"

#if PG_VERSION_NUM < 100000
#error "pgnodemx only builds with PostgreSQL 10 or later"
#endif

#include <dlfcn.h>
#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#endif
#include <unistd.h>

#include "catalog/pg_authid.h"
#if PG_VERSION_NUM >= 110000
#include "catalog/pg_type_d.h"
#else
#include "catalog/pg_type.h"
#endif
#include "fmgr.h"
#include "libpq/auth.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc_tables.h"
#if PG_VERSION_NUM < 150000
#include "utils/int8.h"
#endif
#include "utils/varlena.h"

#include "cgroup.h"
#include "envutils.h"
#include "fileutils.h"
#include "genutils.h"
#include "kdapi.h"
#include "parseutils.h"
#include "procfunc.h"
#include "srfsigs.h"

PG_MODULE_MAGIC;

/* function return signatures */
Oid text_sig[] = {TEXTOID};
Oid bigint_sig[] = {INT8OID};
Oid text_text_sig[] = {TEXTOID, TEXTOID};
Oid text_bigint_sig[] = {TEXTOID, INT8OID};
Oid text_text_bigint_sig[] = {TEXTOID, TEXTOID, INT8OID};
Oid text_text_float8_sig[] = {TEXTOID, TEXTOID, FLOAT8OID};
Oid _2_numeric_text_9_numeric_text_sig[] = {NUMERICOID, NUMERICOID, TEXTOID, NUMERICOID,
										  NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID,
										  NUMERICOID, NUMERICOID, NUMERICOID, TEXTOID};
Oid _4_bigint_6_text_sig[] = {INT8OID, INT8OID, INT8OID, INT8OID,
							  TEXTOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID};
Oid text_16_bigint_sig[] = {TEXTOID,
							INT8OID, INT8OID, INT8OID, INT8OID,
							INT8OID, INT8OID, INT8OID, INT8OID,
							INT8OID, INT8OID, INT8OID, INT8OID,
							INT8OID, INT8OID, INT8OID, INT8OID};

Oid _5_bigint_sig[] = { INT8OID, INT8OID, INT8OID, INT8OID, INT8OID };

Oid int_7_numeric_sig[] = { INT4OID, NUMERICOID, NUMERICOID, NUMERICOID,
							NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID };
Oid int_text_int_text_sig[] = { INT4OID, TEXTOID, INT4OID, TEXTOID };
Oid load_avg_sig[] = { FLOAT8OID, FLOAT8OID, FLOAT8OID, INT4OID };

/* proc_diskstats is unique enough to have its own sig */
Oid proc_diskstats_sig[] = {INT8OID, INT8OID, TEXTOID,
							NUMERICOID, NUMERICOID, NUMERICOID, INT8OID,
							NUMERICOID, NUMERICOID, NUMERICOID, INT8OID,
							INT8OID, INT8OID, INT8OID,
							NUMERICOID, NUMERICOID, NUMERICOID, INT8OID,
							NUMERICOID, INT8OID};

/* proc_pid_stat is unique enough to have its own sig */
Oid proc_pid_stat_sig[] = {INT4OID, TEXTOID, TEXTOID, 
						   INT4OID, INT4OID, INT4OID, INT4OID,
						   INT4OID, INT8OID, NUMERICOID, NUMERICOID,
						   NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID,
						   INT8OID, INT8OID, INT8OID, INT8OID,
						   INT8OID, INT8OID, NUMERICOID, NUMERICOID,
						   INT8OID, NUMERICOID, NUMERICOID, NUMERICOID,
						   NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID,
						   NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID,
						   NUMERICOID, NUMERICOID, INT4OID, INT4OID,
						   INT8OID, INT8OID, NUMERICOID, NUMERICOID,
						   INT8OID, NUMERICOID, NUMERICOID, NUMERICOID,
						   NUMERICOID, NUMERICOID, NUMERICOID, NUMERICOID,
						   INT4OID
						  };
Oid num_text_num_2_text_sig[] = {NUMERICOID, TEXTOID,
								 NUMERICOID, TEXTOID, TEXTOID};

/* exported functions */
void _PG_init(void);
void _PG_fini(void);
bool check_string_list(char **newval, void **extra, GucSource source);
Datum pgnodemx_cgroup_mode(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_path(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_process_count(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_scalar_bigint(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_scalar_float8(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_scalar_text(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_setof_bigint(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_setof_text(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_array_text(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_array_bigint(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_setof_kv(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_setof_ksv(PG_FUNCTION_ARGS);
Datum pgnodemx_cgroup_setof_nkv(PG_FUNCTION_ARGS);
Datum pgnodemx_envvar_text(PG_FUNCTION_ARGS);
Datum pgnodemx_envvar_bigint(PG_FUNCTION_ARGS);
Datum pgnodemx_kdapi_setof_kv(PG_FUNCTION_ARGS);
Datum pgnodemx_kdapi_scalar_bigint(PG_FUNCTION_ARGS);

/* exported vars */
bool proc_enabled = false;

/* static functions */
static bool get_string_in_list(char *slist, char *tgtname);
static char*get_session_var(char *sdef, char *objtype, char *objattr, char *sessname);
static void CA_hook(Port *port, int status);

/* static vars */
static ClientAuthentication_hook_type next_client_auth_hook = NULL;

/*
 * Entrypoint of this module.
 */
void
_PG_init(void)
{
	/* Be sure we do initialization only once */
	static bool inited = false;

	if (inited)
		return;

	/* Must be loaded with shared_preload_libraries */
	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						errmsg("pgnodemx: must be loaded via shared_preload_libraries")));

	DefineCustomBoolVariable("pgnodemx.cgroup_enabled",
							 "True if cgroup virtual file system access is enabled",
							 NULL, &cgroup_enabled, true, PGC_POSTMASTER,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("pgnodemx.containerized",
							 "True if operating inside a container",
							 NULL, &containerized, false, PGC_POSTMASTER,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("pgnodemx.cgrouproot",
							   "Path to root cgroup",
							   NULL, &cgrouproot, "/sys/fs/cgroup", PGC_POSTMASTER,
							   0, NULL, NULL, NULL);

	DefineCustomBoolVariable("pgnodemx.subtree_enabled",
							 "True if cgroup subtree management is enabled",
							 NULL, &subtree_enabled, false, PGC_POSTMASTER,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("pgnodemx.default_subtree",
							   "Default cgroup subtree",
							   NULL, &default_subtree, "default", PGC_POSTMASTER,
							   0, NULL, NULL, NULL);

	DefineCustomBoolVariable("pgnodemx.default_subtree_views_parent_path",
							 "True if default subtree views the parent cgroup path",
							 NULL, &default_views_parent, true, PGC_USERSET,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("pgnodemx.databases_with_subtrees",
							   "List of databases with customized cgroup v2 subtrees",
							   NULL, &databases_subtree_string,
							   "", PGC_SIGHUP,
							   0, check_string_list, NULL, NULL);

	DefineCustomStringVariable("pgnodemx.roles_with_subtrees",
							   "List of roles with customized cgroup v2 subtrees",
							   NULL, &roles_subtree_string,
							   "", PGC_SIGHUP,
							   0, check_string_list, NULL, NULL);

	DefineCustomStringVariable("pgnodemx.delegated_controllers",
							   "cgroup controllers delegated to subtrees",
							   NULL, &delegated_controllers, "+cpu +cpuset +memory +io", PGC_POSTMASTER,
							   0, NULL, NULL, NULL);

	DefineCustomBoolVariable("pgnodemx.kdapi_enabled",
							 "True if Kubernetes Downward API file system access is enabled",
							 NULL, &kdapi_enabled, true, PGC_POSTMASTER,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("pgnodemx.kdapi_path",
							   "Path to Kubernetes Downward API files",
							   NULL, &kdapi_path, "/etc/podinfo", PGC_POSTMASTER,
							   0, NULL, NULL, NULL);

	if (set_cgmode())
	{
		/*
		 * If we get this far, we at least know
		 * cgroup_enabled is true and cgmode is not CGROUP_DISABLED
		 */

		/* must determine if containerized before setting cgpath */
		set_containerized();

		/* try to init default subtree if requested */
		if (is_cgroup_v2 && 
			subtree_enabled)
		{
			bool	ret = false;

			ret = init_default_subtree();
			if (!ret)
			{
				/*
				 * If unable to init subtrees, there is not
				 * much else we can do besides disabling subtrees.
				 */
				elog(WARNING, "cannot enable cgroup subtrees");
				subtree_enabled = false;
			}
		}
	}
	else
	{
		/*
		 * If cgmode cannot be set, either because cgroup_enabled is
		 * already set to false, or because of an error trying to stat
		 * cgrouproot, then we must force disable cgroup functions. 
		 */
		cgroup_enabled = false;
	}

	/* force kdapi disabled if path does not exist */
	if (kdapi_enabled && access(kdapi_path, F_OK) != 0)
	{
		/*
		 * If kdapi_path does not exist, there is not
		 * much else we can do besides disabling kdapi access.
		 */
		ereport(WARNING,
				(errcode_for_file_access(),
				errmsg("pgnodemx: Kubernetes Downward API path %s does not exist: %m", kdapi_path),
				errdetail("disabling Kubernetes Downward API file system access")));

		kdapi_enabled = false;
	}

	/*
	 * Check procfs exists.
	 * The "proc" functions are disabled if not.
	 */
	proc_enabled = check_procfs();

	/* Install backend session post-auth hook only if cgroup is enabled */
	if (cgroup_enabled)
	{
		next_client_auth_hook = ClientAuthentication_hook;
		ClientAuthentication_hook = CA_hook;
	}

	inited = true;
}

void
_PG_fini(void)
{
	ClientAuthentication_hook = next_client_auth_hook;
}

/*
 * check_string_list: GUC check_hook
 * check string list: this just checks list syntax,
 *                    not objname validity
 */
bool
check_string_list(char **newval, void **extra, GucSource source)
{
	char		   *rawstring = NULL;
	List		   *elemlist = NIL;
	bool			result = true;

	/* Need a modifiable copy of string */
	rawstring = pstrdup(*newval);

	/* Parse string into list of syscalls */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		GUC_check_errdetail("List syntax is invalid.");
		result = false;
		goto out;
	}

out:
	/* safe to release if NIL */
	list_free(elemlist);

	/* but pfree is not */
	if (rawstring)
		pfree(rawstring);

	return result;
}

static bool
get_string_in_list(char *slist, char *tgtname)
{
	char		   *rawstring = NULL;
	List		   *elemlist = NIL;
	ListCell	   *l;
	bool			result = false;

	if (slist == NULL)
		return result;

	/* Need a modifiable copy */
	rawstring = pstrdup(slist);

	/* Parse string into list of syscalls */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
		goto out;

	/* add syscall specific rules to the filter */
	foreach(l, elemlist)
	{
		char   *listelem = (char *) lfirst(l);

		if (strcmp(listelem, tgtname) == 0)
		{
			result = true;
			goto out;
		}
	}

out:
	/* safe to release if still NIL */
	list_free(elemlist);

	/* but pfree is not */
	if (rawstring)
		pfree(rawstring);

	return result;
}

static char*
get_session_var(char *sdef, char *objtype, char *sessname, char *objattr)
{
	char		 *cfgvarname;
	const char   *ret;

	cfgvarname = psprintf("%s_%s_%s", objtype, sessname, objattr);
	ret = GetConfigOption(cfgvarname, true, false);
	if (ret != NULL)
		return pstrdup(ret);
	else
		return sdef;
}

/*
 * CA_hook
 *
 * Entrypoint of the client authentication hook.
 * It applies the session level cgroup subtree according to GUC settings.
 */
static void
CA_hook(Port *port, int status)
{
	char *session_subtree = NULL;

	/*
	 * If authentication failed, the supplied socket will be
	 * closed soon, so we don't need to do anything here.
	 */
	if (status != STATUS_OK)
	{
		if (next_client_auth_hook)
			(*next_client_auth_hook)(port, status);

		return;
	}

	/*
	 * If database name is in the databases subtree list, look for customized
	 * subtree default for that database
	 */
	if (get_string_in_list(databases_subtree_string, port->database_name))
	{
		int	i;

		session_subtree = get_session_var(NULL, "database",
										  port->database_name,
										  "session.subtree");

		for (i = 0; i < NUM_DELEGATED_OPTIONS; ++i)
		{
			delegated_options_values[i] = get_session_var(NULL, "database",
														  port->database_name,
														  delegated_options[i]);
		}
	}

	/*
	 * If username is in the roles subtree list, look for customized
	 * subtree default for that role. Role subtree values override
	 * database ones.
	 */
	if (get_string_in_list(roles_subtree_string, port->user_name))
	{
		int	i;

		session_subtree = get_session_var(session_subtree, "role",
										  port->user_name,
										  "session.subtree");

		for (i = 0; i < NUM_DELEGATED_OPTIONS; ++i)
		{
			delegated_options_values[i] = get_session_var(NULL, "role",
														  port->user_name,
														  delegated_options[i]);
		}
	}

	/*
	 * If neither database nor role were used to specifiy a subtree, then the
	 * subtree must be the default one, so use that
	 */
	if (session_subtree == NULL)
	{
		int	i;

		session_subtree = default_subtree;

		/*
		 * Ensure we don't use any previously set option values
		 * with the default subtree, since it is supposed to be
		 * unconstrained
		 */
		for (i = 0; i < NUM_DELEGATED_OPTIONS; ++i)
		{
			delegated_options_values[i] = NULL;
		}
	}

	/* If we have a session subtree, and meet other criteria, try to set it now */
	if (is_cgroup_v2 && 
		subtree_enabled &&
		session_subtree &&
		IsUnderPostmaster)
	{
		if(!set_cgroup_subtree(session_subtree))
		{
			/*
			 * If unable to set subtrees, there is not
			 * much else we can do besides disabling them.
			 */
			elog(WARNING, "cannot set cgroup subtree");
			subtree_enabled = false;
		}
	}

	/* set the cgpath for the session */
	set_cgpath();

	if (next_client_auth_hook)
		(*next_client_auth_hook)(port, status);
}

PG_FUNCTION_INFO_V1(pgnodemx_set_subtree);
Datum
pgnodemx_set_subtree(PG_FUNCTION_ARGS)
{
	char	   *req_subtree = text_to_cstring(PG_GETARG_TEXT_PP(0));

	/* If we have a session subtree, and meet other criteria, try to set it now */
	if (is_cgroup_v2 && 
		subtree_enabled &&
		req_subtree &&
		IsUnderPostmaster)
	{
		if(!set_cgroup_subtree(req_subtree))
		{
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					errmsg("pgnodemx: cannot set cgroup subtree %s", req_subtree)));
		}
		else
		{
			/* reset the cgpath for the session */
			set_cgpath();
			PG_RETURN_TEXT_P(cstring_to_text("OK"));
		}
	}
	else
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				errmsg("pgnodemx: prerequisite not met to set cgroup subtree %s", req_subtree)));
}


PG_FUNCTION_INFO_V1(pgnodemx_cgroup_mode);
Datum
pgnodemx_cgroup_mode(PG_FUNCTION_ARGS)
{
	/*
	 * Do not check cgroup_enabled here; this is the one cgroup
	 * function which *should* work when cgroup is disabled.
	 */

	PG_RETURN_TEXT_P(cstring_to_text(cgmode));
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_path);
Datum
pgnodemx_cgroup_path(PG_FUNCTION_ARGS)
{
	char ***values;
	int		nrow;
	int		ncol = 2;
	int		i;

	if (!cgroup_enabled)
		return form_srf(fcinfo, NULL, 0, ncol, text_text_sig);

	nrow = cgpath->nkvp;
	if (nrow < 1)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				errmsg("pgnodemx: no lines in cgpath")));

	/* never reached */

	values = (char ***) palloc(nrow * sizeof(char **));
	for (i = 0; i < nrow; ++i)
	{
		values[i] = (char **) palloc(ncol * sizeof(char *));

		values[i][0] = pstrdup(cgpath->keys[i]);
		values[i][1] = pstrdup(cgpath->values[i]);
	}

	return form_srf(fcinfo, values, nrow, ncol, text_text_sig);
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_process_count);
Datum
pgnodemx_cgroup_process_count(PG_FUNCTION_ARGS)
{
	int64	   *cgpids;

	if (!cgroup_enabled)
		PG_RETURN_NULL();

	/* cgmembers returns pid count */
	PG_RETURN_INT32(cgmembers(&cgpids));
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_scalar_bigint);
Datum
pgnodemx_cgroup_scalar_bigint(PG_FUNCTION_ARGS)
{
	char   *fqpath;

	if (!cgroup_enabled)
		PG_RETURN_NULL();

	fqpath = get_fq_cgroup_path(fcinfo);

	PG_RETURN_INT64(get_int64_from_file(fqpath));
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_scalar_float8);
Datum
pgnodemx_cgroup_scalar_float8(PG_FUNCTION_ARGS)
{
	char   *fqpath;

	if (!cgroup_enabled)
		PG_RETURN_NULL();

	fqpath = get_fq_cgroup_path(fcinfo);

	PG_RETURN_FLOAT8(get_double_from_file(fqpath));
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_scalar_text);
Datum
pgnodemx_cgroup_scalar_text(PG_FUNCTION_ARGS)
{
	char   *fqpath;

	if (!cgroup_enabled)
		PG_RETURN_NULL();

	fqpath = get_fq_cgroup_path(fcinfo);

	PG_RETURN_TEXT_P(cstring_to_text(get_string_from_file(fqpath)));
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_setof_bigint);
Datum
pgnodemx_cgroup_setof_bigint(PG_FUNCTION_ARGS)
{
	char	   *fqpath;

	if (!cgroup_enabled)
		return form_srf(fcinfo, NULL, 0, 1, bigint_sig);

	fqpath = get_fq_cgroup_path(fcinfo);
	return setof_scalar_internal(fcinfo, fqpath, bigint_sig);
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_setof_text);
Datum
pgnodemx_cgroup_setof_text(PG_FUNCTION_ARGS)
{
	char	   *fqpath;

	if (!cgroup_enabled)
		return form_srf(fcinfo, NULL, 0, 1, text_sig);

	fqpath = get_fq_cgroup_path(fcinfo);
	return setof_scalar_internal(fcinfo, fqpath, text_sig);
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_array_text);
Datum
pgnodemx_cgroup_array_text(PG_FUNCTION_ARGS)
{
	char   *fqpath;
	char  **values;
	int		nvals;
	bool	isnull = false;
	Datum	dvalue;

	if (!cgroup_enabled)
		PG_RETURN_NULL();

	fqpath = get_fq_cgroup_path(fcinfo);

	values = parse_space_sep_val_file(fqpath, &nvals);
	dvalue = string_get_array_datum(values, nvals, TEXTOID, &isnull);
	if (!isnull)
		return dvalue;
	else
		PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_array_bigint);
Datum
pgnodemx_cgroup_array_bigint(PG_FUNCTION_ARGS)
{
	char   *fqpath;
	char  **values;
	int		nvals;
	bool	isnull = false;
	Datum	dvalue;
	int		i;

	if (!cgroup_enabled)
		PG_RETURN_NULL();

	fqpath = get_fq_cgroup_path(fcinfo);

	values = parse_space_sep_val_file(fqpath, &nvals);

	/* deal with "max" */
	for (i = 0; i < nvals; ++i)
	{
		if (strcasecmp(values[i], "max") == 0)
			values[i] = int64_to_string(PG_INT64_MAX);
	}

	dvalue = string_get_array_datum(values, nvals, INT8OID, &isnull);
	if (!isnull)
		return dvalue;
	else
		PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_setof_kv);
Datum
pgnodemx_cgroup_setof_kv(PG_FUNCTION_ARGS)
{
	char	   *fqpath;
	int			nlines;
	char	  **lines;
	int			ncol = 2;

	if (!cgroup_enabled)
		return form_srf(fcinfo, NULL, 0, ncol, text_bigint_sig);

	fqpath = get_fq_cgroup_path(fcinfo);
	lines = read_nlsv(fqpath, &nlines);
	if (nlines > 0)
	{
		char	 ***values;
		int			nrow = nlines;
		int			i;

		values = (char ***) palloc(nrow * sizeof(char **));
		for (i = 0; i < nrow; ++i)
		{
			int	ntok;

			values[i] = parse_ss_line(lines[i], &ntok);
			if (ntok != ncol)
				ereport(ERROR,
						(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						errmsg("pgnodemx: expected %d tokens, got %d in flat keyed file %s, line %d",
							   ncol, ntok, fqpath, i + 1)));
		}

		return form_srf(fcinfo, values, nrow, ncol, text_bigint_sig);
	}

	ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
			errmsg("pgnodemx: no lines in flat keyed file: %s ", fqpath)));

	/* never reached */
	return (Datum) 0;
}

/*
 * Some virtual files have multiple rows of three columns:
 * (key text, subkey text, value bigint). They essentially
 * look like nkv, except they only have one subkey and value
 * and no "=" between them. The columns are space separated.
 * They also may have a "grand sum" line that only has two
 * columns because it represents a sum of all the other lines.
 * Two examples of this are blkio.throttle.io_serviced and
 * blkio.throttle.io_service_bytes.
 */
PG_FUNCTION_INFO_V1(pgnodemx_cgroup_setof_ksv);
Datum
pgnodemx_cgroup_setof_ksv(PG_FUNCTION_ARGS)
{
	char	   *fqpath;
	int			nlines;
	char	  **lines;
	int			ncol = 3;

	if (!cgroup_enabled)
		return form_srf(fcinfo, NULL, 0, ncol, text_text_bigint_sig);

	fqpath = get_fq_cgroup_path(fcinfo);
	lines = read_nlsv(fqpath, &nlines);

	if (nlines > 0)
	{
		char	 ***values;
		int			nrow = nlines;
		int			i;

		values = (char ***) palloc(nrow * sizeof(char **));
		for (i = 0; i < nrow; ++i)
		{
			int	ntok;

			values[i] = parse_ss_line(lines[i], &ntok);
			if (ntok > ncol || ntok < ncol - 1)
			{
				ereport(ERROR,
						(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						errmsg("pgnodemx: expected %d tokens, got %d in flat keyed file %s, line %d",
							   ncol, ntok, fqpath, i + 1)));
			}
			else if (ntok == 2)
			{
				/* for the two column case, expand and shift the values right */
				values[i] = (char **) repalloc(values[i], ncol * sizeof(char *));
				values[i][2] = values[i][1];
				values[i][1] = values[i][0];
				values[i][0] = pstrdup("all");
			}
		}

		return form_srf(fcinfo, values, nrow, ncol, text_text_bigint_sig);
	}

	ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
			errmsg("pgnodemx: no lines in flat keyed file: %s ", fqpath)));

	/* never reached */
	return (Datum) 0;
}

PG_FUNCTION_INFO_V1(pgnodemx_cgroup_setof_nkv);
Datum
pgnodemx_cgroup_setof_nkv(PG_FUNCTION_ARGS)
{
	char	   *fqpath;
	int			nlines;
	char	  **lines;
	int			ncol = 3;

	if (!cgroup_enabled)
		return form_srf(fcinfo, NULL, 0, ncol, text_text_float8_sig);

	fqpath = get_fq_cgroup_path(fcinfo);
	lines = read_nlsv(fqpath, &nlines);
	if (nlines > 0)
	{
		char			 ***values;
		int					nrow;
		kvpairs			   *nkl;
		int					nkvp;
		int					i;

		/*
		 * We expect that each line in a "nested keyed" file has the
		 * same number of column. Therefore use the first line of the
		 * parsed file to determine how many columns we have. The entire
		 * line has a key, and each column will consist of a subkey and
		 * value. We will build "number of column" rows from this one line.
		 * Each row in the output will look like (key, subkey, value).
		 */
		nkl = parse_nested_keyed_line(pstrdup(lines[0]));
		nkvp = nkl->nkvp;

		/* each line expands to nkvp - 1 rows in the output */
		nrow = nlines * (nkvp - 1);
		values = (char ***) palloc(nrow * sizeof(char **));

		for (i = 0; i < nlines; ++i)
		{
			int		j;

			nkl = parse_nested_keyed_line(lines[i]);
			if (nkl->nkvp != nkvp)
				ereport(ERROR,
						(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						errmsg("pgnodemx: not nested keyed file: %s ", fqpath)));

			for (j = 1; j < nkvp; ++j)
			{
				values[(i * (nkvp - 1)) + j - 1] = (char **) palloc(ncol * sizeof(char *));

				values[(i * (nkvp - 1)) + j - 1][0] = pstrdup(nkl->values[0]);
				values[(i * (nkvp - 1)) + j - 1][1] = pstrdup(nkl->keys[j]);
				values[(i * (nkvp - 1)) + j - 1][2] = pstrdup(nkl->values[j]);
			}
		}

		return form_srf(fcinfo, values, nrow, ncol, text_text_float8_sig);
	}

	ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
			errmsg("pgnodemx: no lines in nested keyed file: %s ", fqpath)));

	/* never reached */
	return (Datum) 0;
}

PG_FUNCTION_INFO_V1(pgnodemx_envvar_text);
Datum
pgnodemx_envvar_text(PG_FUNCTION_ARGS)
{
	char *varname = text_to_cstring(PG_GETARG_TEXT_PP(0));

	/* Limit use to members of special role */
	pgnodemx_check_role();

	PG_RETURN_TEXT_P(cstring_to_text(get_string_from_env(varname)));
}

PG_FUNCTION_INFO_V1(pgnodemx_envvar_bigint);
Datum
pgnodemx_envvar_bigint(PG_FUNCTION_ARGS)
{
	bool	success = false;
	int64	result;
	char   *varname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char   *value = get_string_from_env(varname);

	/* Limit use to members of special role */
	pgnodemx_check_role();

	success = scanint8(value, true, &result);
	if (!success)
		ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				errmsg("contents not an integer: env variable \"%s\"",
				varname)));

	PG_RETURN_INT64(result);
}

PG_FUNCTION_INFO_V1(pgnodemx_kdapi_setof_kv);
Datum
pgnodemx_kdapi_setof_kv(PG_FUNCTION_ARGS)
{
	char	   *fqpath;
	int			nlines;
	char	  **lines;
	int			ncol = 2;

	if (!kdapi_enabled)
		return form_srf(fcinfo, NULL, 0, ncol, text_text_sig);

	fqpath = get_fq_kdapi_path(fcinfo);
	lines = read_nlsv(fqpath, &nlines);
	if (nlines > 0)
	{
		char	 ***values;
		int			nrow = nlines;
		int			i;

		values = (char ***) palloc(nrow * sizeof(char **));
		for (i = 0; i < nrow; ++i)
		{
			/*
			 * parse_keqv_line always returns two tokens
			 * or throws an error if it cannot.
			 */
			values[i] = parse_keqv_line(lines[i]);
		}

		return form_srf(fcinfo, values, nrow, ncol, text_text_sig);
	}

	ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
			errmsg("pgnodemx: no lines in Kubernetes Downward API file: %s ", fqpath)));

	/* never reached */
	return (Datum) 0;
}

PG_FUNCTION_INFO_V1(pgnodemx_kdapi_scalar_bigint);
Datum
pgnodemx_kdapi_scalar_bigint(PG_FUNCTION_ARGS)
{
	char   *fqpath;

	if (!kdapi_enabled)
		PG_RETURN_NULL();

	fqpath = get_fq_kdapi_path(fcinfo);

	PG_RETURN_INT64(get_int64_from_file(fqpath));
}

PG_FUNCTION_INFO_V1(pgnodemx_fips_mode);
Datum
pgnodemx_fips_mode(PG_FUNCTION_ARGS)
{
	/* Limit use to members of special role */
	pgnodemx_check_role();

#ifdef USE_OPENSSL
#if OPENSSL_VERSION_MAJOR >= 3
	if (EVP_default_properties_is_fips_enabled(NULL))
#else
	if (FIPS_mode())
#endif
		PG_RETURN_BOOL(true);
	else
		PG_RETURN_BOOL(false);
#else
	PG_RETURN_BOOL(false);
#endif
}

PG_FUNCTION_INFO_V1(pgnodemx_openssl_version);
Datum
pgnodemx_openssl_version(PG_FUNCTION_ARGS)
{
	/* Limit use to members of special role */
	pgnodemx_check_role();

#ifdef USE_OPENSSL
	PG_RETURN_TEXT_P(cstring_to_text(OPENSSL_VERSION_TEXT));
#else
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pgnodemx_symbol_filename);
Datum
pgnodemx_symbol_filename(PG_FUNCTION_ARGS)
{
	const char *sym_name = text_to_cstring(PG_GETARG_TEXT_PP(0));
	const void *sym_addr;
	Dl_info		info;  
	int			rc;
	char	   *msg;

	/* Limit use to members of special role */
	pgnodemx_check_role();

	/* according to the man page, clear any residual error message first */
	msg = dlerror();

	/* grab the symbol address using the default path */
	sym_addr = dlsym(RTLD_DEFAULT, sym_name);

	/* any error means we could not find the symbol by this name */
	msg = dlerror();
	if (msg)
		PG_RETURN_NULL();

	/* grab the source library */
	rc = dladdr(sym_addr, &info);
	if (!rc)
		PG_RETURN_NULL();
	else
	{
		char   *tmppath = realpath(info.dli_fname, NULL);
		char   *rpath;

		if (tmppath == NULL)
			PG_RETURN_NULL();

		rpath = pstrdup(tmppath);
		free(tmppath);

		PG_RETURN_TEXT_P(cstring_to_text(rpath));
	}
}

PG_FUNCTION_INFO_V1(pgnodemx_version);
Datum
pgnodemx_version(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(cstring_to_text(GIT_HASH));
}
