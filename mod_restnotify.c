#include "conf.h"
#include "privs.h"
#include <libgen.h>
#include <sys/types.h>
#include "mod_restnotify.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include <curl/curl.h>
//#include <cjson/cJSON.h>
#include <json-c/json.h>
//#include <libxml/encoding.h>
//#include <libxml/xmlwriter.h>


#define MOD_RESTNOTIFY_VERSION "mod_restnotify (lwg)/0.1"
module restnotify_module;


void dump_table(const char *, ...);


// This is a bad idea.  Just wanted to see if it would compile.
// the better solution is to use xmlMemSetup() to define how
// libxml2 should malloc(), realloc(), free(),
// and strdup()...
//xmlBufferPtr mod_restnotify_xmlBufferCreate(void)
//{
//	return xmlBufferCreateStatic(
//		palloc(session.pool,sizeof(xmlBuffer)), 8*1024);
//}

/**
 * Configuration setter: notifyEndpoint
 */
MODRET set_notify_endpoint(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);

  c = add_config_param_str("NotifyEndpoint", 1, (void *) cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

static int handle_upload_table_cb(const void *key, size_t keysz, const void *value,
		size_t valuesz, void *user_data)
{
	//cJSON_AddItemToArray((cJSON*)user_data,cJSON_CreateString((char*)key));
	json_object *file = json_object_new_object();
	json_object_object_add(file,"name",json_object_new_string((char*)key));
	json_object_object_add(file,"size",json_object_new_int64(((struct stat*)value)->st_size));
	//json_object_object_add(file,"lastModified",json_object_new_string(ctime(&(((struct stat*)value)->st_mtim.tv_sec))));
	json_object_object_add(file,"lastModified",json_object_new_int64(((struct stat*)value)->st_mtim.tv_sec*1000));
	json_object_array_add((json_object*)user_data,file);
	pr_log_debug(DEBUG4, MOD_RESTNOTIFY_VERSION ": debug: adding key: %s",
		(char*)key);
	/*
	pr_log_debug(DEBUG4, MOD_RESTNOTIFY_VERSION ": debug: tab[%s](%lu)=%s(%lu)",
			(char*)key, keysz, (char*)value, valuesz);
	*/
	return 0;
}

/**
 * End FTP Session
 */
static void restnotify_shutdown(const void *event_data, void *user_data)
{
	pr_table_t *uploaded_table;

	uploaded_table = (pr_table_t*) pr_table_get(
		session.notes,"mod_restnotify.uloaded",NULL);

	//pr_table_dump((void*) dump_table, (pr_table_t*) uploaded_table);

	if (pr_table_count(uploaded_table)>0)
	{
		pr_log_debug(DEBUG4, MOD_RESTNOTIFY_VERSION ": debug: made it here");

		json_object *msg = json_object_new_object();
		json_object_object_add(msg,"user",json_object_new_string(session.user));
		json_object *filesArray = json_object_new_array();
		//cJSON *msg = cJSON_CreateObject();
		//cJSON *files = cJSON_AddArrayToObject(msg,"files");
		pr_table_do((pr_table_t*)uploaded_table, handle_upload_table_cb, filesArray, 0);

		json_object_object_add(msg,"files",filesArray);

		//cJSON_AddItemToObject(msg,"test",cJSON_CreateString("test"));

		pr_log_debug(DEBUG4, MOD_RESTNOTIFY_VERSION ": debug: JSON: %s",
			json_object_to_json_string(msg));
		
		//cJSON_Delete(msg);


		json_object_put(msg);

		//cJSON_Delete(msg);

		pr_log_debug(DEBUG4, MOD_RESTNOTIFY_VERSION ": debug: made it here too");

		/*
		pr_table_t *upTab = (pr_table_t*) uploaded_table;
		pr_table_rewind(upTab);
		for(void *key=pr_table_next(upTab);NULL!=key;
				key=pr_table_next(upTab))
		{
			const void *value = pr_table_get(upTab, (const char *)key, NULL);
			pr_log_debug(DEBUG4, MOD_RESTNOTIFY_VERSION ": debug: tab[%s]=%s",
				(char *)key, (char *)value);	
		}
		*/
	}

	pr_log_debug(DEBUG4,
		MOD_RESTNOTIFY_VERSION ": debug: finishing up...");
}

/**
 * Start FTP Session
 */
static int restnotify_sess_init(void)
{
	pr_table_t *uploaded_table;

	pr_event_register(&restnotify_module,
		"core.exit", restnotify_shutdown, NULL);


	uploaded_table = pr_table_nalloc(session.pool, 0, 30);
	pr_table_add(session.notes, "mod_restnotify.uloaded",
		uploaded_table, sizeof(uploaded_table));

	pr_log_debug(DEBUG4,
		MOD_RESTNOTIFY_VERSION ": debug: setting up restnotify_sess_init.");

	return 0;
}

MODRET capture_upload(cmd_rec *cmd)
{
	struct stat s;
	const pr_table_t *uploaded_table;

	pr_fsio_stat(cmd->arg, &s);

	pr_log_debug(DEBUG4,
		MOD_RESTNOTIFY_VERSION ": debug: %s uploading %s (size %ld)",
		session.user, cmd->arg, s.st_size);

	uploaded_table = pr_table_get(
		session.notes,"mod_restnotify.uloaded",NULL);

	if (pr_table_exists((pr_table_t*) uploaded_table, cmd->arg) < 1)
	{
		char *fileName = pstrndup(session.pool,cmd->arg,strlen(cmd->arg));

		pr_log_debug(DEBUG4,
			MOD_RESTNOTIFY_VERSION ": debug: adding newly uploaded file: %s",
			fileName);

		pr_table_add_dup((pr_table_t*) uploaded_table,fileName,&s,sizeof(struct stat));
	}

	return PR_DECLINED(cmd);
}


void dump_table(const char *fmt, ...)
{
	char buf[PR_TUNABLE_BUFFER_SIZE + 1];
	va_list msg;

	memset(buf, '\0', sizeof(buf));
	va_start(msg, fmt);

	vsnprintf(buf, (size_t)sizeof(buf), fmt, msg);
	va_end(msg);

	buf[sizeof(buf)-1] = '\0';
	pr_log_debug(DEBUG4,
		MOD_RESTNOTIFY_VERSION ": debug: tabledump: %s",
		buf);
}

MODRET capture_delete(cmd_rec *cmd)
{
	const pr_table_t *uploaded_table;

	uploaded_table = pr_table_get(
		session.notes,"mod_restnotify.uloaded",NULL);

	if (pr_table_exists((pr_table_t*) uploaded_table,cmd->arg) > 0)
	{
		pr_log_debug(DEBUG4,
			MOD_RESTNOTIFY_VERSION ": debug: removing deleted file: %s",
			cmd->arg);

		// Remove the DELEted file name from our table...
		(void) pr_table_remove((pr_table_t*) uploaded_table, cmd->arg, NULL);
	}
	
	return PR_DECLINED(cmd);
}

MODRET capture_rename_to(cmd_rec *cmd)
{
	const char *rnfr_val;

	if (!pr_table_exists(session.notes,"mod_core.rnfr-path"))
	{
		pr_log_debug(DEBUG4,
			MOD_RESTNOTIFY_VERSION ": debug: "
				"received RNTO and mod_core.rnfr-path was blank!");

		return PR_DECLINED(cmd);
	}

	rnfr_val = pr_table_get(
		session.notes,"mod_core.rnfr-path", NULL);

	const pr_table_t *uploaded_table;
	pr_log_debug(DEBUG4,
		MOD_RESTNOTIFY_VERSION ": debug: %s renamed %s to %s",
		session.user, rnfr_val , cmd->arg);

	for(int i=0;i<cmd->argc;i++)
		pr_log_debug(DEBUG4,
			MOD_RESTNOTIFY_VERSION ": debug: cmd.argv[%d]=%s",
			i,
			(char*) cmd->argv[i]);
					
	uploaded_table = pr_table_get(
		session.notes,"mod_restnotify.uloaded",NULL);

	pr_log_debug(DEBUG4,
		MOD_RESTNOTIFY_VERSION ": debug: exists(%s)=%i",
		rnfr_val,
		pr_table_exists((pr_table_t*) uploaded_table,rnfr_val));

	if (pr_table_exists((pr_table_t*) uploaded_table,rnfr_val) > 0)
	{
		pr_log_debug(DEBUG4,
			MOD_RESTNOTIFY_VERSION ": debug: removing RNFR file: %s",
			rnfr_val);

		// Remove the RNFR or renamed from file name from our table...
		const struct stat *file_stat = pr_table_remove((pr_table_t*) uploaded_table, rnfr_val, NULL);

		char *newFileName = pstrndup(
			session.pool,cmd->arg,strlen(cmd->arg)+1);

		pr_log_debug(DEBUG4,
			MOD_RESTNOTIFY_VERSION ": debug: kexists(%s)=%i",
			newFileName,
			pr_table_exists((pr_table_t*) uploaded_table, newFileName));

		// Only add the "renamed to" file if it doesn't already exist.
		if (pr_table_exists((pr_table_t*) uploaded_table,newFileName) < 1)
		{
			pr_log_debug(DEBUG4,
				MOD_RESTNOTIFY_VERSION ": debug adding RNTO %s",
				newFileName);

			(void) pr_table_add((pr_table_t*) uploaded_table, newFileName,
				file_stat, sizeof(struct stat));

			pr_log_debug(DEBUG4,
				MOD_RESTNOTIFY_VERSION ": debug  RNTO filesize=%lu",
				file_stat->st_size);
		}
	}

	//pr_table_dump((void*) dump_table, (pr_table_t*) uploaded_table);

	return PR_DECLINED(cmd);
}


static conftable restnotify_conftab[] = {
  { "NotifyEndpoint", set_notify_endpoint, NULL },
  { NULL }
};

static cmdtable restnotify_cmdtab[] = {
   { POST_CMD, C_STOR, G_NONE, capture_upload, TRUE, FALSE },
   { POST_CMD, C_STOU, G_NONE, capture_upload, TRUE, FALSE },
   { POST_CMD, C_APPE, G_NONE, capture_upload, TRUE, FALSE },
   { POST_CMD, C_RNTO, G_NONE, capture_rename_to, TRUE, FALSE },
	{ POST_CMD, C_DELE, G_NONE, capture_delete, TRUE, FALSE },
   { 0, NULL }
};

module restnotify_module =
{
	NULL,              /* Always NULL */
	NULL,              /* Always NULL */
	0x20,              /* module api version */
	"restnotify",       /* module name */
	restnotify_conftab, /* module configuration handler table */
	restnotify_cmdtab,  /* module command handler table */
	NULL,              /* module authentication handler table */
	NULL,              /* module initialization */
	restnotify_sess_init,  /* session initialization */
	MOD_RESTNOTIFY_VERSION /* module version */
};
