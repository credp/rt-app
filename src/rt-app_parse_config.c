/*
This file is part of rt-app - https://launchpad.net/rt-app
Copyright (C) 2010  Giacomo Bagnoli <g.bagnoli@asidev.com>
Copyright (C) 2014  Juri Lelli <juri.lelli@gmail.com>
Copyright (C) 2014  Vincent Guittot <vincent.guittot@linaro.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* for CPU_SET macro */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <json-c/json.h>

#include "rt-app_utils.h"
#include "rt-app_parse_config.h"

#define PFX "[json] "
#define PFL "         "PFX
#define PIN PFX"    "
#define PIN2 PIN"    "
#define PIN3 PIN2"    "
#define JSON_FILE_BUF_SIZE 4096
#define DEFAULT_MEM_BUF_SIZE (4 * 1024 * 1024)

#ifndef TRUE
#define TRUE true
#define FALSE false
#endif

/* redefine foreach as in <json/json_object.h> but to be ANSI
 * compatible */
#define foreach(obj, entry, key, val, idx)				\
	for ( ({ idx = 0; entry = json_object_get_object(obj)->head;});	\
		({ if (entry) { key = (char*)entry->k;			\
				val = (struct json_object*)entry->v;	\
			      };					\
		   entry;						\
		 }							\
		);							\
		({ entry = entry->next; idx++; })			\
	    )
/* this macro set a default if key not present, or give an error and exit
 * if key is present but does not have a default */
#define set_default_if_needed(key, value, have_def, def_value) do {	\
	if (!value) {							\
		if (have_def) {						\
			log_info(PIN "key: %s <default> %d", key, def_value);\
			return def_value;				\
		} else {						\
			log_critical(PFX "Key %s not found", key);	\
			exit(EXIT_INV_CONFIG);				\
		}							\
	}								\
} while(0)

/* same as before, but for string, for which we need to strdup in the
 * default value so it can be a literal */
#define set_default_if_needed_str(key, value, have_def, def_value) do {	\
	if (!value) {							\
		if (have_def) {						\
			if (!def_value) {				\
				log_info(PIN "key: %s <default> NULL", key);\
				return NULL;				\
			}						\
			log_info(PIN "key: %s <default> %s",		\
				  key, def_value);			\
			return strdup(def_value);			\
		} else {						\
			log_critical(PFX "Key %s not found", key);	\
			exit(EXIT_INV_CONFIG);				\
		}							\
	}								\
}while (0)

/* get an object obj and check if its type is <type>. If not, print a message
 * (this is what parent and key are used for) and exit
 */
static inline void
assure_type_is(struct json_object *obj,
	       struct json_object *parent,
	       const char *key,
	       enum json_type type)
{
	if (!json_object_is_type(obj, type)) {
		log_critical("Invalid type for key %s", key);
		log_critical("%s", json_object_to_json_string(parent));
		exit(EXIT_INV_CONFIG);
	}
}

/* search a key (what) in object "where", and return a pointer to its
 * associated object. If nullable is false, exit if key is not found */
static inline struct json_object*
get_in_object(struct json_object *where,
	      const char *what,
	      int nullable)
{
	struct json_object *to;
	json_bool ret;
	ret = json_object_object_get_ex(where, what, &to);
	if (!nullable && !ret) {
		log_critical(PFX "Error while parsing config\n" PFL);
		exit(EXIT_INV_CONFIG);
	}
	if (!nullable && strcmp(json_object_to_json_string(to), "null") == 0) {
		log_critical(PFX "Cannot find key %s", what);
		exit(EXIT_INV_CONFIG);
	}
	return to;
}

static inline int
get_int_value_from(struct json_object *where,
		   const char *key,
		   int have_def,
		   int def_value)
{
	struct json_object *value;
	int i_value;
	value = get_in_object(where, key, have_def);
	set_default_if_needed(key, value, have_def, def_value);
	assure_type_is(value, where, key, json_type_int);
	i_value = json_object_get_int(value);
	log_info(PIN "key: %s, value: %d, type <int>", key, i_value);
	return i_value;
}

static inline int
get_bool_value_from(struct json_object *where,
		    const char *key,
		    int have_def,
		    int def_value)
{
	struct json_object *value;
	int b_value;
	value = get_in_object(where, key, have_def);
	set_default_if_needed(key, value, have_def, def_value);
	assure_type_is(value, where, key, json_type_boolean);
	b_value = json_object_get_boolean(value);
	log_info(PIN "key: %s, value: %d, type <bool>", key, b_value);
	return b_value;
}

static inline char*
get_string_value_from(struct json_object *where,
		      const char *key,
		      int have_def,
		      const char *def_value)
{
	struct json_object *value;
	char *s_value;
	value = get_in_object(where, key, have_def);
	set_default_if_needed_str(key, value, have_def, def_value);
	if (json_object_is_type(value, json_type_null)) {
		log_info(PIN "key: %s, value: NULL, type <string>", key);
		return NULL;
	}
	assure_type_is(value, where, key, json_type_string);
	s_value = strdup(json_object_get_string(value));
	log_info(PIN "key: %s, value: %s, type <string>", key, s_value);
	return s_value;
}

static void init_mutex_resource(rtapp_resource_t *data, const rtapp_options_t *opts)
{
	log_info(PIN3 "Init: %s mutex", data->name);

	pthread_mutexattr_init(&data->res.mtx.attr);
	if (opts->pi_enabled) {
		pthread_mutexattr_setprotocol(
				&data->res.mtx.attr,
				PTHREAD_PRIO_INHERIT);
	}
	pthread_mutex_init(&data->res.mtx.obj,
			&data->res.mtx.attr);
}

static void init_timer_resource(rtapp_resource_t *data, const rtapp_options_t *opts)
{
	log_info(PIN3 "Init: %s timer", data->name);
	data->res.timer.init = 0;
	data->res.timer.relative = 1;
}

static void init_cond_resource(rtapp_resource_t *data, const rtapp_options_t *opts)
{
	log_info(PIN3 "Init: %s wait", data->name);

	pthread_condattr_init(&data->res.cond.attr);
	pthread_cond_init(&data->res.cond.obj,
			&data->res.cond.attr);
}

static void init_membuf_resource(rtapp_resource_t *data, const rtapp_options_t *opts)
{
	log_info(PIN3 "Init: %s membuf", data->name);

	data->res.buf.ptr = malloc(opts->mem_buffer_size);
	data->res.buf.size = opts->mem_buffer_size;
}

static void init_iodev_resource(rtapp_resource_t *data, const rtapp_options_t *opts)
{
	log_info(PIN3 "Init: %s io device", data->name);

	data->res.dev.fd = open(opts->io_device, O_CREAT | O_WRONLY, 0644);
}

static void init_barrier_resource(rtapp_resource_t *data, const rtapp_options_t *opts)
{
	log_info(PIN3 "Init: %s barrier", data->name);

	/* each task waiting for this resource will increment this counter.
	 * start at -1 so that when we see this is zero we are the last man
	 * to enter the sync point and should wake everyone else.
	 */
	data->res.barrier.waiting = -1;
	pthread_mutexattr_init(&data->res.barrier.m_attr);
	if (opts->pi_enabled) {
		pthread_mutexattr_setprotocol(
				&data->res.barrier.m_attr,
				PTHREAD_PRIO_INHERIT);
	}
	pthread_mutex_init(&data->res.barrier.m_obj,
			&data->res.barrier.m_attr);

	pthread_cond_init(&data->res.barrier.c_obj, NULL);
}

static void
init_resource_data(const char *name, int type, int idx, const rtapp_options_t *opts)
{
	rtapp_resource_t *data = &(opts->resources[idx]);

	/* common and defaults */
	data->index = idx;
	data->name = strdup(name);
	data->type = type;

	switch (data->type) {
		case rtapp_mutex:
			init_mutex_resource(data, opts);
			break;
		case rtapp_timer:
			init_timer_resource(data, opts);
			break;
		case rtapp_wait:
			init_cond_resource(data, opts);
			break;
		case rtapp_mem:
			init_membuf_resource(data, opts);
			break;
		case rtapp_iorun:
			init_iodev_resource(data, opts);
			break;
		case rtapp_barrier:
			init_barrier_resource(data, opts);
			break;
		default:
			break;
	}
}

static void
parse_resource_data(const char *name, struct json_object *obj, int idx,
		  rtapp_resource_t *data, const rtapp_options_t *opts)
{
	char *type;
	char def_type[RTAPP_RESOURCE_DESCR_LENGTH];

	log_info(PFX "Parsing resources %s [%d]", name, idx);

	/* resource type */
	resource_to_string(0, def_type);
	type = get_string_value_from(obj, "type", TRUE, def_type);
	if (string_to_resource(type, &data->type) != 0) {
		log_critical(PIN2 "Invalid type of resource %s", type);
		exit(EXIT_INV_CONFIG);
	}

	/*
	 * get_string_value_from allocate the string so with have to free it
	 * once useless
	 */
	free(type);

	init_resource_data(name, data->type, idx, opts);
}

static int
add_resource_data(const char *name, int type, rtapp_options_t *opts)
{
	int idx;

	idx = opts->nresources;

	log_info(PIN2 "Add new resource %s [%d] type %d", name, idx, type);

	opts->nresources++;
	opts->resources = realloc(opts->resources, sizeof(rtapp_resource_t) * opts->nresources);

	init_resource_data(name, type, idx, opts);

	return idx;
}

static void
parse_resources(struct json_object *resources, rtapp_options_t *opts)
{
	struct lh_entry *entry; char *key; struct json_object *val; int idx;

	log_info(PFX "Parsing resource section");

	if (!resources) {
		log_info(PFX "No resource section Found");
		return;
	}

	if (json_object_is_type(resources, json_type_object)) {
		opts->nresources = 0;
		foreach(resources, entry, key, val, idx) {
			opts->nresources++;
		}

		log_info(PFX "Found %d Resources", opts->nresources);
		opts->resources = malloc(sizeof(rtapp_resource_t) * opts->nresources);

		foreach (resources, entry, key, val, idx) {
			parse_resource_data(key, val, idx, &opts->resources[idx], opts);
		}
	}
}

static int get_resource_index(const char *name, int type, rtapp_options_t *opts)
{
	rtapp_resource_t *resources = opts->resources;
	int nresources = opts->nresources;
	int i = 0;

	while ((i < nresources) && ((strcmp(resources[i].name, name) != 0) || (resources[i].type != type)))
		i++;

	if (i >= nresources)
		i = add_resource_data(name, type, opts);

	return i;
}

static char* create_unique_name(char *tmp, int size, const char* ref, long tag)
{
	snprintf(tmp, size, "%s%lx", ref, (long)(tag));
	return tmp;
}

static int
_strncmp_strlen(const char *event_name, const char *match)
{
	return strncmp(event_name, match, strlen(match));
}

#define name_starts(m) !_strncmp_strlen(name, m)

static int
parse_valid_int(int *dest, struct json_object *obj)
{
	if (!json_object_is_type(obj, json_type_int))
		return 0;
	*dest = json_object_get_int(obj);
	return -1;
}

/*
 * pted_* functions:
 * All these functions are called from the parse_event_thread_data
 * loop. In order to avoid having a single large function as the number
 * of event types has grown, give each type (potentially) its own.
 * All of these functions should return 0 for success, anything else
 * for failure.
 */
static int
pted_runtime(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	if (!parse_valid_int(&data->duration, obj))
		return -1;
	log_info(PIN2 "type %d duration %d", data->type, data->duration);
	return 0;
}

static int
pted_mem(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	char unique_name[22];
	const char *ref;

	if (!parse_valid_int(&data->count, obj))
		return -1;

	/* create an unique name for per-thread buffer */
	ref = create_unique_name(unique_name, sizeof(unique_name), "mem", tag);
	data->res = get_resource_index(ref, rtapp_mem, opts);

	log_info(PIN2 "type %d count %d", data->type, data->count);
	return 0;
}

static int
pted_iorun(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	int i;

	if (pted_mem(obj, data, opts, tag))
		return -1;

	/* A single IO devices for all threads */
	data->dep = get_resource_index("io_device", rtapp_iorun, opts);

	/* no additional log_info, pted_mem has the same info */
	return 0;
}

static int
pted_lock(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata, *ddata;
	const char *ref;

	if (!json_object_is_type(obj, json_type_string))
		return -1;

	ref = json_object_get_string(obj);
	data->res = get_resource_index(ref, rtapp_mutex, opts);

	rdata = &(opts->resources[data->res]);
	ddata = &(opts->resources[data->dep]);
	log_info(PIN2 "type %d target %s [%d]", data->type, rdata->name, rdata->index);

	return 0;
}

static int
pted_signal(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata, *ddata;
	const char *ref;
	int i;

	if (!json_object_is_type(obj, json_type_string))
		return -1;

	ref = json_object_get_string(obj);
	data->res = get_resource_index(ref, rtapp_wait, opts);

	rdata = &(opts->resources[data->res]);
	ddata = &(opts->resources[data->dep]);
	log_info(PIN2 "type %d target %s [%d]", data->type, rdata->name, rdata->index);

	return 0;
}

static int
pted_wait(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata, *ddata;
	char *tmp;
	int i;

	tmp = get_string_value_from(obj, "ref", TRUE, "unknown");
	i = get_resource_index(tmp, rtapp_wait, opts);
	/*
	 * get_string_value_from allocate the string so with have to free it
	 * once useless
	 */
	free(tmp);
	data->res = i;

	tmp = get_string_value_from(obj, "mutex", TRUE, "unknown");
	i = get_resource_index(tmp, rtapp_mutex, opts);
	/*
	 * get_string_value_from allocate the string so with have to free it
	 * once useless
	 */
	free(tmp);
	data->dep = i;

	rdata = &(opts->resources[data->res]);
	ddata = &(opts->resources[data->dep]);
	log_info(PIN2 "type %d target %s [%d] mutex %s [%d]", data->type, rdata->name, rdata->index, ddata->name, ddata->index);

	return 0;
}

static int
pted_barrier(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata;
	const char *ref;

	if (!json_object_is_type(obj, json_type_string))
		return -1;

	ref = json_object_get_string(obj);
	data->res = get_resource_index(ref, rtapp_barrier, opts);
	rdata = &(opts->resources[data->res]);
	rdata->res.barrier.waiting += 1;

	log_info(PIN2 "type %d target %s [%d] %d users so far", data->type, rdata->name, rdata->index, rdata->res.barrier.waiting);

	return 0;
}

static int
pted_timer(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata, *ddata;
	char unique_name[22];
	const char *ref;
	char *tmp;
	int i = 0;

	tmp = get_string_value_from(obj, "ref", TRUE, "unknown");
	if (!_strncmp_strlen(tmp, "unique"))
		ref = create_unique_name(unique_name, sizeof(unique_name), tmp, tag);
	else
		ref = tmp;

	i = get_resource_index(ref, rtapp_timer, opts);

	/*
	 * get_string_value_from allocate the string so with have to free it
	 * once useless
	 */
	free(tmp);

	data->res = i;
	data->duration = get_int_value_from(obj, "period", TRUE, 0);

	rdata = &(opts->resources[data->res]);
	ddata = &(opts->resources[data->dep]);

	tmp = get_string_value_from(obj, "mode", TRUE, "relative");
	if (!_strncmp_strlen(tmp, "absolute"))
		rdata->res.timer.relative = 0;
	free(tmp);

	log_info(PIN2 "type %d target %s [%d] period %d", data->type, rdata->name, rdata->index, data->duration);
	return 0;
}

static int
pted_resume(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata, *ddata;
	const char *ref;

	if (!json_object_is_type(obj, json_type_string))
		return -1;

	ref = json_object_get_string(obj);
	data->res = get_resource_index(ref, rtapp_wait, opts);
	data->dep = get_resource_index(ref, rtapp_mutex, opts);

	rdata = &(opts->resources[data->res]);
	ddata = &(opts->resources[data->dep]);
	log_info(PIN2 "type %d target %s [%d] mutex %s [%d]", data->type, rdata->name, rdata->index, ddata->name, ddata->index);

	return 0;
}

/* just log out the event creation, it owns no data beyond type */
static int
pted_empty(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	log_info(PIN2 "type %d", data->type);
	return 0;
}

static int
pted_fork(struct json_object *obj, event_data_t *data,
	     rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata;
	const char *ref;

	if (!json_object_is_type(obj, json_type_string))
		return -1;

	ref = json_object_get_string(obj);
	data->res = get_resource_index(ref, rtapp_fork, opts);

	rdata = &(opts->resources[data->res]);
	rdata->res.fork.ref = strdup(ref);
	rdata->res.fork.tdata = NULL;
	rdata->res.fork.nforks = 0;

	if (!rdata->res.fork.ref) {
		log_error("Failed to duplicate ref");
		exit(EXIT_FAILURE);
	}

	log_info(PIN2 "type %d target %s [%d]", data->type, rdata->name, rdata->index);
	return 0;
}

/*
 * parser_items
 * an array of pted_* name prefix, type and parser function pointers
 *
 * This struct is used in the parser loop - each thread event
 * item from the config file is compared against each prefix
 * in order. When we find a prefix which matches the start of
 * the event name, we set the event->type to the stored type
 * and then call the stored function pointer.
 * It is also used in obj_is_event.
 *
 * Ordering is important here since we only compare the
 * beginning of the event name for the length of the prefix in
 * this array - for example, run comes after runtime so we can
 * tell them apart at parse time.
 *
 * At startup, we call validate_parser_item_array to complain if
 * this table is not ordered correctly.
 */
struct {
	const char *	prefix;
	resource_t	type;
	int (*handler)(struct json_object *obj, event_data_t *data,
			rtapp_options_t *opts, long tag);
} parser_items[] = {
	{ "runtime",	rtapp_runtime,	&pted_runtime },
	{ "run",	rtapp_run,	&pted_runtime },
	{ "sleep",	rtapp_sleep,	&pted_runtime },
	{ "mem",	rtapp_mem,	&pted_mem },
	{ "iorun",	rtapp_iorun,	&pted_iorun },
	{ "lock",	rtapp_lock,	&pted_lock },
	{ "unlock",	rtapp_unlock,	&pted_lock },
	{ "signal",	rtapp_signal,	&pted_signal },
	{ "broad",	rtapp_broadcast, &pted_signal },
	{ "wait",	rtapp_wait,	&pted_wait },
	{ "sync", 	rtapp_sig_and_wait, &pted_wait },
	{ "barrier",	rtapp_barrier,	&pted_barrier },
	{ "timer",	rtapp_timer,	&pted_timer },
	{ "resume",	rtapp_resume,	&pted_resume },
	{ "suspend",	rtapp_suspend,	&pted_resume },
	{ "yield",	rtapp_yield,	&pted_empty },
	{ "fork",	rtapp_fork,	&pted_fork },
	{ NULL,		rtapp_unknown,  NULL}
};

/* check invariant string match - no previous strings should be substrings */
int
validate_parser_item_array(void)
{
	int x, i = 0, err = 0;

	while (parser_items[i].prefix) {
		x = i+1;
		while (parser_items[x].prefix) {
			if (!_strncmp_strlen(parser_items[x].prefix, parser_items[i].prefix)) {
				log_error("string table incorrectly ordered. Item %d is a substring of item %d", i, x);
				err++;
			}
			x++;
		}
		i++;
	}
	return(err == 0);
}

static void
parse_thread_event_data(char *name, struct json_object *obj,
		  event_data_t *data, rtapp_options_t *opts, long tag)
{
	rtapp_resource_t *rdata, *ddata;
	char unique_name[22];
	const char *ref;
	char *tmp;
	int i = 0;

	while (parser_items[i].prefix) {
		if(name_starts(parser_items[i].prefix)) {
			data->type = parser_items[i].type;
			if (parser_items[i].handler(obj, data, opts, tag))
				goto unknown_event;
			return;
		}
		i++;
	};

	log_error(PIN2 "Resource %s not found in the resource section !!!", ref);
	log_error(PIN2 "Please check the resource name or the resource section");

unknown_event:
	data->duration = 0;
	data->type = rtapp_run;
	log_error(PIN2 "Unknown or mismatch %s event type !!!", name);
}

static int
obj_is_event(char *name)
{
	const char *event;
	int i = 0;
	do{
		event = parser_items[i++].prefix;
		if (!strncmp(name, event, strlen(event)))
			return 1;
	} while(event);
	return 0;
}

static void parse_cpuset_data(struct json_object *obj, cpuset_data_t *data)
{
	struct json_object *cpuset_obj, *cpu;
	unsigned int max_cpu = sysconf(_SC_NPROCESSORS_CONF) - 1;

	/* cpuset */
	cpuset_obj = get_in_object(obj, "cpus", TRUE);
	if (cpuset_obj) {
		unsigned int i;
		unsigned int cpu_idx;

		assure_type_is(cpuset_obj, obj, "cpus", json_type_array);
		data->cpuset_str = strdup(json_object_to_json_string(cpuset_obj));
		data->cpusetsize = sizeof(cpu_set_t);
		data->cpuset = malloc(data->cpusetsize);
		CPU_ZERO(data->cpuset);
		for (i = 0; i < json_object_array_length(cpuset_obj); i++) {
			cpu = json_object_array_get_idx(cpuset_obj, i);
			cpu_idx = json_object_get_int(cpu);
			if (cpu_idx > max_cpu) {
				log_critical(PIN2 "Invalid cpu %u in cpuset %s", cpu_idx, data->cpuset_str);
				free(data->cpuset);
				free(data->cpuset_str);
				exit(EXIT_INV_CONFIG);
			}
			CPU_SET(cpu_idx, data->cpuset);
		}
	} else {
		data->cpuset_str = strdup("-");
		data->cpuset = NULL;
		data->cpusetsize = 0;
	}
	log_info(PIN "key: cpus %s", data->cpuset_str);
}

static sched_data_t *parse_sched_data(struct json_object *obj, int def_policy)
{
	sched_data_t tmp_data;
	char *def_str_policy;
	char *policy;
	int prior_def = -1;

	/* Get default policy */
	def_str_policy = policy_to_string(def_policy);

	/* Get Policy */
	policy = get_string_value_from(obj, "policy", TRUE, def_str_policy);
	if (policy ){
		if (string_to_policy(policy, &tmp_data.policy) != 0) {
			log_critical(PIN2 "Invalid policy %s", policy);
			exit(EXIT_INV_CONFIG);
		}
	} else {
		tmp_data.policy = -1;
	}

	/* Get priority */
	if (tmp_data.policy == -1)
		prior_def = -1;
	else if (tmp_data.policy == other || tmp_data.policy == idle)
		prior_def = DEFAULT_THREAD_NICE;
	else
		prior_def = DEFAULT_THREAD_PRIORITY;

	tmp_data.prio = get_int_value_from(obj, "priority", TRUE, prior_def);

	/* deadline params */
	tmp_data.runtime = get_int_value_from(obj, "dl-runtime", TRUE, 0);
	tmp_data.period = get_int_value_from(obj, "dl-period", TRUE, tmp_data.runtime);
	tmp_data.deadline = get_int_value_from(obj, "dl-deadline", TRUE, tmp_data.period);


	if (def_policy != -1) {
		/* Support legacy grammar for thread object */
		if (!tmp_data.runtime)
			tmp_data.runtime = get_int_value_from(obj, "runtime", TRUE, 0);
		if (!tmp_data.period)
			tmp_data.period = get_int_value_from(obj, "period", TRUE, tmp_data.runtime);
		if (!tmp_data.deadline)
			tmp_data.deadline = get_int_value_from(obj, "deadline", TRUE, tmp_data.period);
	}

	/* Move from usec to nanosec */
	tmp_data.runtime *= 1000;
	tmp_data.period *= 1000;
	tmp_data.deadline *= 1000;

	/* Check if we found at least one meaningful scheduler parameter */
	if (tmp_data.prio != -1 || tmp_data.runtime || tmp_data.period || tmp_data.period) {
		sched_data_t *new_data;

		/* At least 1 parameters has been set in the object */
		new_data = malloc(sizeof(sched_data_t));
		memcpy( new_data, &tmp_data,sizeof(sched_data_t));

		log_debug(PIN "key: set scheduler %d with priority %d", new_data->policy, new_data->prio);

		return new_data;
	}

	return NULL;
}

static void
parse_thread_phase_data(struct json_object *obj,
		  phase_data_t *data, rtapp_options_t *opts, long tag)
{
	/* used in the foreach macro */
	struct lh_entry *entry; char *key; struct json_object *val; int idx;
	int i;

	/* loop */
	data->loop = get_int_value_from(obj, "loop", TRUE, 1);

	/* Count number of events */
	data->nbevents = 0;
	foreach(obj, entry, key, val, idx) {
		if (obj_is_event(key))
				data->nbevents++;
	}

	if (data->nbevents == 0) {
		log_critical(PIN "No events found. Task must have events or it's useless");
		exit(EXIT_INV_CONFIG);

	}

	log_info(PIN "Found %d events", data->nbevents);

	data->events = malloc(data->nbevents * sizeof(event_data_t));

	/* Parse events */
	i = 0;
	foreach(obj, entry, key, val, idx) {
		if (obj_is_event(key)) {
			log_info(PIN "Parsing event %s", key);
			parse_thread_event_data(key, val, &data->events[i], opts, tag);
			i++;
		}
	}
	parse_cpuset_data(obj, &data->cpu_data);
	data->sched_data = parse_sched_data(obj, -1);

}

static void
parse_thread_data(char *name, struct json_object *obj, int index,
		  thread_data_t *data, rtapp_options_t *opts)
{
	struct json_object *phases_obj, *resources;

	log_info(PFX "Parsing thread %s [%d]", name, index);

	/* common and defaults */
	data->resources = &opts->resources;
	data->ind = index;
	data->name = strdup(name);
	data->lock_pages = opts->lock_pages;

	data->cpu_data.cpuset = NULL;
	data->cpu_data.cpuset_str = NULL;
	data->curr_cpu_data = NULL;
	data->def_cpu_data.cpuset = NULL;
	data->def_cpu_data.cpuset_str = NULL;

	data->curr_sched_data = NULL;

	/* cpuset */
	parse_cpuset_data(obj, &data->cpu_data);
	/* Scheduling policy */
	data->sched_data = parse_sched_data(obj, opts->policy);

	/* initial delay */
	data->delay = get_int_value_from(obj, "delay", TRUE, 0);

	/* It's the responsibility of the caller to set this if we were forked */
	data->forked = 0;
	data->num_instances = get_int_value_from(obj, "instance", TRUE, 1);

	/* Get phases */
	phases_obj = get_in_object(obj, "phases", TRUE);
	if (phases_obj) {
		/* used in the foreach macro */
		struct lh_entry *entry; char *key; struct json_object *val; int idx;

		assure_type_is(phases_obj, obj, "phases",
					json_type_object);

		log_info(PIN "Parsing phases section");
		data->nphases = 0;
		foreach(phases_obj, entry, key, val, idx) {
			data->nphases++;
		}

		log_info(PIN "Found %d phases", data->nphases);
		data->phases = malloc(sizeof(phase_data_t) * data->nphases);
		foreach(phases_obj, entry, key, val, idx) {
			log_info(PIN "Parsing phase %s", key);
			assure_type_is(val, phases_obj, key, json_type_object);
			parse_thread_phase_data(val, &data->phases[idx], opts, (long)data);
		}

		/* Get loop number */
		data->loop = get_int_value_from(obj, "loop", TRUE, -1);

	} else {
		data->nphases = 1;
		data->phases = malloc(sizeof(phase_data_t) * data->nphases);
		parse_thread_phase_data(obj,  &data->phases[0], opts, (long)data);

		/* There is no "phases" object which means that thread and phase will
		 * use same scheduling parameters. But thread object looks for default
		 * value when parameters are not defined whereas phase doesn't.
		 * We remove phase's scheduling policy which is a subset of thread's one
		 */
		free(data->phases[0].sched_data);
		data->phases[0].sched_data = NULL;

		/*
		 * Get loop number:
		 *
		 * If loop is specified, we already parsed it in
		 * parse_thread_phase_data() above, so we just need to remember
		 * that we don't want to loop forever.
		 *
		 * If not specified we want to loop forever.
		 *
		 */
		if (get_in_object(obj, "loop", TRUE))
			data->loop = 1;
		else
			data->loop = -1;
	}

}

static void
parse_tasks(struct json_object *tasks, rtapp_options_t *opts)
{
	/* used in the foreach macro */
	struct lh_entry *entry; char *key; struct json_object *val; int idx;

	int i = 0;
	int instance;

	log_info(PFX "Parsing tasks section");
	opts->nthreads = 0;
	opts->num_tasks = 0;
	foreach(tasks, entry, key, val, idx) {
		instance = get_int_value_from(val, "instance", TRUE, 1);
		opts->nthreads += instance;

		opts->num_tasks++;
	}

	log_info(PFX "Found %d tasks", opts->nthreads);

	/*
	 * Parse thread data of defined tasks so that we can use them later
	 * when creating the tasks at main() and fork event.
	 */
	opts->threads_data = malloc(sizeof(thread_data_t) * opts->num_tasks);
	foreach (tasks, entry, key, val, idx)
		parse_thread_data(key, val, -1, &opts->threads_data[i++], opts);
}

static void
parse_global(struct json_object *global, rtapp_options_t *opts)
{
	char *policy, *tmp_str;
	struct json_object *tmp_obj;
	int scan_cnt;

	log_info(PFX "Parsing global section");

	if (!global) {
		log_info(PFX " No global section Found: Use default value");
		opts->duration = -1;
		opts->gnuplot = 0;
		opts->policy = other;
		opts->calib_cpu = 0;
		opts->calib_ns_per_loop = 0;
		opts->logdir = strdup("./");
		opts->logbasename = strdup("rt-app");
		opts->logsize = 0;
		opts->ftrace = 0;
		opts->lock_pages = 1;
		opts->pi_enabled = 0;
		opts->io_device = strdup("/dev/null");
		opts->mem_buffer_size = DEFAULT_MEM_BUF_SIZE;
		opts->cumulative_slack = 0;
		return;
	}

	opts->duration = get_int_value_from(global, "duration", TRUE, -1);
	opts->gnuplot = get_bool_value_from(global, "gnuplot", TRUE, 0);
	policy = get_string_value_from(global, "default_policy",
				       TRUE, "SCHED_OTHER");
	if (string_to_policy(policy, &opts->policy) != 0) {
		log_critical(PFX "Invalid policy %s", policy);
		exit(EXIT_INV_CONFIG);
	}
	/*
	 * get_string_value_from allocate the string so with have to free it
	 * once useless
	 */
	free(policy);

	tmp_obj = get_in_object(global, "calibration", TRUE);
	if (tmp_obj == NULL) {
		/* no setting ? Calibrate CPU0 */
		opts->calib_cpu = 0;
		opts->calib_ns_per_loop = 0;
		log_error("missing calibration setting force CPU0");
	} else {
		if (json_object_is_type(tmp_obj, json_type_int)) {
			/* integer (no " ") detected. */
			opts->calib_ns_per_loop = json_object_get_int(tmp_obj);
			log_debug("ns_per_loop %d", opts->calib_ns_per_loop);
		} else {
			/* Get CPU number */
			tmp_str = get_string_value_from(global, "calibration",
					 TRUE, "CPU0");
			scan_cnt = sscanf(tmp_str, "CPU%d", &opts->calib_cpu);
			/*
			 * get_string_value_from allocate the string so with have to free it
			 * once useless
			 */
			free(tmp_str);
			if (!scan_cnt) {
				log_critical(PFX "Invalid calibration CPU%d", opts->calib_cpu);
				exit(EXIT_INV_CONFIG);
			}
			log_debug("calibrating CPU%d", opts->calib_cpu);
		}
	}

	tmp_obj = get_in_object(global, "log_size", TRUE);
	if (tmp_obj == NULL) {
		/* no size ? use file system */
		opts->logsize = -2;
	} else {
		if (json_object_is_type(tmp_obj, json_type_int)) {
			/* integer (no " ") detected. */
			/* buffer size is set in MB */
			opts->logsize = json_object_get_int(tmp_obj) << 20;
			log_notice("Log buffer size fixed to %dMB per threads", (opts->logsize >> 20));
		} else {
			/* Get CPU number */
			tmp_str = get_string_value_from(global, "log_size",
					 TRUE, "disable");

			if (!strcmp(tmp_str, "disable"))
				opts->logsize = 0;
			else if (!strcmp(tmp_str, "file"))
				opts->logsize = -2;
			else if (!strcmp(tmp_str, "auto"))
				opts->logsize = -2; /* Automatic buffer size computation is not supported yet so we fall back on file system mode */
			log_debug("Log buffer set to %s mode", tmp_str);

			/*
			 * get_string_value_from allocate the string so with have to free it
			 * once useless
			 */
			free(tmp_str);
		}
	}

	opts->logdir = get_string_value_from(global, "logdir", TRUE, "./");
	opts->logbasename = get_string_value_from(global, "log_basename",
						  TRUE, "rt-app");
	opts->ftrace = get_bool_value_from(global, "ftrace", TRUE, 0);
	opts->lock_pages = get_bool_value_from(global, "lock_pages", TRUE, 1);
	opts->pi_enabled = get_bool_value_from(global, "pi_enabled", TRUE, 0);
	opts->io_device = get_string_value_from(global, "io_device", TRUE,
						"/dev/null");
	opts->mem_buffer_size = get_int_value_from(global, "mem_buffer_size",
							TRUE, DEFAULT_MEM_BUF_SIZE);
	opts->cumulative_slack = get_bool_value_from(global, "cumulative_slack", TRUE, 0);

}

static void
get_opts_from_json_object(struct json_object *root, rtapp_options_t *opts)
{
	struct json_object *global, *tasks, *resources;

	if (root == NULL) {
		log_error(PFX "Error while parsing input JSON");
		exit(EXIT_INV_CONFIG);
	}
	log_info(PFX "Successfully parsed input JSON");
	log_info(PFX "root     : %s", json_object_to_json_string(root));

	global = get_in_object(root, "global", TRUE);
	if (global)
		log_info(PFX "global   : %s", json_object_to_json_string(global));

	tasks = get_in_object(root, "tasks", FALSE);
	log_info(PFX "tasks    : %s", json_object_to_json_string(tasks));

	resources = get_in_object(root, "resources", TRUE);
	if (resources)
		log_info(PFX "resources: %s", json_object_to_json_string(resources));

	log_info(PFX "Parsing global");
	parse_global(global, opts);
	json_object_put(global);
	log_info(PFX "Parsing resources");
	parse_resources(resources, opts);
	json_object_put(resources);
	log_info(PFX "Parsing tasks");
	parse_tasks(tasks, opts);
	json_object_put(tasks);
	log_info(PFX "Free json objects");

}

void
parse_config_stdin(rtapp_options_t *opts)
{
	/*
	 * Read from stdin until EOF, write to temp file and parse
	 * as a "normal" config file
	 */
	size_t in_length;
	char buf[JSON_FILE_BUF_SIZE];
	struct json_object *js;
	log_info(PFX "Reading JSON config from stdin...");

	in_length = fread(buf, sizeof(char), JSON_FILE_BUF_SIZE, stdin);
	buf[in_length] = '\0';
	js = json_tokener_parse(buf);
	get_opts_from_json_object(js, opts);
	return;
}

void
parse_config(const char *filename, rtapp_options_t *opts)
{
	char *fn = strdup(filename);
	struct json_object *js;
	log_info(PFX "Reading JSON config from %s", fn);
	js = json_object_from_file(fn);
	get_opts_from_json_object(js, opts);
	return;
}
