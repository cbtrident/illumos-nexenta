/*
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

#include <strings.h>
#include <sys/debug.h>
#include <umem.h>

#include <sys/krrp.h>
#include "libkrrp.h"
#include "libkrrp_impl.h"

int
krrp_set_srv_config(libkrrp_handle_t *hdl, const char *address,
    const uint16_t port)
{
	nvlist_t *params = NULL;
	krrp_cfg_type_t cfg_type = KRRP_SVC_CFG_TYPE_SERVER;
	int rc;

	params = fnvlist_alloc();

	VERIFY(hdl != NULL);

	if ((address != NULL) && (strlen(address))) {
		(void) krrp_param_put(KRRP_PARAM_LISTENING_ADDRESS, params,
		    (void *)address);
	}

	(void) krrp_param_put(KRRP_PARAM_CFG_TYPE, params, (void *)&cfg_type);
	(void) krrp_param_put(KRRP_PARAM_PORT, params,
	    (void *)&port);

	rc = krrp_ioctl_perform(hdl, KRRP_IOCTL_SVC_SET_CONFIG, params, NULL);

	fnvlist_free(params);
	return (rc);
}

int
krrp_get_srv_config(libkrrp_handle_t *hdl, libkrrp_srv_config_t *cfg)
{
	nvlist_t *result = NULL;
	nvlist_t *params = NULL;
	char *address = NULL;
	int rc;
	krrp_cfg_type_t cfg_type = KRRP_SVC_CFG_TYPE_SERVER;

	VERIFY(hdl != NULL);

	params = fnvlist_alloc();

	(void) krrp_param_put(KRRP_PARAM_CFG_TYPE, params, (void *)&cfg_type);

	rc = krrp_ioctl_perform(hdl, KRRP_IOCTL_SVC_GET_CONFIG, params,
	    &result);

	if (rc != 0) {
		rc = -1;
		goto fini;
	}

	VERIFY3U(krrp_param_get(KRRP_PARAM_PORT, result,
	    (void *)&cfg->port), ==, 0);

	rc = krrp_param_get(KRRP_PARAM_LISTENING_ADDRESS, result,
	    (void *)&address);

	VERIFY(rc == 0 || rc == ENOENT);

	if (rc == 0) {
		rc = strlcpy(cfg->address, address, sizeof (cfg->address));
		VERIFY(rc < sizeof (cfg->address));
	} else {
		cfg->address[0] = '\0';
	}

	rc = 0;

fini:
	fnvlist_free(params);

	if (result != NULL)
		fnvlist_free(result);

	return (rc);
}

int
krrp_svc_enable(libkrrp_handle_t *hdl)
{
	VERIFY(hdl != NULL);
	return (krrp_ioctl_perform(hdl, KRRP_IOCTL_SVC_ENABLE, NULL, NULL));
}

int
krrp_svc_disable(libkrrp_handle_t *hdl)
{
	VERIFY(hdl != NULL);
	return (krrp_ioctl_perform(hdl, KRRP_IOCTL_SVC_DISABLE, NULL, NULL));
}

int
krrp_svc_state(libkrrp_handle_t *hdl, libkrrp_svc_state_t *state)
{
	int rc;
	nvlist_t *result_nvl = NULL;

	VERIFY(hdl != NULL);

	rc = krrp_ioctl_perform(hdl, KRRP_IOCTL_SVC_STATE, NULL, &result_nvl);

	if (rc != 0)
		return (-1);

	VERIFY3U(krrp_param_get(KRRP_PARAM_SVC_ENABLED, result_nvl,
	    (void *)&state->enabled), ==, 0);

	VERIFY3U(krrp_param_get(KRRP_PARAM_SRV_RUNNING, result_nvl,
	    (void *)&state->running), ==, 0);

	fnvlist_free(result_nvl);
	return (rc);
}

int
krrp_sess_list(libkrrp_handle_t *hdl, libkrrp_sess_list_t **res_sess_list)
{
	int rc;
	nvlist_t *result = NULL;
	uint_t i;
	krrp_param_array_t sessions;
	nvlist_t *session;
	char *sess_id_str;
	char *sess_kstat_id;
	libkrrp_sess_list_t *sess_list = NULL;
	libkrrp_sess_list_t *entry = NULL;
	libkrrp_sess_list_t *prev = NULL;

	VERIFY(hdl != NULL);

	rc = krrp_ioctl_perform(hdl, KRRP_IOCTL_SESS_LIST, NULL, &result);
	if (rc != 0)
		return (-1);

	if (result == NULL) {
		*res_sess_list = NULL;
		return (0);
	}

	VERIFY3U(krrp_param_get(KRRP_PARAM_SESSIONS, result,
	    (void *)&sessions), ==, 0);

	for (i = 0; i < sessions.nelem; i++) {
		session = sessions.array[i];
		VERIFY3U(krrp_param_get(KRRP_PARAM_SESS_ID, session,
		    (void *)&sess_id_str), ==, 0);

		entry = umem_zalloc(sizeof (libkrrp_sess_list_t), UMEM_DEFAULT);

		if (entry == NULL) {
			libkrrp_error_set(&hdl->libkrrp_error,
			    LIBKRRP_ERRNO_NOMEM, errno, 0);
			rc = -1;
			goto fini;
		}

		if (uuid_parse(sess_id_str, entry->sess_id) != 0) {
			libkrrp_error_set(&hdl->libkrrp_error,
			    LIBKRRP_ERRNO_SESSID, EINVAL, 0);
			rc = -1;
			goto fini;
		}

		VERIFY3U(krrp_param_get(KRRP_PARAM_SESS_KSTAT_ID, session,
		    (void *)&sess_kstat_id), ==, 0);

		entry->sess_kstat_id = umem_alloc(KRRP_KSTAT_ID_STRING_LENGTH,
		    UMEM_DEFAULT);

		if (entry->sess_kstat_id == NULL) {
			libkrrp_error_set(&hdl->libkrrp_error,
			    LIBKRRP_ERRNO_NOMEM, errno, 0);
			rc = -1;
			goto fini;
		}

		(void) strlcpy(entry->sess_kstat_id, sess_kstat_id,
		    KRRP_KSTAT_ID_STRING_LENGTH);

		VERIFY3U(krrp_param_get(KRRP_PARAM_SESS_STARTED, session,
		    (void *)&entry->sess_started), ==, 0);

		VERIFY3U(krrp_param_get(KRRP_PARAM_SESS_RUNNING, session,
		    (void *)&entry->sess_running), ==, 0);

		if (prev == NULL)
			sess_list = entry;
		else
			prev->sl_next = entry;

		prev = entry;
	}

	*res_sess_list = sess_list;

fini:
	fnvlist_free(result);

	if (rc != 0 && sess_list != NULL)
		krrp_sess_list_free(sess_list);

	return (rc);
}

void
krrp_sess_list_free(libkrrp_sess_list_t *sess_list)
{
	libkrrp_sess_list_t *next;

	while (sess_list != NULL) {
		next = sess_list->sl_next;

		if (sess_list->sess_kstat_id != NULL) {
			umem_free(sess_list->sess_kstat_id,
			    KRRP_KSTAT_ID_STRING_LENGTH);
		}

		umem_free(sess_list, sizeof (libkrrp_sess_list_t));
		sess_list = next;
	}
}
