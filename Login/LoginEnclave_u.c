#include "LoginEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_login_user_t {
	int ms_retval;
	const user_t* ms_user;
	size_t ms_user_size;
} ms_ecall_login_user_t;

typedef struct ms_ecall_logout_user_t {
	int ms_retval;
	char* ms_username;
	size_t ms_username_size;
} ms_ecall_logout_user_t;

typedef struct ms_ecall_verify_user_t {
	int ms_retval;
	char* ms_username;
	size_t ms_username_size;
} ms_ecall_verify_user_t;

typedef struct ms_ecall_create_users_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_create_users_t;

typedef struct ms_ecall_register_user_t {
	int ms_retval;
	const user_t* ms_user;
	size_t ms_user_size;
} ms_ecall_register_user_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_save_users_t {
	int ms_retval;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_save_users_t;

typedef struct ms_ocall_load_users_t {
	int ms_retval;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_load_users_t;

typedef struct ms_ocall_is_users_t {
	int ms_retval;
} ms_ocall_is_users_t;

static sgx_status_t SGX_CDECL LoginEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_ocall_save_users(void* pms)
{
	ms_ocall_save_users_t* ms = SGX_CAST(ms_ocall_save_users_t*, pms);
	ms->ms_retval = ocall_save_users(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_ocall_load_users(void* pms)
{
	ms_ocall_load_users_t* ms = SGX_CAST(ms_ocall_load_users_t*, pms);
	ms->ms_retval = ocall_load_users(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL LoginEnclave_ocall_is_users(void* pms)
{
	ms_ocall_is_users_t* ms = SGX_CAST(ms_ocall_is_users_t*, pms);
	ms->ms_retval = ocall_is_users();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[9];
} ocall_table_LoginEnclave = {
	9,
	{
		(void*)(uintptr_t)LoginEnclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)(uintptr_t)LoginEnclave_ocall_print_string,
		(void*)(uintptr_t)LoginEnclave_ocall_save_users,
		(void*)(uintptr_t)LoginEnclave_ocall_load_users,
		(void*)(uintptr_t)LoginEnclave_ocall_is_users,
	}
};

sgx_status_t ecall_login_user(sgx_enclave_id_t eid, int* retval, const user_t* user, size_t user_size)
{
	sgx_status_t status;
	ms_ecall_login_user_t ms;
	ms.ms_user = user;
	ms.ms_user_size = user_size;
	status = sgx_ecall(eid, 0, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_logout_user(sgx_enclave_id_t eid, int* retval, char* username, size_t username_size)
{
	sgx_status_t status;
	ms_ecall_logout_user_t ms;
	ms.ms_username = username;
	ms.ms_username_size = username_size;
	status = sgx_ecall(eid, 1, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_verify_user(sgx_enclave_id_t eid, int* retval, char* username, size_t username_size)
{
	sgx_status_t status;
	ms_ecall_verify_user_t ms;
	ms.ms_username = username;
	ms.ms_username_size = username_size;
	status = sgx_ecall(eid, 2, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_users(sgx_enclave_id_t eid, int* retval, const char* master_password)
{
	sgx_status_t status;
	ms_ecall_create_users_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_register_user(sgx_enclave_id_t eid, int* retval, const user_t* user, size_t user_size)
{
	sgx_status_t status;
	ms_ecall_register_user_t ms;
	ms.ms_user = user;
	ms.ms_user_size = user_size;
	status = sgx_ecall(eid, 4, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

