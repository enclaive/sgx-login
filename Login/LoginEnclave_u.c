#include "LoginEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_login_t {
	int ms_retval;
	char* ms_username;
	char* ms_password;
} ms_ecall_login_t;

typedef struct ms_ecall_register_t {
	char* ms_username;
	char* ms_password;
} ms_ecall_register_t;

typedef struct ms_ecall_logout_t {
	int* ms_token;
} ms_ecall_logout_t;

typedef struct ms_ecall_verify_t {
	int ms_retval;
	int* ms_token;
} ms_ecall_verify_t;

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

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_LoginEnclave = {
	6,
	{
		(void*)(uintptr_t)LoginEnclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)LoginEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)(uintptr_t)LoginEnclave_ocall_print_string,
	}
};

sgx_status_t ecall_login(sgx_enclave_id_t eid, int* retval, char* username, char* password)
{
	sgx_status_t status;
	ms_ecall_login_t ms;
	ms.ms_username = username;
	ms.ms_password = password;
	status = sgx_ecall(eid, 0, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_register(sgx_enclave_id_t eid, char* username, char* password)
{
	sgx_status_t status;
	ms_ecall_register_t ms;
	ms.ms_username = username;
	ms.ms_password = password;
	status = sgx_ecall(eid, 1, &ocall_table_LoginEnclave, &ms);
	return status;
}

sgx_status_t ecall_logout(sgx_enclave_id_t eid, int* token)
{
	sgx_status_t status;
	ms_ecall_logout_t ms;
	ms.ms_token = token;
	status = sgx_ecall(eid, 2, &ocall_table_LoginEnclave, &ms);
	return status;
}

sgx_status_t ecall_verify(sgx_enclave_id_t eid, int* retval, int* token)
{
	sgx_status_t status;
	ms_ecall_verify_t ms;
	ms.ms_token = token;
	status = sgx_ecall(eid, 3, &ocall_table_LoginEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

