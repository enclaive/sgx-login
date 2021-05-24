#include "LoginEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_login_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_login_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_login_user_t* ms = SGX_CAST(ms_ecall_login_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const user_t* _tmp_user = ms->ms_user;
	size_t _tmp_user_size = ms->ms_user_size;
	size_t _len_user = _tmp_user_size;
	user_t* _in_user = NULL;

	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_user != NULL && _len_user != 0) {
		_in_user = (user_t*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_user, _len_user, _tmp_user, _len_user)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_login_user((const user_t*)_in_user, _tmp_user_size);

err:
	if (_in_user) free(_in_user);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_logout_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_logout_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_logout_user_t* ms = SGX_CAST(ms_ecall_logout_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_username = ms->ms_username;
	size_t _tmp_username_size = ms->ms_username_size;
	size_t _len_username = _tmp_username_size;
	char* _in_username = NULL;

	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_username != NULL && _len_username != 0) {
		if ( _len_username % sizeof(*_tmp_username) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_username, _len_username, _tmp_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_logout_user(_in_username, _tmp_username_size);

err:
	if (_in_username) free(_in_username);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_user_t* ms = SGX_CAST(ms_ecall_verify_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_username = ms->ms_username;
	size_t _tmp_username_size = ms->ms_username_size;
	size_t _len_username = _tmp_username_size;
	char* _in_username = NULL;

	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_username != NULL && _len_username != 0) {
		if ( _len_username % sizeof(*_tmp_username) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_username, _len_username, _tmp_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_verify_user(_in_username, _tmp_username_size);

err:
	if (_in_username) free(_in_username);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_users(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_users_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_users_t* ms = SGX_CAST(ms_ecall_create_users_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_create_users((const char*)_in_master_password);

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_register_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_register_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_register_user_t* ms = SGX_CAST(ms_ecall_register_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const user_t* _tmp_user = ms->ms_user;
	size_t _tmp_user_size = ms->ms_user_size;
	size_t _len_user = _tmp_user_size;
	user_t* _in_user = NULL;

	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_user != NULL && _len_user != 0) {
		_in_user = (user_t*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_user, _len_user, _tmp_user, _len_user)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_register_user((const user_t*)_in_user, _tmp_user_size);

err:
	if (_in_user) free(_in_user);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_login_user, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_logout_user, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_user, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_users, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_register_user, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][5];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_save_users(int* retval, const uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_data = sealed_size;

	ms_ocall_save_users_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_save_users_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_save_users_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_save_users_t));
	ocalloc_size -= sizeof(ms_ocall_save_users_t);

	if (sealed_data != NULL) {
		ms->ms_sealed_data = (const uint8_t*)__tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealed_data, _len_sealed_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_load_users(int* retval, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_data = sealed_size;

	ms_ocall_load_users_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_users_t);
	void *__tmp = NULL;

	void *__tmp_sealed_data = NULL;

	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_users_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_users_t));
	ocalloc_size -= sizeof(ms_ocall_load_users_t);

	if (sealed_data != NULL) {
		ms->ms_sealed_data = (uint8_t*)__tmp;
		__tmp_sealed_data = __tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_sealed_data, 0, _len_sealed_data);
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sealed_data) {
			if (memcpy_s((void*)sealed_data, _len_sealed_data, __tmp_sealed_data, _len_sealed_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_is_users(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_is_users_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_is_users_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_is_users_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_is_users_t));
	ocalloc_size -= sizeof(ms_ocall_is_users_t);

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
