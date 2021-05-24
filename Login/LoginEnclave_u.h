#ifndef LOGINENCLAVE_U_H__
#define LOGINENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "../Include/user.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_SAVE_USERS_DEFINED__
#define OCALL_SAVE_USERS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_save_users, (const uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_LOAD_USERS_DEFINED__
#define OCALL_LOAD_USERS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_users, (uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_IS_USERS_DEFINED__
#define OCALL_IS_USERS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_is_users, (void));
#endif

sgx_status_t ecall_login_user(sgx_enclave_id_t eid, int* retval, const user_t* user, size_t user_size);
sgx_status_t ecall_logout_user(sgx_enclave_id_t eid, int* retval, char* username, size_t username_size);
sgx_status_t ecall_verify_user(sgx_enclave_id_t eid, int* retval, char* username, size_t username_size);
sgx_status_t ecall_create_users(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_register_user(sgx_enclave_id_t eid, int* retval, const user_t* user, size_t user_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
