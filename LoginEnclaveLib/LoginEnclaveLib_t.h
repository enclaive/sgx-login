#ifndef LOGINENCLAVELIB_T_H__
#define LOGINENCLAVELIB_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../Include/user.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_login_user(const user_t* user, size_t user_size);
int ecall_logout_user(char* username, size_t username_size);
int ecall_verify_user(char* username, size_t username_size);
int ecall_create_users(const char* master_password);
int ecall_register_user(const user_t* user, size_t user_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_save_users(int* retval, const uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_load_users(int* retval, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_is_users(int* retval);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
