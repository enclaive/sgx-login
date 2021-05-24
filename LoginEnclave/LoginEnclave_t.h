#ifndef LOGINENCLAVE_T_H__
#define LOGINENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../Include/user.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_login(const user_t* user, size_t user_size);
void ecall_register(char* username, char* password);
void ecall_logout(char* token);
void ecall_verify(char* token);
int ecall_create_users(const char* master_password);
int ecall_add_user(const user_t* user, size_t user_size);

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_save_users(int* retval, const uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_load_users(int* retval, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_is_users(int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
