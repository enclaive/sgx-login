#pragma once
#include <cstdint>
#include "../Include/user.h"

//trusted E-Calls
int ecall_login_user(const user_t* user, size_t user_size);
int ecall_logout_user(char* username, size_t username_size);
int ecall_verify_user(char* username, size_t username_size);
int ecall_register_user(const user_t* users, size_t user_size);
int ecall_create_users(const char* master_password);

//untrusted O-Calls
void ocall_print_string(const char* str);
int ocall_save_users(const uint8_t* sealed_data, size_t sealed_size);
int ocall_load_users(uint8_t* sealed_data, const size_t sealed_size);
int ocall_is_users(void);