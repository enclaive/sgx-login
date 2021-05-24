#pragma once
#include <cstdint>
#include "../Include/user.h"

//trusted E-Calls
void ecall_register(char* username, char* password);
int ecall_login(const user_t* user, size_t user_size);
void ecall_logout(int* token);
int ecall_verify(int* token);
int ecall_add_user(const user_t* users, size_t user_size);
int ecall_create_users(const char* master_password);

//untrusted O-Calls
void ocall_print_string(const char* str);
int ocall_save_users(const uint8_t* sealed_data, size_t sealed_size);
int ocall_load_users(uint8_t* sealed_data, const size_t sealed_size);
int ocall_is_users(void);