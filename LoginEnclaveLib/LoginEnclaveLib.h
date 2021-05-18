#pragma once

//trusted E-Calls
void ecall_register(char* username, char* password);
int ecall_login(char* username, char* password);
void ecall_logout(int* token);
int ecall_verify(int* token);

//untrusted O-Calls
void ocall_print_string(const char* str);