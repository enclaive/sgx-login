#pragma once

#ifndef SGX_LOGIN
#define SGX_LOGIN

int sgx_login();
bool sgx_verify(int token);
bool sgx_logout(int token);


#endif

