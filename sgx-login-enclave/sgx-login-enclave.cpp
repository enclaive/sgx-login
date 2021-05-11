#include "sgx-login-enclave_t.h"

#include "sgx_trts.h"
#include "sgx-login-enclave_t.h"

const int max = 100;
const int min = 1;
int keys[max];

 int generateToken() {
	return 1;
}

int sgx_login() {
	int token = generateToken();

	while (keys[token] != 0) {
		token = generateToken();
	}

	keys[token] = token;

	return token;
}
