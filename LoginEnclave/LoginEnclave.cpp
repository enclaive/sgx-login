#include "LoginEnclave_t.h"

#include "sgx_trts.h"

#include "sgx_tcrypto.h"

// Check if username and password is correct, send 0 or 1 back
int ecall_login(char* username, char* password) {

	ocall_print_string("Login erfolgreich");
	return 1;
}



void ecall_register(char* username, char* password) {
	//register
	//hashing with sgx_sha256_hash
	//if register successful, make O-CALL

	ocall_print_string(username);
}

void ecall_logout(int* token) {
	//logout

	// send message if logout was successfull
	//ocall_print_string("Logout erfolgreich");
	ocall_print_string("Logout erfolgreich!");
}

int ecall_verify(int* token) {
	
		ocall_print_string("Token korrekt!");
		return 1;
}