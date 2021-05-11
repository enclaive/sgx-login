// sgx-login.cpp : Hiermit werden die Funktionen für die statische Bibliothek definiert.
//

#include "pch.h"
#include "framework.h"
#include <stdio.h>  
#include <stdlib.h>     
#include <time.h>
#include "sgx-login-enclave_u.h"
#include <iostream>
#include "sgx_urts.h"
#include "sgx-login.h"
#include <tchar.h>

#define ENCLAVE_FILE _T("sgx-login-enclave.signed.dll")
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/*
 *Initialize the enclave:
 */
int initialize_enclave(void)
{
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;

	/* call sgx_create_enclave to initialize an enclave instance */
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to create enclave.\n", ret);
		return -1;
	}
	return 0;
}

const int max = 100;
const int min = 1;
int keys[max];


int generateToken() {
	return rand() % (max - min + 1) + min;
}
/*
*/


int login() {
	int status = -1;
	if (initialize_enclave() >= 0) {
		status = sgx_login();
	}
	
	/* Destroy the enclave */
	sgx_destroy_enclave(global_eid);
	return status;
}



bool sgx_verify(int token) {
	bool successful;

	if (token < sizeof(keys)) {
		successful = keys[token] == token;
	}
	else {
		successful = false;
	}

	return successful;
}


bool sgx_logout(int token) {
	bool successful;

	if (sgx_verify(token) && token < sizeof(keys)) {
		keys[token] = 0;
		successful = true;
	}
	else {
		successful = false;
	}

	return successful;
}






