#include "LoginEnclave_t.h"

#include <list>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <fstream>
#include <iostream>
#include "sgx_tseal.h"
#include "Sealing.h"

// 0: Username, 1: Password
std::list<std::tuple<char*, char*>> authenticationList;
// 0: Username, 2: Token
std::list<std::tuple<char*, char*>> tokenList;

// Check if username and password is correct, send 0 or 1 back
int ecall_login(user_t* user, size_t user_size) {
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;

	// 1. load user
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_users(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		ocall_print_string("Failed to load Users.");
		return -1;
	}


	// 3. unseal wallet
	uint32_t plaintext_size = sizeof(users_t);
	users_t* users = (users_t*)malloc(plaintext_size);
	sealing_status = unseal_users((sgx_sealed_data_t*)sealed_data, users, plaintext_size);
	free(sealed_data);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		ocall_print_string("Unseal Users failed");
		return -1;
	}

	size_t users_size = users->size;
	// 5. remove item from the wallet
	for (int i = 0; i < users_size - 1; ++i) {
		if (users->users[i].username == user->username && users->users[i].password == user->password) {
			ocall_print_string("Login successfull");
			users->users[i].logged = true;
		}
	}

	// 6. seal users
	sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		free(sealed_data);
		ocall_print_string("Failed to seal users");
		return -1;
	}

	// 7. save users
	ocall_status = ocall_save_users(&ocall_ret, sealed_data, sealed_size);
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		ocall_print_string("Failed so save Users");
		return -1;
	}
	return 0;
}

void ecall_register(char* username, char* password) {
    // First check if username already exists
    for (std::tuple<char*, char*> n : authenticationList) {
		if (*std::get<0>(n) == *username) {
			ocall_print_string("Username already exist\n");
			return;
		}
    }

	// Push username and password to authentication list
	char enclaveUsername = *username;
	char enclavePassword = *password;
	authenticationList.push_back(std::make_tuple(&enclaveUsername, &enclavePassword));

	ocall_print_string("Register succesfull\n");
}

void ecall_logout(char* token) {
	//logout

	// send message if logout was successfull
	//ocall_print_string("Logout erfolgreich");
	ocall_print_string("Logout erfolgreich!");
}

void ecall_verify(char* token) {
	
	ocall_print_string("Token korrekt!");
}

int ecall_add_user(const user_t* user, size_t user_size) {

	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;

	// 1. load user
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_users(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return -1;
	}
	

	// 3. unseal wallet
	uint32_t plaintext_size = sizeof(users_t);
	users_t* users = (users_t*)malloc(plaintext_size);
	sealing_status = unseal_users((sgx_sealed_data_t*)sealed_data, users, plaintext_size);
	free(sealed_data);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		return -1;
	}

	// 4. check input length
	if (strlen(user->username) + 1 > MAX_ITEM_SIZE ||
		strlen(user->password) + 1 > MAX_ITEM_SIZE
		) {
		free(users);
		return -1;
	}

	// 5. add item to the wallet
	size_t users_size = users->size;
	if (users_size >= MAX_ITEMS) {
		free(users);
		return -1;
	}
	users->users[users_size] = *user;
	++users->size;


	// 6. seal wallet
	sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		free(sealed_data);
		return -1;
	}

	// 7. save wallet
	ocall_status = ocall_save_users(&ocall_ret, sealed_data, sealed_size);
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return -1;
	}
	return 0;
}

int ecall_create_users(const char* master_password) {

	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;

	// 2. abort if wallet already exist
	ocall_status = ocall_is_users(&ocall_ret);
	if (ocall_ret != 0) {
		return -1;
	}


	// 3. create new wallet
	users_t* users = (users_t*)malloc(sizeof(users_t));
	users->size = 0;
	strncpy(users->master_password, master_password, strlen(master_password) + 1);


	// 4. seal wallet
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(sealed_data);
		return -1;
	}


	// 5. save wallet
	ocall_status = ocall_save_users(&ocall_ret, sealed_data, sealed_size);
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return -1;
	}

	// 6. exit enclave
	return 0;
}
