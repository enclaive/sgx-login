#include "LoginEnclave_t.h"

#include <list>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <fstream>
#include <iostream>
#include "sgx_tseal.h"
#include "Sealing.h"


int ecall_login_user(const user_t* user, size_t user_size) {
	
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


	// 2. unseal user
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
	// 3. verify login
	for (int i = 0; i < users_size; ++i) {
		if (strcmp(users->users[i].username, user->username) == 0 && strcmp(users->users[i].password, user->password) == 0) {
			users->users[i].logged = 0;
			ocall_print_string("User was logged in successfully");
		}
	}

	// 4. seal users
	sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		free(sealed_data);
		ocall_print_string("Failed to seal users");
		return -1;
	}

	// 5. save users
	ocall_status = ocall_save_users(&ocall_ret, sealed_data, sealed_size);
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		ocall_print_string("Failed so save Users");
		return -1;
	}
	
	return 0;
}

int ecall_register_user(const user_t* user, size_t user_size) {

	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;

	// 1. load users
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_users(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return -1;
	}
	

	// 2. unseal users
	uint32_t plaintext_size = sizeof(users_t);
	users_t* users = (users_t*)malloc(plaintext_size);
	sealing_status = unseal_users((sgx_sealed_data_t*)sealed_data, users, plaintext_size);
	free(sealed_data);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		return -1;
	}

	// 3. check input length
	if (strlen(user->username) + 1 > MAX_ITEM_SIZE ||
		strlen(user->password) + 1 > MAX_ITEM_SIZE
		) {
		free(users);
		return -1;
	}

	// 4. check if username already exist

	size_t users_size = users->size;
	// 3. verify login
	for (int i = 0; i < users_size; ++i) {
		if (strcmp(users->users[i].username, user->username) == 0){
			ocall_print_string("Username already exists! \n");
		return -1;
	}
}

	// 5. add user to users
	if (users_size >= MAX_ITEMS) {
		free(users);
		return -1;
	}
	users->users[users_size] = *user;
	++users->size;


	// 6. seal users
	sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		free(sealed_data);
		return -1;
	}

	// 7. save users
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

	// 1. abort if users already exist
	ocall_status = ocall_is_users(&ocall_ret);
	if (ocall_ret != 0) {
		return -1;
	}


	// 2. create new users
	users_t* users = (users_t*)malloc(sizeof(users_t));
	users->size = 0;
	strncpy(users->master_password, master_password, strlen(master_password) + 1);


	// 3. seal users
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(sealed_data);
		return -1;
	}


	// 4. save users
	ocall_status = ocall_save_users(&ocall_ret, sealed_data, sealed_size);
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return -1;
	}

	return 0;
}

int ecall_logout_user(char* username, size_t username_size) {
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;
	// 1. load users
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_users(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return -1;
	}

	// 2. unseal users
	uint32_t plaintext_size = sizeof(users_t);
	users_t* users = (users_t*)malloc(plaintext_size);
	sealing_status = unseal_users((sgx_sealed_data_t*)sealed_data, users, plaintext_size);
	free(sealed_data);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		return -1;
	}

	//3. get user by username
	size_t users_size = users->size;
	for (int i = 0; i < users_size; ++i) {
		if (strcmp(users->users[i].username, username) == 0) {
			if (users->users[i].logged == 0) {
				users->users[i].logged = -1;
				ocall_print_string("Logout was successful.\n");
			}
			else {
				ocall_print_string("User not logged in.\n");
				return -1;
			}
		}
	}

	// 4. seal users
	sealed_data = (uint8_t*)malloc(sealed_size);
	sealing_status = seal_users(users, (sgx_sealed_data_t*)sealed_data, sealed_size);
	free(users);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		free(sealed_data);
		ocall_print_string("Failed to seal users");
		return -1;
	}

	// 5. save users
	ocall_status = ocall_save_users(&ocall_ret, sealed_data, sealed_size);
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		ocall_print_string("Failed so save Users");
		return -1;
	}

	return 0;
}

int ecall_verify_user(char* username, size_t username_size) {
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;

	// 1. load users
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(users_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_users(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return -1;
	}

	// 2. unseal users
	uint32_t plaintext_size = sizeof(users_t);
	users_t* users = (users_t*)malloc(plaintext_size);
	sealing_status = unseal_users((sgx_sealed_data_t*)sealed_data, users, plaintext_size);
	free(sealed_data);
	if (sealing_status != SGX_SUCCESS) {
		free(users);
		return -1;
	}

	//3. get user by username
	size_t users_size = users->size;
	for (int i = 0; i < users_size; ++i) {
		if (strcmp(users->users[i].username, username) == 0) {
			ocall_print_string("User exist! \n");
			return 0;
		}
	}
	ocall_print_string("No User found! \n");
	return -1;
}

