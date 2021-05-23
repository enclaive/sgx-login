#include "LoginEnclave_t.h"

#include <list>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"


// 0: Username, 1: Password
std::list<std::tuple<char*, char*>> authenticationList;
// 0: Username, 2: Token
std::list<std::tuple<char*, char*>> tokenList;

// Check if username and password is correct, send 0 or 1 back
void ecall_login(char* username, char* password) {
	ocall_print_string(username);

	// Check if username and password are correct
	for (std::tuple<char*, char*> it : authenticationList) {
		char* u = std::get<0>(it);
		char* p = std::get<1>(it);
		bool okUsername = *u == *username;
		bool okPassword = *p == *password;

		if (okUsername && okPassword) {
			tokenList.push_back(std::make_tuple(username, password));

			ocall_print_string("Login successfull\n");
			return;
		}
	}

	ocall_print_string("Wrong username or password");
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