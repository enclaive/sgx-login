// sgx-login.cpp : Hiermit werden die Funktionen für die statische Bibliothek definiert.
//

#include "pch.h"
#include "framework.h"
#include <stdio.h>  
#include <stdlib.h>     
#include <time.h>

#include <iostream>

// TODO: Dies ist ein Beispiel für eine Bibliotheksfunktion.
void fnsgxlogin()
{
}

const int max = 100;
const int min = 1;
int keys[max];


int generateToken() {
	return rand() % (max - min + 1) + min;
}

int sgx_login() {
	int token = generateToken();

	while (keys[token] != 0) {
		std::cout << token;
		token = generateToken();
	}

	keys[token] = token;

	return token;
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






