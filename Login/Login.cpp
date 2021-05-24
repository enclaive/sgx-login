// Login.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//

#include <iostream>
#include <fstream>
#include <string> // To use string
#include "sgx_urts.h"
#include "Login.h"
#include "LoginEnclave_u.h"
#include <fstream>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char* msg;
    const char* sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}
/*
 *Initialize the enclave:
 */
int initialize_enclave(void)
{
    sgx_launch_token_t token = { 0 };
    sgx_status_t ret = SGX_SUCCESS;
    int updated = 0;

    /* call sgx_create_enclave to initialize an enclave instance */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);

        return -1;
    }
    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char* argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t ecall_status, enclave_status;
    int updated, ret, runnning = 0;

    /* Initialize the enclave */
    if (initialize_enclave() < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    /* Check for users init*/
    ecall_status = ecall_create_users(global_eid, &ret, "test");
    if (ecall_status != SGX_SUCCESS || ret == -1) {
        printf("Users could not be created or already exist.");
        printf("\n");
    }
    else {
        printf("Users successfully created.");
    }
    printf("Type in 'help' to get more information.\n");
    /* Wait for user Inputs*/
    while (runnning != -1) {
        char* userInput = new char[512];
        std::cin >> userInput;

        if (strcmp(userInput, "help") == 0) {
            printf("Type in Options: help, login, register, logout, verify.\n");
            userInput = new char[512];
        }
        else if (strcmp(userInput, "register") == 0) {
            char* user = new char[512];
            char* pass = new char[512];

            std::cout << "Register: \n";
            std::cout << "Type in Username (Press Enter to confirm): ";
            std::cin >> user;

            std::cout << "Type in Password (Press Enter to confirm): ";
            std::cin >> pass;

            std::cout << "\n";
            user_t* new_user = (user_t*)malloc(sizeof(user_t));

            new_user->logged = 0;
            strcpy_s(new_user->username, user);
            strcpy_s(new_user->password, pass);
            ecall_status = ecall_register_user(global_eid, &ret, new_user, sizeof(user_t));
            if (ecall_status != SGX_SUCCESS || ret == -1) {
                printf("Fail to add new user to users.\n");
            }
            else {
                printf("User successfully created.\n");
            }
            free(new_user);
        }
        else if (strcmp(userInput, "login") == 0) {
            char* user = new char[512];
            char* pass = new char[512];

            std::cout << "Login: \n";
            std::cout << "Type in Username (Press Enter to confirm): ";
            std::cin >> user;

            std::cout << "Type in Password (Press Enter to confirm): ";
            std::cin >> pass;

            std::cout << "\n";
            user_t* new_user = (user_t*)malloc(sizeof(user_t));
            new_user->logged = -1;
            strcpy_s(new_user->username, user);
            strcpy_s(new_user->password, pass);
            ecall_status = ecall_login_user(global_eid, &ret, new_user, sizeof(user_t));
            if (ecall_status != SGX_SUCCESS || ret == -1) {
                printf("Fail to login with username.\n");
            }

        }
        else if (strcmp(userInput, "logout") == 0) {
            char* username = new char[512];

            std::cout << "Logout: \n";
            std::cout << "Type in Username for logout (Press Enter to confirm): ";
            std::cin >> username;
            ecall_status = ecall_logout_user(global_eid, &ret, username, sizeof(user_t));
        }
        else if (strcmp(userInput, "verify") == 0) {
            char* username = new char[512];

            std::cout << "Verify: \n";
            std::cout << "Type in Username for Verify (Press Enter to confirm): ";
            std::cin >> username;
            ecall_status = ecall_verify_user(global_eid, &ret, username, sizeof(user_t));
        }
        else if (strcmp(userInput,"exit") == 0) {
            runnning = -1;
        }

        userInput = new char[512];
    }

    sgx_destroy_enclave(global_eid);
    
    printf("\n");
    printf("Info:Enclave successfully returned.\n");
    getchar();
    return 0;
}



void ocall_print_string(const char* str) 
{
    printf("%s", str);
}

int ocall_save_users(const uint8_t* sealed_data, const size_t sealed_size) 
{

    std::ofstream file("User.seal", std::ios::out | std::ios::binary);
    if (file.fail()) { return 1; }
    file.write((const char*)sealed_data, sealed_size);
    file.close();
   
    return 0;

}
int ocall_load_users(uint8_t* sealed_data, const size_t sealed_size)
{
    std::ifstream file("User.seal", std::ios::in | std::ios::binary);
    if (file.fail()) { return 1; }
    file.read((char*)sealed_data, sealed_size);
    file.close();
    return 0;
}

int ocall_is_users(void) 
{
    std::ifstream file("User.seal", std::ios::in | std::ios::binary);
    if (file.fail()) { return 0; }
    file.close();
    return 1;
}
