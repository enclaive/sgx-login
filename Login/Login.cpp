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
    int updated, ret;

    std::cout << "Hello World!\n";
    char username[BUFSIZ] = { 'test' };
    char password[BUFSIZ] = { "password" };
    char usernameTest[BUFSIZ] = { 'nope' };

    /* Initialize the enclave */
    if (initialize_enclave() < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    char* user1 = new char[512];
    char* pass1 = new char[512];

    std::cout << "Register: \n";
    std::cout << "Username: ";
    std::cin >> user1;

    std::cout << "Password: ";
    std::cin >> pass1;

    std::cout << "\n";
    
    ecall_status = ecall_create_users(global_eid, &ret, "test");
    if (ecall_status != SGX_SUCCESS || ret == -1) {
        printf("Fail to create new users.");
    }
    else {
        printf("Users successfully created.");
    }

    //user hinzufügen
    user_t* new_user = (user_t*)malloc(sizeof(user_t));

    new_user->logged = 0;
    strcpy_s(new_user->username, user1);
    strcpy_s(new_user->password, pass1);
    ecall_status = ecall_add_user(global_eid, &ret, new_user, sizeof(user_t));
    if (ecall_status != SGX_SUCCESS || ret == -1) {
        printf("Fail to add new item to wallet.");
    }
    else {
        printf("Item successfully added to the wallet.");
    }
    free(new_user);
   // ecall_register(global_eid, user1, pass1);
   // ecall_register(global_eid, user1, pass1);

       
   // ecall_login(global_eid, user1, pass1);
    
    char* user2 = new char[512];
    char* pass2 = new char[512];

    std::cout << "Login: \n";
    std::cout << "Username: ";
    std::cin >> user2;

    std::cout << "Password: ";
    std::cin >> pass2;

    std::cout << "\n";

    user_t* new_user2 = (user_t*)malloc(sizeof(user_t));

    new_user2->logged = 0;
    strcpy_s(new_user2->username, user2);
    strcpy_s(new_user2->password, pass2);
    ecall_login_user(global_eid, &ret, new_user2, sizeof(user_t));
    
    sgx_destroy_enclave(global_eid);

    printf("\n");
    printf("Info:Enclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
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
    if (file.fail()) { return 0; } // failure means no users found
    file.close();
    return 1;
}

// Programm ausführen: STRG+F5 oder Menüeintrag "Debuggen" > "Starten ohne Debuggen starten"
// Programm debuggen: F5 oder "Debuggen" > Menü "Debuggen starten"

// Tipps für den Einstieg: 
//   1. Verwenden Sie das Projektmappen-Explorer-Fenster zum Hinzufügen/Verwalten von Dateien.
//   2. Verwenden Sie das Team Explorer-Fenster zum Herstellen einer Verbindung mit der Quellcodeverwaltung.
//   3. Verwenden Sie das Ausgabefenster, um die Buildausgabe und andere Nachrichten anzuzeigen.
//   4. Verwenden Sie das Fenster "Fehlerliste", um Fehler anzuzeigen.
//   5. Wechseln Sie zu "Projekt" > "Neues Element hinzufügen", um neue Codedateien zu erstellen, bzw. zu "Projekt" > "Vorhandenes Element hinzufügen", um dem Projekt vorhandene Codedateien hinzuzufügen.
//   6. Um dieses Projekt später erneut zu öffnen, wechseln Sie zu "Datei" > "Öffnen" > "Projekt", und wählen Sie die SLN-Datei aus.
