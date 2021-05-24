#ifndef SEALING_H_
#define SEALING_H_

#include "sgx_trts.h"
#include "sgx_tseal.h"


sgx_status_t seal_users(const users_t* plaintext, sgx_sealed_data_t* sealed_data, size_t sealed_size);

sgx_status_t unseal_users(const sgx_sealed_data_t* sealed_data, users_t* plaintext, uint32_t plaintext_size);


#endif 