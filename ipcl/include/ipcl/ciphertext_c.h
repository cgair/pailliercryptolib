#pragma once

////////////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Intel Paillier Cryptosystem 
// Library that can be Invoked by .rs code.
//
////////////////////////////////////////////////////////////////////////////////

#include "defines.h"

PAILLIER_C_FUNC CipherText_Create1(void **ciphertext);
PAILLIER_C_FUNC CipherText_Create2(void *keypair, void **ciphertext, uint32_t *input, int len);

PAILLIER_C_FUNC CipherText_SaveSize(void *thisptr, size_t *result);
PAILLIER_C_FUNC CipherText_Save(void *thisptr, uint32_t *outptr, size_t size, size_t *out_len);

PAILLIER_C_FUNC CipherText_Destroy(void *thisptr);