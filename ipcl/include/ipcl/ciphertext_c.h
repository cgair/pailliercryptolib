#pragma once

////////////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Intel Paillier Cryptosystem 
// Library that can be Invoked by .rs code.
//
////////////////////////////////////////////////////////////////////////////////

#include "defines.h"

PAILLIER_C_FUNC CipherText_Create1(void **ciphertext);

PAILLIER_C_FUNC CipherText_SaveSize(void *thisptr, size_t *result);
PAILLIER_C_FUNC CipherText_Save(void *thisptr, uint32_t *outptr, size_t size, size_t *out_len);

// In fact we are saving the BigNumber
PAILLIER_C_FUNC CipherText_Save2(void *thisptr, const char* file, unsigned int version);

// In fact we are loading the BigNumber
PAILLIER_C_FUNC CipherText_Load2(void *key, void **ciphertext, const char* file, unsigned int version);


PAILLIER_C_FUNC CipherText_Destroy(void *thisptr);