#pragma once

////////////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Intel Paillier Cryptosystem 
// Library that can be Invoked by .rs code.
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>

#include "defines.h"

PAILLIER_C_FUNC PlainText_Create1(void **plaintext);
PAILLIER_C_FUNC PlainText_Create2(void **plaintext, uint32_t *input, int len);

PAILLIER_C_FUNC PlainText_SaveSize(void *thisptr, size_t *result);
PAILLIER_C_FUNC PlainText_Save(void *thisptr, uint32_t *outptr, size_t size, size_t *out_len);

PAILLIER_C_FUNC PlainText_Destroy(void *thisptr);
