#pragma once

////////////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Intel Paillier Cryptosystem 
// Library that can be Invoked by .rs code.
//
////////////////////////////////////////////////////////////////////////////////

#include "ipcl/ipcl.hpp"
#include "ipcl/utils/util.hpp"
#include "defines.h"

using namespace ipcl;

PAILLIER_C_FUNC KeyPair_Create(int64_t n_length, bool enable_DJN, void **keypair);

PAILLIER_C_FUNC KeyPair_Destroy(void *thisptr)
{
  KeyPair *keypair = FromVoid<KeyPair>(thisptr);
  IfNullRet(keypair, E_POINTER);

  delete keypair;
  return S_OK;
}

// TODO(cgair): currently we still use the whole keypair to preform save/load
// operations, this should be removed after export the publickey class.
PAILLIER_C_FUNC PubKey_Save(void *thisptr, const char* file, unsigned int version)
{
  KeyPair *keypair = FromVoid<KeyPair>(thisptr);
  IfNullRet(keypair, E_POINTER);
  try 
  {
    keypair->pub_key.save_to_file(file, version);
    return S_OK;
  }
  catch (const std::runtime_error &)
  {
    return COR_E_IO;
  }
}

PAILLIER_C_FUNC PubKey_Load(void *thisptr, const char* file, unsigned int version)
{
  KeyPair *keypair = FromVoid<KeyPair>(thisptr);
  IfNullRet(keypair, E_POINTER);
  try 
  {
    keypair->pub_key.load_from_file(file, version);
    return S_OK;
  }
  catch (const std::runtime_error &)
  {
    return COR_E_IO;
  }
}

PAILLIER_C_FUNC KeyPair_Encrypt(void *thisptr, void *plaintext, void **destination) {
  KeyPair *keypair = FromVoid<KeyPair>(thisptr);
  IfNullRet(keypair, E_POINTER);
  PlainText *plaintextptr = FromVoid<PlainText>(plaintext);
  IfNullRet(plaintextptr, E_POINTER);

  IfNullRet(destination, E_POINTER);
  try 
  {
    keypair->pub_key.encrypt2(*plaintextptr, destination);
    return S_OK;
  }
  catch (const std::invalid_argument &)
  {
      return E_INVALIDARG;
  }
  catch (const std::logic_error &)
  {
      return COR_E_INVALIDOPERATION;
  }
}

PAILLIER_C_FUNC KeyPair_Decrypt(void *thisptr, void *encrypted, void **destination) 
{
  KeyPair *keypair = FromVoid<KeyPair>(thisptr);
  IfNullRet(keypair, E_POINTER);
  CipherText *encryptedptr = FromVoid<CipherText>(encrypted);
  IfNullRet(encryptedptr, E_POINTER);

  IfNullRet(destination, E_POINTER);

  try 
  {
    keypair->priv_key.decrypt2(*encryptedptr, destination);
    return S_OK;
  }
  catch (const std::invalid_argument &)
  {
      return E_INVALIDARG;
  }
  catch (const std::logic_error &)
  {
      return COR_E_INVALIDOPERATION;
  }
}

// Perform enc(x) + enc(y)
PAILLIER_C_FUNC Paillier_Add(void *lhs, void *rhs, void *destination) 
{
  CipherText *left = FromVoid<CipherText>(lhs);
  IfNullRet(left, E_POINTER);
  CipherText *right = FromVoid<CipherText>(rhs);
  IfNullRet(right, E_POINTER);
  CipherText *destinationptr = FromVoid<CipherText>(destination);
  IfNullRet(destinationptr, E_POINTER);

  *destinationptr = *left + *right;
  return S_OK;
}

// Perform enc(x) + y
PAILLIER_C_FUNC Paillier_Add2(void *lhs, void *rhs, void *destination) 
{
  CipherText *left = FromVoid<CipherText>(lhs);
  IfNullRet(left, E_POINTER);
  PlainText *right = FromVoid<PlainText>(rhs);
  IfNullRet(right, E_POINTER);
  CipherText *destinationptr = FromVoid<CipherText>(destination);
  IfNullRet(destinationptr, E_POINTER);

  *destinationptr = *left + *right;
  return S_OK;
}

// Perform enc(x) * y
PAILLIER_C_FUNC Paillier_Multiply(void *lhs, void *rhs, void *destination) 
{
  CipherText *left = FromVoid<CipherText>(lhs);
  IfNullRet(left, E_POINTER);
  PlainText *right = FromVoid<PlainText>(rhs);
  IfNullRet(right, E_POINTER);
  CipherText *destinationptr = FromVoid<CipherText>(destination);
  IfNullRet(destinationptr, E_POINTER);

  *destinationptr = *left * *right;
  return S_OK;
}
