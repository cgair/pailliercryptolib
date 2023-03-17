// Copyright (C) 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

/*
  Example of encryption and decryption
*/
#include <climits>
#include <iostream>
#include <random>
#include <vector>

#include <assert.h>     /* assert */

#include "ipcl/ipcl.hpp"

#include "ipcl/plaintext.hpp"
#include "ipcl/utils/util.hpp"
#include "ipcl/defines.h"

#include "ipcl/ciphertext_c.h"
#include "ipcl/plaintext_c.h"
#include "ipcl/ipcl_c.h"

#include <cereal/archives/json.hpp>
#include <fstream>

int main() {
  std::cout << std::endl;
  std::cout << "======================================" << std::endl;
  std::cout << "Example: Encrypt and Decrypt with IPCL" << std::endl;
  std::cout << "======================================" << std::endl;

  ipcl::initializeContext("QAT");

  const uint32_t num_total = 20;

  // ipcl::KeyPair key = ipcl::generateKeypair(2048, true);

  /* KeyPair_Create */
  void *k = NULL;
  void **keypair = &k;
  long ret1 = KeyPair_Create(2048, true, keypair);
  assert (ret1 == 0);

  ipcl::KeyPair *key = ipcl::FromVoid<ipcl::KeyPair>(*keypair);
  int bits, dwords;
  bits = key->pub_key.getBits();
  dwords = key->pub_key.getDwords();
  std::cout << "bits: " << bits 
            << ", " << "dword: " << dwords << std::endl;

  std::vector<uint32_t> n(num_total);

  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(0,
                                                                UINT_MAX >> 16);

  for (int i = 0; i < num_total; i++) {
    n[i] = dist(rng);
  }

  ipcl::PlainText pt = ipcl::PlainText(n);

  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::CipherText ct = key->pub_key.encrypt(pt);
  ipcl::PlainText dt = key->priv_key.decrypt(ct);

  /* PlainText -> CipherText -> vector<uint32> -> CipherText -> PlainText */
  uint32_t n2[1] = {1};

  ipcl::PlainText pt_n2 = ipcl::PlainText(n2);
  std::vector<uint32_t> pp = pt_n2.getElementVec(0);
  std::cout << "To be encrypted: " << pp[0] << std::endl;

  ipcl::CipherText ct_n2 = key->pub_key.encrypt(pt_n2);

  ipcl::PlainText res = key->priv_key.decrypt(ct_n2);
  std::vector<uint32_t> ret = res.getElementVec(0);
  std::cout << "Decrypt result1: " << ret[0] << std::endl;

  std::vector<uint32_t> ct_v1 = ct_n2.getElementVec(0);
  uint32_t n3[1] = {ct_v1[0]};
  std::cout << " Before: " << n3[0];
  std::cout << std::endl;

  void *c = NULL;
  void **ciphertext = &c;
  long ret2 = CipherText_Create2(*keypair, ciphertext, n3, 1);
  assert (ret2 == 0);

  ipcl::CipherText *ct_n3 = ipcl::FromVoid<ipcl::CipherText>(*ciphertext);
  std::vector<uint32_t> ct_v3 = ct_n3->getElementVec(0);
  std::cout << "After: " << ct_v3[0];
  std::cout << std::endl;

  void *pr = NULL;
  void **plaintext_res = &pr;
  long ret3 = PlainText_Create1(plaintext_res);
  assert (ret3 == 0);
  /* Do Decryption */
  long ret4 = KeyPair_Decrypt(*keypair, *ciphertext, plaintext_res);
  assert (ret4 == 0);
  ipcl::PlainText *pt_n3 = ipcl::FromVoid<ipcl::PlainText>(*plaintext_res);

  std::vector<uint32_t> rett = pt_n3->getElementVec(0);
  std::cout << "Decrypt result2: " << rett[0] << std::endl;

  ipcl::setHybridOff();

  // verify result
  bool verify = true;
  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v = dt.getElementVec(i);
    if (v[0] != (n[i])) {
      verify = false;
      break;
    }
  }

  std::cout << "Test pt == dec(enc(pt)) -- " << (verify ? "pass" : "fail")
            << std::endl;
  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl << std::endl;
}
