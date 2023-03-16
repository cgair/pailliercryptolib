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
