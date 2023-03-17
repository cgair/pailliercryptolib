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
  std::cout << "  Example: Serialize and Deserialize  " << std::endl;
  std::cout << "======================================" << std::endl;

  ipcl::initializeContext("QAT");

  const uint32_t num_total = 20;

  /* KeyPair_Create */
  void *k1 = NULL;
  void **keypair1 = &k1;
  // long ret1 = KeyPair_Create(2048, true, keypair1);
  long ret1 = KeyPair_Create(2048, false, keypair1);
  assert (ret1 == 0);

  ipcl::KeyPair *key1 = ipcl::FromVoid<ipcl::KeyPair>(*keypair1);

  /* JSON Serialization */
  PubKey_Save(*keypair1, "key1.json", 0);

  {
    void *k2 = NULL;
    void **keypair2 = &k2;
    // long ret2 = KeyPair_Create(2048, true, keypair2);
    long ret2 = KeyPair_Create(2048, false, keypair2);
    assert (ret2 == 0);

    PubKey_Load(*keypair2, "key1.json", 0);
    PubKey_Save(*keypair2, "key2.json", 0);

    ipcl::KeyPair *key2 = ipcl::FromVoid<ipcl::KeyPair>(*keypair2);

    std::vector<uint32_t> vec(num_total);

    for (int i = 0; i < num_total; i++) {
      vec[i] = i;
    }

    ipcl::PlainText pt = ipcl::PlainText(vec);

    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    ipcl::CipherText ct = key2->pub_key.encrypt(pt);
    ipcl::PlainText dt = key1->priv_key.decrypt(ct);

    // verify result
    bool verify = true;
    for (int i = 0; i < num_total; i++) {
      std::vector<uint32_t> v = dt.getElementVec(i);
      if (v[0] != (vec[i])) {
        verify = false;
        break;
      }
    }
    
  }

  ipcl::setHybridOff();

  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl << std::endl;
}