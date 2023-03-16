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

  // ipcl::KeyPair key = ipcl::generateKeypair(2048, true);

  /* KeyPair_Create */
  void *k = NULL;
  void **keypair = &k;
  long ret1 = KeyPair_Create(2048, true, keypair);
  assert (ret1 == 0);

  ipcl::KeyPair *key = ipcl::FromVoid<ipcl::KeyPair>(*keypair);
  // ipcl::KeyPair key2 = ipcl::generateKeypair(2048, true);

  /* JSON Serialization */
  /*
  {
    std::ofstream os("key.json");
    cereal::JSONOutputArchive archive(os); // Create an output archive

    std::vector<uint32_t> vec1;
    key->pub_key.getN()->num2vec(vec1);
    std::cout << "Before se: ";
    for (int i = 0; i < vec1.size(); i ++) {
      std::cout << vec1[i] << " ";
    }
    std::cout << std::endl;

    key->pub_key.save(archive, 1);

    std::vector<uint32_t> vec2;
    key->pub_key.getN()->num2vec(vec2);
    std::cout << "After se: ";
    for (int i = 0; i < vec2.size(); i ++) {
      std::cout << vec2[i] << " ";
    }
    std::cout << std::endl;
    // key2.pub_key.save(archive, 1);
  } // archive goes out of scope, ensuring all contents are flushed

  {
    std::ifstream is("key.json");
    cereal::JSONInputArchive archive(is); // Create an input archive

    ipcl::KeyPair key2 = ipcl::generateKeypair(2048, true);
    assert (key2.pub_key.getN() != 0);
    key2.pub_key.load(archive, 1);
    std::vector<uint32_t> vec2;
    key2.pub_key.getN()->num2vec(vec2);
    std::cout << "After de: ";
    for (int i = 0; i < vec2.size(); i ++) {
      std::cout << vec2[i] << " ";
    }
    std::cout << std::endl;

    std::vector<uint32_t> vec(num_total);

    for (int i = 0; i < num_total; i++) {
      vec[i] = i;
    }

    ipcl::PlainText pt = ipcl::PlainText(vec);

    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    ipcl::CipherText ct = key2.pub_key.encrypt(pt);
    ipcl::PlainText dt = key->priv_key.decrypt(ct);

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
  */

  ipcl::setHybridOff();

  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl << std::endl;
}