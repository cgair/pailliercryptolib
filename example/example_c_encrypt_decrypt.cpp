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

int c_api() {
  // Get keypairs
  void *k = NULL;
  void **keypair = &k;
  long ret1 = KeyPair_Create(2048, true, keypair);
  assert (ret1 == 0);
  ipcl::KeyPair *key = ipcl::FromVoid<ipcl::KeyPair>(*keypair);

  // Create PlainText 
  void *px = NULL;
  void *py = NULL;
  void **plaintext_x = &px;
  uint32_t x[1] = {13};

  long ret2 = PlainText_Create2(plaintext_x, x, 1);
  assert (ret2 == 0);

  void *cx = NULL;
  void **ciphertext_x = &cx;
  long ret3 = CipherText_Create1(ciphertext_x);
  assert (ret3 == 0);
  long ret33 = KeyPair_Encrypt(*keypair, *plaintext_x, ciphertext_x);
  assert (ret33 == 0);

  long ret4 = CipherText_Save2(*ciphertext_x, "ciphertext.json", 1);
  assert (ret4 == 0);

  void *cxx = NULL;
  void **ciphertext_xx = &cxx;
  long ret5 = CipherText_Create1(ciphertext_xx);
  assert (ret5 == 0);
  long ret55 = CipherText_Load2(key, ciphertext_xx, "ciphertext.json", 1);
  assert (ret55 == 0);

  void *pr1 = NULL;
  void **plaintext_ret1 = &pr1;
  long ret6 = PlainText_Create1(plaintext_ret1);
  assert (ret6 == 0);

  void *pr2 = NULL;
  void **plaintext_ret2 = &pr2;
  long ret7 = PlainText_Create1(plaintext_ret2);
  assert (ret7 == 0);

  long ret9 = KeyPair_Decrypt(*keypair, *ciphertext_x, plaintext_ret1);
  assert (ret9 == 0);
  long ret10 = KeyPair_Decrypt(*keypair, *ciphertext_xx, plaintext_ret2);
  assert (ret10 == 0);

  ipcl::PlainText *result1 = ipcl::FromVoid<ipcl::PlainText>(*plaintext_ret1);
  ipcl::PlainText *result2 = ipcl::FromVoid<ipcl::PlainText>(*plaintext_ret2);
  std::vector<uint32_t> v = result1->getElementVec(0);
  std::vector<uint32_t> vv = result2->getElementVec(0);
  std::cout << v[0] << " == " << vv[0] <<std::endl;

  return 0;
}

int naive_api() {
  ipcl::KeyPair key = ipcl::generateKeypair(2048, true);

  // PlainText -> CipherText -> vector<uint32_t> -> CipherText -> PlainText
  std::vector<uint32_t> n = {13};
  ipcl::PlainText pt_n1 = ipcl::PlainText(n);
  std::vector<uint32_t> pt = pt_n1.getElementVec(0);
  std::cout << "To be encrypted: " << pt[0] << std::endl;

  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  ipcl::CipherText ct_n1 = key.pub_key.encrypt(pt_n1);
  BigNumber ct_bg = ct_n1.getElement(0);
  std::cout << "After encrypted(BigBumber):" << ct_bg << std::endl;
  std::vector<uint32_t> ct = ct_n1.getElementVec(0);
  std::cout << "After encrypted(Vec):" << ct[0] << std::endl;
  std::string ct_s = ct_n1.getElementHex(0);
  std::cout << "After encrypted(hex):" << ct_s << std::endl;

  // Way 1: through vector<uint32_t>: (X)
  // size_t ct_size = ct_n1.getSize();
  // std::vector<BigNumber> ct_bgn(ct_size);
  // for (int i = 0; i < ct_size; i ++) { ct_bgn[i] = ct[i]; }
  // BigNumber ct_bgg1 = BigNumber(ct_bgn[0]);
  // assert (ct_bg == ct_bgg1);

  // ipcl::CipherText * ct_n2 = new ipcl::CipherText(key.pub_key, ct);
  // ipcl::CipherText * ct_n2 = new ipcl::CipherText(key.pub_key, ct_bgn);

  // Way 2: through hex string: (V)
  std::string s;
  ct_bg.num2hex(s);
  assert (s == ct_s);
  // [Convert a std::string to char* in C++](https://www.techiedelight.com/convert-std-string-char-cpp/)
  // std::vector<char> chars(s.begin(), s.end());
  // char *c = &chars[0];
  // OR
  // char* c = &*s.begin();

  {
    std::ofstream os("bg.json");
    cereal::JSONOutputArchive archive(os); // Create an output archive 
    ct_bg.save(archive, 1);
  }

  std::ifstream is("bg.json");
  cereal::JSONInputArchive archive(is); // Create an input archive
  BigNumber bg = BigNumber();
  bg.load(archive, 1);
  // BigNumber ct_bgg2 = BigNumber(c);
  // std::cout << "Construct BigBumber(from hex string):" << ct_bgg2 << std::endl;
  // assert (ct_bg == ct_bgg2);
  assert (ct_bg == bg);

  ipcl::CipherText * ct_n2 = new ipcl::CipherText(key.pub_key, bg);

  std::vector<uint32_t> ctt = ct_n2->getElementVec(0);
  std::cout << "  After restore:" << ctt[0] << std::endl;
  
  std::cout << "ct1_size = " << ct_n1.getSize() << std::endl;
  std::cout << "ct2_size = " << ct_n2->getSize() << std::endl;

  std::vector<BigNumber> ct1_text = ct_n1.getTexts();
  std::vector<BigNumber> ct2_text = ct_n2->getTexts();
  for (int i = 0; i < ct_n1.getSize(); i ++) { std::cout << "ct1_text:" << ct1_text[i] << " " << std::endl; }
  for (int i = 0; i < ct_n2->getSize(); i ++) { std::cout << "ct2_text:" << ct2_text[i] << " " << std::endl; }

  assert (ct_n1.getSize() == ct_n2->getSize());
  assert (ct_n1.getTexts() == ct_n2->getTexts());
  
  ipcl::PlainText ct_n1_res = key.priv_key.decrypt(ct_n1);
  std::vector<uint32_t> ret = ct_n1_res.getElementVec(0);
  std::cout << "Decrypt result1: " << ret[0] << std::endl;

  ipcl::PlainText ct_n2_res = key.priv_key.decrypt(*ct_n2);
  std::vector<uint32_t> rett = ct_n2_res.getElementVec(0);
  std::cout << "Decrypt result2: " << rett[0] << std::endl;

  // ipcl::setHybridOff();
  return 0;
}

int main() {
  std::cout << std::endl;
  std::cout << "======================================" << std::endl;
  std::cout << "Example: Encrypt and Decrypt with IPCL" << std::endl;
  std::cout << "======================================" << std::endl;

  ipcl::initializeContext("QAT");
  // naive_api();
  c_api();
  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl << std::endl;
}