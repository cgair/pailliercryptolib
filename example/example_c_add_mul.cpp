// Copyright (C) 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

/*
  Example of encryption and decryption
*/
#include <climits>
#include <iostream>
#include <random>
#include <vector>

#include <chrono>
#include <assert.h>     /* assert */

#include "ipcl/ipcl.hpp"
#include "ipcl/plaintext.hpp"
#include "ipcl/utils/util.hpp"
#include "ipcl/defines.h"

#include "ipcl/ipcl_c.h"
#include "ipcl/plaintext_c.h"
#include "ipcl/ciphertext_c.h"

int plaintext_create() {
  std::cout << std::endl;
  std::cout << "==============================================" << std::endl;
  std::cout << "       Test: PlainText Create Function        " << std::endl;
  std::cout << "==============================================" << std::endl;
  ipcl::initializeContext("QAT");

  ipcl::KeyPair key = ipcl::generateKeypair(2048, true);

  void *p1 = NULL;
  void **plaintext1 = &p1;

  long ret1 = PlainText_Create1(plaintext1);
  assert (ret1 == 0);

  void *p2 = NULL;
  void **plaintext2 = &p2;
  uint32_t input[] = {0, 1, 2, 3, 4, 5, 6, 7};
  for (int i = 0; i < 8; i ++) { std::cout << input[i] << " "; }
  std::cout << std::endl;

  long ret2 = PlainText_Create2(plaintext2, input, 8);
  assert (ret2 == 0);

  ipcl::PlainText *plain = ipcl::FromVoid<ipcl::PlainText>(*plaintext2);

  for (int i = 0; i < 8; i ++) {
    std::vector<uint32_t> p = (*plain).getElementVec(i);
    std::cout << p[0] << " ";
  }
  std::cout << std::endl;

  ipcl::terminateContext();
  std::cout << "Test Complete!" << std::endl << std::endl;

  return 0;
}

int add_mul() {
  std::cout << std::endl;
  std::cout << "==============================================" << std::endl;
  std::cout << "Example: Addition and Multiplication with IPCL" << std::endl;
  std::cout << "==============================================" << std::endl;

  ipcl::initializeContext("default");

  const uint32_t num_total = 1;

  // Generate keys
  void *k = NULL;
  void **keypair = &k;
  long ret1 = KeyPair_Create(2048, true, keypair);
  assert (ret1 == 0);
  ipcl::KeyPair *key = ipcl::FromVoid<ipcl::KeyPair>(*keypair);

  void *px = NULL;
  void *py = NULL;
  void **plaintext_x = &px;
  void **plaintext_y = &py;
  uint32_t x[num_total] = {10};
  uint32_t y[num_total] = {20};

  long ret2 = PlainText_Create2(plaintext_x, x, num_total);
  assert (ret2 == 0);
  long ret3 = PlainText_Create2(plaintext_y, y, num_total);
  assert (ret3 == 0);

  void *cx = NULL;
  void *cy = NULL;
  void **ciphertext_x = &cx;
  void **ciphertext_y = &cy;

  long ret4 = CipherText_Create1(ciphertext_x);
  assert (ret4 == 0);
  long ret5 = CipherText_Create1(ciphertext_y);
  assert (ret5 == 0);

  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  long ret6 = KeyPair_Encrypt(*keypair, *plaintext_x, ciphertext_x);
  assert (ret6 == 0);
  long ret7 = KeyPair_Encrypt(*keypair, *plaintext_y, ciphertext_y);
  assert (ret7 == 0);

  void *res1 = NULL;
  void **result1 = &res1;
  long ret8 = CipherText_Create1(result1);
  assert (ret8 == 0);

  long ret9 = Paillier_Add(*ciphertext_x, *ciphertext_y, *result1);
  assert (ret9 == 0);


  void *pr1 = NULL;
  void **plaintext_ret1 = &pr1;
  long ret88 = PlainText_Create1(plaintext_ret1);
  assert (ret88 == 0);
  long ret99 = KeyPair_Decrypt(*keypair, *result1, plaintext_ret1);
  assert (ret99 == 0);
  ipcl::PlainText *sum1 = ipcl::FromVoid<ipcl::PlainText>(*plaintext_ret1);

  // verify result
  bool verify = true;
  std::vector<uint32_t> v = (*sum1).getElementVec(0);
  std::cout << v[0] << std::endl;
  if (v[0] != (x[0] + y[0])) {
    verify = false;
  }
  std::cout << "Test (x + y) == dec(enc(x) + enc(y)) -- "
            << (verify ? "pass" : "fail") << std::endl
            << std::endl;

  void *res2 = NULL;
  void **result2 = &res2;
  long ret10 = CipherText_Create1(result2);
  assert (ret10 == 0);

  long ret11 = Paillier_Add2(*ciphertext_x, *plaintext_y, *result2);
  assert (ret11 == 0);

  void *pr2 = NULL;
  void **plaintext_ret2 = &pr2;
  long ret100 = PlainText_Create1(plaintext_ret2);
  assert (ret100 == 0);
  long ret110 = KeyPair_Decrypt(*keypair, *result2, plaintext_ret2);
  assert (ret110 == 0);
  ipcl::PlainText *sum2 = ipcl::FromVoid<ipcl::PlainText>(*plaintext_ret2);

  // verify result
  verify = true;
  std::vector<uint32_t> vv = (*sum2).getElementVec(0);
  std::cout << vv[0] << std::endl;
  if (vv[0] != (x[0] + y[0])) {
    verify = false;
  }
  std::cout << "Test (x + y) == dec(enc(x) + y) -- "
            << (verify ? "pass" : "fail") << std::endl
            << std::endl;

  void *res3 = NULL;
  void **result3 = &res3;
  long ret12 = CipherText_Create1(result3);
  assert (ret12 == 0);

  long ret13 = Paillier_Multiply(*ciphertext_x, *plaintext_y, *result3);
  assert (ret13 == 0);

  void *pr3 = NULL;
  void **plaintext_ret3 = &pr3;
  long ret120 = PlainText_Create1(plaintext_ret3);
  assert (ret120 == 0);
  long ret130 = KeyPair_Decrypt(*keypair, *result3, plaintext_ret3);
  assert (ret130 == 0);
  ipcl::PlainText *mul = ipcl::FromVoid<ipcl::PlainText>(*plaintext_ret3);


  // verify result
  verify = true;
  std::vector<uint32_t> vvv = (*mul).getElementVec(0);
  std::cout << vvv[0] << std::endl;
  if (vvv[0] != (x[0] * y[0])) {
    verify = false;
  }
  std::cout << "Test (x * y) == dec(enc(x) * y) -- "
            << (verify ? "pass" : "fail") << std::endl
            << std::endl;

  // ipcl::setHybridOff();

  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl;

  return 0;
}

int complet_flow() 
{
  std::cout << std::endl;
  std::cout << "==============================================" << std::endl;
  std::cout << "         Test: A Complete Work Flow           " << std::endl;
  std::cout << "==============================================" << std::endl;
  ipcl::initializeContext("QAT");

  const uint32_t num_total = 20;

  /* Key Generation */
  void *k = NULL;
  void **keypair = &k;
  long ret1 = KeyPair_Create(2048, true, keypair);
  assert (ret1 == 0);
  ipcl::KeyPair *key = ipcl::FromVoid<ipcl::KeyPair>(*keypair);

  /* PlainText Create */
  void *px = NULL;
  void *py = NULL;
  void **plaintext_x = &px;
  void **plaintext_y = &py;
  uint32_t x[num_total];
  uint32_t y[num_total];

  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(0,
                                                                UINT_MAX >> 16);

  for (int i = 0; i < num_total; i++) {
    x[i] = dist(rng);
    y[i] = dist(rng);
  }

  long ret2 = PlainText_Create2(plaintext_x, x, num_total);
  assert (ret2 == 0);
  long ret3 = PlainText_Create2(plaintext_y, y, num_total);
  assert (ret3 == 0);

  /* Place holder for CipherText */
  void *cx = NULL;
  void *cy = NULL;
  void **ciphertext_x = &cx;
  void **ciphertext_y = &cy;

  long ret4 = CipherText_Create1(ciphertext_x);
  assert (ret4 == 0);
  long ret5 = CipherText_Create1(ciphertext_y);
  assert (ret5 == 0);

  /* Do Encryption */
  long ret6 = KeyPair_Encrypt(*keypair, *plaintext_x, ciphertext_x);
  assert (ret6 == 0);
  long ret7 = KeyPair_Encrypt(*keypair, *plaintext_y, ciphertext_y);
  assert (ret7 == 0);

  /* Perform enc(x) + enc(y) */ 
  void *res = NULL;
  void **result = &res;
  long ret8 = CipherText_Create1(result);
  assert (ret8 == 0);

  long ret9 = Paillier_Add(*ciphertext_x, *ciphertext_y, *result);
  assert (ret9 == 0);

  /* Place holder for Plaintext */
  void *pr = NULL;
  void **plaintext_res = &pr;
  long ret10 = PlainText_Create1(plaintext_res);
  assert (ret10 == 0);

  /* Do Decryption */
  long ret11 = KeyPair_Decrypt(*keypair, *result, plaintext_res);
  assert (ret11 == 0);
  ipcl::PlainText *final_ret = ipcl::FromVoid<ipcl::PlainText>(*plaintext_res);

  // verify result
  bool verify = true;
  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v = (*final_ret).getElementVec(i);
    if (v[0] != (x[i] + y[i])) {
      verify = false;
      break;
    }
  }
  std::cout << "Test (x + y) == dec(enc(x) + enc(y)) -- "
            << (verify ? "pass" : "fail") << std::endl
            << std::endl;
  
  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl;

  return 0;
}

int functinality() {
  std::cout << std::endl;
  std::cout << "==============================================" << std::endl;
  std::cout << "                 Comparison                  " << std::endl;
  std::cout << "==============================================" << std::endl;
  ipcl::initializeContext("QAT");

  const uint32_t num_total = 20;

  void *k = NULL;
  void **keypair = &k;
  long ret0 = KeyPair_Create(2048, true, keypair);
  assert (ret0 == 0);
  ipcl::KeyPair *key = ipcl::FromVoid<ipcl::KeyPair>(*keypair);

  std::vector<uint32_t> n1(num_total);
  uint32_t n2[num_total];

  for (int i = 0; i < num_total; i++) {
    n1[i] = i;
    n2[i] = i;
  }

  void *pn = NULL;
  void **plaintext_n = &pn;

  ipcl::PlainText pt_n = ipcl::PlainText(n1);
  long ret1 = PlainText_Create2(plaintext_n, n2, num_total);
  assert (ret1 == 0);
  ipcl::PlainText * plain = ipcl::FromVoid<ipcl::PlainText>(*plaintext_n);

  
  size_t s, l;
  s = 0, l = 0;
  long r1 = PlainText_SaveSize(*plaintext_n, &s);
  assert (r1 == 0);
  std::cout << "size: " << s << std::endl;
  uint32_t save[num_total];
  // uint32_t *p = save;
  long r2 = PlainText_Save(*plaintext_n, save, s, &l);
  assert (r2 == 0);
  std::cout << "write len: " << l << std::endl;
  for (int i = 0; i < s; i ++) {
    std::cout << save[i] << " ";
  }
  std::cout << std::endl;

  /* PlainText: naive */
  // size_t size = pt_n.getSize();
  // for (int i = 0; i < size; i++) {
  //   std::vector<uint32_t> v1 = pt_n.getElementVec(i);
  //   std::cout << v1[0] << " ";
  // }
  // std::cout << std::endl;

  /* PlainText: export */
  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v2 = (*plain).getElementVec(i);
    std::cout << v2[0] << " ";
  }
  std::cout << std::endl;

  ipcl::CipherText ct_n = key->pub_key.encrypt(pt_n);

  void *cn = NULL;
  void **ciphertext_n = &cn;

  long ret4 = CipherText_Create1(ciphertext_n);
  assert (ret4 == 0);
  long ret5 = KeyPair_Encrypt(*keypair, *plaintext_n, ciphertext_n);
  assert (ret5 == 0);


  size_t s1, l1;
  s1 = 0, l1 = 0;
  long r3 = CipherText_SaveSize(*ciphertext_n, &s1);
  assert (r3 == 0);
  std::cout << "size: " << s1 << std::endl;
  uint32_t save1[num_total];
  long r4 = CipherText_Save(*ciphertext_n, save1, s1, &l1);
  assert (r4 == 0);
  std::cout << "write len: " << l1 << std::endl;
  for (int i = 0; i < s1; i ++) {
    std::cout << save1[i] << " ";
  }
  std::cout << std::endl;


  ipcl::CipherText * cipher = ipcl::FromVoid<ipcl::CipherText>(*ciphertext_n);

  /*
  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v3 = ct_n.getElementVec(i);
    std::cout << v3[0] << " ";
  }
  std::cout << std::endl;
  */

  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v4 = (*cipher).getElementVec(i);
    std::cout << v4[0] << " ";
  }
  std::cout << std::endl;


  /*
  ipcl::PlainText dt = key->priv_key.decrypt(ct_n);
  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v5 = dt.getElementVec(i);
    std::cout << v5[0] << " ";
  }
  std::cout << std::endl;

  void *pr = NULL;
  void **plaintext_res = &pr;
  long ret6 = PlainText_Create1(plaintext_res);
  assert (ret6 == 0);

  long ret7 = KeyPair_Decrypt(*keypair, *ciphertext_n, plaintext_res);
  assert (ret7 == 0);
  ipcl::PlainText *final_ret = ipcl::FromVoid<ipcl::PlainText>(*plaintext_res);

  for (int i = 0; i < num_total; i++) {
    std::vector<uint32_t> v6 = (*final_ret).getElementVec(i);
    std::cout << v6[0] << " ";
  }
  std::cout << std::endl;
  */

  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl;

  return 0;
}

#include <algorithm>
int main() {
  // plaintext_create();
  add_mul();

  // complet_flow();
  // functinality();
}
