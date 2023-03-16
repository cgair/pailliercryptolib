// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "ipcl/plaintext.hpp"

#include <algorithm>
#include <vector>

#include "ipcl/ciphertext.hpp"
#include "ipcl/utils/util.hpp"

namespace ipcl {

PlainText::PlainText(const uint32_t& n) : BaseText(n) {}

PlainText::PlainText(const std::vector<uint32_t>& n_v) : BaseText(n_v) {}

PlainText::PlainText(const BigNumber& bn) : BaseText(bn) {}

PlainText::PlainText(const std::vector<BigNumber>& bn_v) : BaseText(bn_v) {}

PlainText::PlainText(const PlainText& pt) : BaseText(pt) {}

PlainText& PlainText::operator=(const PlainText& other) {
  BaseText::operator=(other);

  return *this;
}

CipherText PlainText::operator+(const CipherText& other) const {
  return other.operator+(*this);
}

CipherText PlainText::operator*(const CipherText& other) const {
  return other.operator*(*this);
}

PlainText::operator std::vector<uint32_t>() const {
  ERROR_CHECK(m_size > 0,
              "PlainText: type conversion to uint32_t vector error");
  std::vector<uint32_t> v;
  m_texts[0].num2vec(v);

  return v;
}

PlainText::operator BigNumber() const {
  ERROR_CHECK(m_size > 0, "PlainText: type conversion to BigNumber error");
  return m_texts[0];
}

PlainText::operator std::vector<BigNumber>() const {
  ERROR_CHECK(m_size > 0,
              "PlainText: type conversion to BigNumber vector error");
  return m_texts;
}

PlainText PlainText::rotate(int shift) const {
  ERROR_CHECK(m_size != 1, "rotate: Cannot rotate single CipherText");
  ERROR_CHECK(shift >= -m_size && shift <= m_size,
              "rotate: Cannot shift more than the test size");

  if (shift == 0 || shift == m_size || shift == -m_size)
    return PlainText(m_texts);

  if (shift > 0)
    shift = m_size - shift;
  else
    shift = -shift;

  std::vector<BigNumber> new_bn = getTexts();
  std::rotate(std::begin(new_bn), std::begin(new_bn) + shift, std::end(new_bn));
  return PlainText(new_bn);
}

}  // namespace ipcl

#include "ipcl/plaintext_c.h"

PAILLIER_C_FUNC PlainText_Create1(void **plaintext) 
{
  IfNullRet(plaintext, E_POINTER);
  ipcl::PlainText *plain = new ipcl::PlainText();
  *plaintext = plain;

  return S_OK;
}

PAILLIER_C_FUNC PlainText_Create2(void **plaintext, uint32_t *input, int len) 
{
  IfNullRet(plaintext, E_POINTER);
  std::vector<uint32_t> n(input, input + len);
  ipcl::PlainText *plain = new ipcl::PlainText(n);
  *plaintext = plain;

  return S_OK;
}

PAILLIER_C_FUNC PlainText_Destroy(void *thisptr)
{
  ipcl::PlainText *plain = ipcl::FromVoid<ipcl::PlainText>(thisptr);
  IfNullRet(plain, E_POINTER);

  delete plain;
  return S_OK;
}

PAILLIER_C_FUNC PlainText_SaveSize(void *thisptr, size_t *result) {
  ipcl::PlainText *plain = ipcl::FromVoid<ipcl::PlainText>(thisptr);
  IfNullRet(plain, E_POINTER);
  IfNullRet(result, E_POINTER);

  *result = (*plain).getSize();
  return S_OK;
}

PAILLIER_C_FUNC PlainText_Save(void *thisptr, uint32_t *outptr, size_t size, size_t *out_len) {
  if (*out_len != 0) { return E_INVALIDARG; }

  ipcl::PlainText *plain = ipcl::FromVoid<ipcl::PlainText>(thisptr);
  IfNullRet(plain, E_POINTER);
  for (int i = 0; i < size; i ++) {
    std::vector<uint32_t> v = (*plain).getElementVec(i);
    *outptr = v[0];
    outptr += 1;
    *out_len = *out_len + 1;
  }
  
  return S_OK;
}