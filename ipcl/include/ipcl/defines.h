#pragma once

#ifdef _MSC_VER

// Check that architecture (platform) is x64
#ifndef _WIN64
static_assert(false, "Require architecture == x64");
#endif

#if defined(PAILLIER_C_EXPORTS) || defined(paillier_c_EXPORTS) || defined(paillierc_EXPORTS)
#define PAILLIER_C_DECOR extern "C" __declspec(dllexport)
#else
#define PAILLIER_C_DECOR extern "C" __declspec(dllimport)
#endif

#define PAILLIER_C_CALL __cdecl

#else // _MSC_VER

#define PAILLIER_C_DECOR extern "C"
#define PAILLIER_C_CALL

#define HRESULT long

#define _HRESULT_TYPEDEF_(hr) ((HRESULT)hr)

#define E_POINTER _HRESULT_TYPEDEF_(0x80004003L)
#define E_INVALIDARG _HRESULT_TYPEDEF_(0x80070057L)
#define E_UNEXPECTED _HRESULT_TYPEDEF_(0x8000FFFFL)
#define COR_E_IO _HRESULT_TYPEDEF_(0x80131620L)
#define COR_E_INVALIDOPERATION _HRESULT_TYPEDEF_(0x80131509L)

#define S_OK _HRESULT_TYPEDEF_(0L)

#endif // _MSC_VER

#define IfNullRet(expr, ret)   \
    {                          \
        if ((expr) == nullptr) \
        {                      \
            return ret;        \
        }                      \
    }

#define IfFailRet(expr)          \
    {                            \
        HRESULT __hr__ = (expr); \
        if (FAILED(__hr__))      \
        {                        \
            return __hr__;       \
        }                        \
    }


#define PAILLIER_C_FUNC PAILLIER_C_DECOR HRESULT PAILLIER_C_CALL