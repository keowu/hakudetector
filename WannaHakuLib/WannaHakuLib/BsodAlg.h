#pragma once

#ifdef BsodAlg_EXPORTS
#define BsodAlg_API __declspec(dllexport)
#else
#define BsodAlg_API __declspec(dllimport)
#endif

extern "C" BsodAlg_API void BSOD_DEATH(void);
