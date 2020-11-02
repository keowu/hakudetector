#pragma once

#ifdef helloworld_EXPORTS
#define helloworld_API __declspec(dllexport)
#else
#define helloworld_API __declspec(dllimport)
#endif

extern "C" helloworld_API void helloworld(void);
