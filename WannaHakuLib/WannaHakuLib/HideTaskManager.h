#pragma once

#ifdef HakuHideTaskManager_EXPORTS
#define HakuHideTaskManager_API __declspec(dllexport)
#else
#define HakuHideTaskManager_API __declspec(dllimport)
#endif

extern "C" HakuHideTaskManager_API bool blockUserTask(void);