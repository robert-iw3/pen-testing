#pragma once
#include "QueryEPM.h"
#include "QueryProcesses.h"
#include <fstream>

wstring TASK_NAME = L"RPC-Recon";
const DWORD MILISECOND = 1;
const DWORD SECOND = MILISECOND * 1000;
const DWORD MINUTE = 60 * SECOND;
DWORD g_SleepTime = 5 * MINUTE;