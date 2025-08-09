#pragma once
#include "RPC-Lib/Utils.h"
#include <map>
#include <vector>

using std::map;
using std::vector;
using std::wstringstream;

void QueryEpm(map<wstring, vector<wstring>>& IfMap);
void CompareEpmResults(map<wstring, vector<wstring>>& EpmEarly, map<wstring, vector<wstring>>& EpmLate, wstringstream& OutStream);