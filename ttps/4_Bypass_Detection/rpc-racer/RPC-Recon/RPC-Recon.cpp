#include "RPC-Recon.h"

void PrintHelp()
{
	wcout << "usage: RPC-Recon.exe [/register]" << endl;
}

bool CheckParams(int argc, wchar_t* argv[])
{
	if (argc >= 3)
	{
		wstring param = argv[1];
		if (!param.compare(L"-h") || !param.compare(L"--help"))
		{
			PrintHelp();
			return false;
		}
		else
		{
			if (!param.compare(L"-s"))
			{
				int numberOfMinutes = _wtoi(argv[2]);
				g_SleepTime = numberOfMinutes * MINUTE;
			}
			else
			{
				wcout << L"invalid parameter" << endl;
				PrintHelp();
				return false;
			}
		}
	}
	return true;
}

// Create the log file in the same folder as the executable
void LogReconData(wstringstream& DataStream)
{
	DWORD size = MAX_PATH;
	wchar_t exePath[MAX_PATH] = {};
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, exePath, &size);
	wstring exePathStr = exePath;
	size_t it = exePathStr.find_last_of(L"\\");
	wstring logPath = exePathStr.substr(0, it);
	logPath.append(L"\\RPC-Recon.txt");
	std::wofstream logStream(logPath.c_str(), std::ios::out);
	if (logStream.good())
	{
		logStream << DataStream.rdbuf();
		logStream.close();
	}
	else
	{
		wcout << L"writing to " << logPath << L" failed" << endl;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	try
	{
		if (argc > 1)
		{
			wstring param = argv[1];
			if (!param.compare(L"-h") || !param.compare(L"--help"))
			{
				PrintHelp();
				return EXIT_SUCCESS;
			}
			else
			{
				if (!param.compare(L"/register"))
				{
					wstring taskArgument;
					RegisterScheduledTask(TASK_NAME, taskArgument, true);
					return EXIT_SUCCESS;
				}
				else
				{
					wcout << L"invalid parameter" << endl;
					PrintHelp();
					return EXIT_SUCCESS;
				}
			}
		}

		wstringstream reconStream;
		reconStream << L"--------------------------------------------" << endl;
		reconStream << L"|             EPM Recon Results            |" << endl;
		reconStream << L"--------------------------------------------" << endl;

		// Gather data on dynamic endpoints
		map<wstring, vector<wstring>> epmEarly;
		map<wstring, vector<wstring>> epmLate;
		QueryEpm(epmEarly);

		// Gather data on well-known endpoints
		map<DWORD, map<wstring, vector<wstring>>> procsEarly;
		map<DWORD, map<wstring, vector<wstring>>> procsLate;
		QueryProcesses(procsEarly);
		wcout << L"First EPM recon found " << epmEarly.size() << L" UUIDs" << endl;
		wcout << L"First processes recon found " << procsEarly.size() << L" RPC servers" << endl;

		// Wait for delayed services to start
		wcout << L"Sleeping for " << g_SleepTime / MINUTE << L" minutes" << endl;
		Sleep(g_SleepTime);

		// Gather data again after the services started
		QueryEpm(epmLate);
		QueryProcesses(procsLate);
		wcout << L"Second EPM recon found " << epmLate.size() << L" UUIDs" << endl;
		wcout << L"Second processes recon found " << procsLate.size() << L" RPC servers" << endl;

		// Find which interfaces are registered late
		CompareEpmResults(epmEarly, epmLate, reconStream);
		reconStream << L"|          Processes Recon Results         |" << endl;
		reconStream << L"--------------------------------------------" << endl;
		CompareProcsResults(procsEarly, procsLate, reconStream);
		LogReconData(reconStream);
		wcout << L"Press enter to exit" << endl;
		getchar();
	}
	catch (std::exception& ex)
	{
		cout << ex.what() << endl;
	}
	catch (...)
	{
		cout << "Unknown exception occured" << endl;
	}

}