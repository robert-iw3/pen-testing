#pragma once

#include <windows.h>
#include <map>

namespace threads_util {

	typedef struct _thread_info_ext
	{
		ULONGLONG sys_start_addr;
		DWORD state;
		DWORD wait_reason;
		DWORD wait_time;

		_thread_info_ext()
		{
			this->sys_start_addr = 0;
			this->state = 0;
			this->wait_reason = 0;
			this->wait_time = 0;
		}

		_thread_info_ext(const _thread_info_ext& other)
		{
			this->sys_start_addr = other.sys_start_addr;
			this->state = other.state;
			this->wait_reason = other.wait_reason;
			this->wait_time = other.wait_time;
		}

	} thread_info_ext;

	typedef struct _thread_info
	{
		DWORD tid;
		ULONGLONG start_addr;
		bool is_extended;
		thread_info_ext ext;

		_thread_info(DWORD _tid = 0)
			: tid(_tid),
			start_addr(0),
			is_extended(false)
		{
		}

		_thread_info(const _thread_info& other)
		{
			this->tid = other.tid;
			this->start_addr = other.start_addr;
			this->is_extended = other.is_extended;
			this->ext = other.ext;
		}

	} thread_info;

	bool query_threads_details(IN OUT std::map<DWORD, thread_info>& threads_info);

	bool fetch_threads_info(IN DWORD pid, OUT std::map<DWORD, thread_info>& threads_info);

	template <typename PTR_T>
	PTR_T read_return_ptr(IN HANDLE hProcess, IN ULONGLONG Rsp) {
		PTR_T ret_addr = 0;
		SIZE_T readSize = 0;
		if (ReadProcessMemory(hProcess, (LPVOID)Rsp, (BYTE*)&ret_addr, sizeof(ret_addr), &readSize) && readSize == sizeof(ret_addr)) {
			return ret_addr;
		}
		return NULL;
	}

	inline bool read_context(DWORD tid, CONTEXT& ctx)
	{
		DWORD thAccess = THREAD_GET_CONTEXT;
		HANDLE hThread = OpenThread(thAccess, 0, tid);
		if (!hThread) return false;

		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (!GetThreadContext(hThread, &ctx)) {
			CloseHandle(hThread);
			return false;
		}
		CloseHandle(hThread);
		return true;
	}

}; // namespace threads_util
