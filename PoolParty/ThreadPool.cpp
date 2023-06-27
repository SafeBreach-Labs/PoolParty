#include "ThreadPool.hpp"

PFULL_TP_WORK w_CreateThreadpoolWork(PTP_WORK_CALLBACK pWorkCallback, PVOID pWorkContext, PTP_CALLBACK_ENVIRON pCallbackEnviron) {
	auto pWorkItem = (PFULL_TP_WORK)CreateThreadpoolWork(pWorkCallback, pWorkContext, NULL);
	if (pWorkItem == NULL) {
		throw std::runtime_error(GetLastErrorString("CreateThreadpoolWork", GetLastError()));
	}

	return pWorkItem;
}

PFULL_TP_WAIT w_CreateThreadpoolWait(PTP_WAIT_CALLBACK pWaitCallback, PVOID pWaitContext, PTP_CALLBACK_ENVIRON pCallbackEnviron) {
	auto pWait = (PFULL_TP_WAIT)CreateThreadpoolWait(pWaitCallback, pWaitCallback, pCallbackEnviron);
	if (pWait == NULL) {
		throw std::runtime_error(GetLastErrorString("CreateThreadpoolWait", GetLastError()));
	}
	return pWait;
}

PFULL_TP_IO w_CreateThreadpoolIo(HANDLE hFile, PTP_WIN32_IO_CALLBACK pCallback, PVOID pContext, PTP_CALLBACK_ENVIRON pCallbackEnviron) {
	auto pTpIo = (PFULL_TP_IO)CreateThreadpoolIo(hFile, pCallback, pContext, pCallbackEnviron);
	if (pTpIo == NULL) {
		throw std::runtime_error(GetLastErrorString("CreateThreadpoolIo", GetLastError()));
	}
	return pTpIo;
}

PFULL_TP_ALPC w_TpAllocAlpcCompletion(HANDLE hAlpc, PTP_ALPC_CALLBACK pCallback, PVOID Context, PTP_CALLBACK_ENVIRON pCallbackEnviron) 
{
	PFULL_TP_ALPC pTpAlpc = { 0 };
	auto Ntstatus = TpAllocAlpcCompletion(&pTpAlpc, hAlpc, pCallback, Context, pCallbackEnviron);
	if (!NT_SUCCESS(Ntstatus)) 
	{
		throw std::runtime_error(GetLastErrorString("TpAllocAlpcCompletion", RtlNtStatusToDosError(Ntstatus)));
	}

	return pTpAlpc;
}

PFULL_TP_JOB w_TpAllocJobNotification(HANDLE hJob, PVOID pCallback, PVOID Context, PTP_CALLBACK_ENVIRON pCallbackEnviron)
{
	PFULL_TP_JOB TpJob = { 0 };
	auto Ntstatus = TpAllocJobNotification(&TpJob, hJob, pCallback, Context, pCallbackEnviron);
	if (!NT_SUCCESS(Ntstatus))
	{
		throw std::runtime_error(GetLastErrorString("TpAllocJobNotification", RtlNtStatusToDosError(Ntstatus)));
	}

	return TpJob;
}