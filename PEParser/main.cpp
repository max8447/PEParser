#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <ctime>

#include <windows.h>

#include <BinaryReader/BinaryReader.h>
#include <CmdLineParser/CmdLineParser.h>

DWORD ToRealAddress(const IMAGE_NT_HEADERS& NTHeader, LONGLONG NTHeaderStart, BinaryReader& Reader, DWORD RVA);
std::string ReadString(BinaryReader& Reader, DWORD StringAddress);
std::string ReadString(BinaryReader& Reader);

std::string MachineToString(WORD Machine);
std::string TimeDateStampToString(DWORD TimeDateStamp);
std::string FileCharacteristicsToString(WORD Characteristics);
std::string MagicToString(WORD Magic);
std::string SubsystemToString(WORD Subsystem);
std::string SectionCharacteristicsToString(DWORD Characteristics);

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Usage: %s [FILE] [OPTION...]\n", argv[0]);
		return 0;
	}

#define DEFINE_CMDLINE_FIELDS(Define)           \
Define(bool, bShowHelp, "--help", false);		\
Define(bool, bShowAll, "-showall", false);		\
Define(bool, bShowSections, "-s", false);		\
Define(bool, bShowImports, "-i", false);		\
Define(bool, bShowExports, "-e", false);		\
Define(bool, bShowTlsEntries, "-t", false);		\
Define(bool, bShowDebugDir, "-d", false);

	DEFINE_CMDLINE(CmdLine);

	if (!PARSE_CMDLINE(CmdLine, argc, argv))
	{
		printf("Failed to parse command line.\n");
		return 1;
	}

	if (CmdLine.bShowHelp)
	{
		printf("Usage: %s [FILE] [OPTION...]\n", argv[0]);

		printf(R"(Options:
--help: Show this message
-showall: Show all available info
-s: Show sections
-i: Show imports
-e: Show exports
-t: Show TLS callbacks
-d: Show debug info
		)");

		return 0;
	}

	char* FilePath = argv[1];

	std::ifstream FileStream(FilePath, std::ios::binary | std::ios::ate);

	if (!FileStream || !FileStream.is_open())
	{
		printf("Failed to open file %s.\n", FilePath);
		return 1;
	}

	std::streamsize FileStreamSize = FileStream.tellg();
	std::vector<char> FileStreamData(FileStreamSize);

	FileStream.seekg(0);
	if (!FileStream.read(FileStreamData.data(), FileStreamSize))
	{
		printf("Failed to read file %s.\n", FilePath);
		return 1;
	}

	FileStream.close();

	printf("File Size: %.2f KB\n", (double)FileStreamSize / 1024.0);

	BinaryReader FileReader(FileStreamData.data(), FileStreamSize);

	char Magic[3] = { 0 };
	FileReader.ReadChars(Magic, 2);

	printf("DOS Magic: %s\n", Magic);

	if (memcmp(Magic, "MZ", sizeof(Magic) - 1) != 0)
	{
		printf("File %s is not a valid PE file (invalid DOS magic).\n", FilePath);
		return 1;
	}

	FileReader.SetPos(0);

	IMAGE_DOS_HEADER DOSHeader;
	FileReader.Read(DOSHeader);

	LONGLONG NTHeaderStart = DOSHeader.e_lfanew;

	FileReader.SetPos(NTHeaderStart);

	IMAGE_NT_HEADERS NTHeader;
	FileReader.Read(NTHeader);

	FileReader.SetPos(NTHeaderStart);

	char Signature[4] = { 0 };
	FileReader.ReadChars(Signature);

	printf("NT Signature: %s\n", Signature);

	if (memcmp(&NTHeader.Signature, "PE\0\0", sizeof(NTHeader.Signature)) != 0)
	{
		printf("File %s is not a valid PE file (invalid NT signature).\n", FilePath);
		return 1;
	}

	printf("File header:\n");
	printf("\tMachine: %s\n", MachineToString(NTHeader.FileHeader.Machine).c_str());
	printf("\tNumber of sections: %hu\n", NTHeader.FileHeader.NumberOfSections);
	printf("\tTime date stamp: %s\n", TimeDateStampToString(NTHeader.FileHeader.TimeDateStamp).c_str());
	printf("\tPointer to symbol table: 0x%lX\n", NTHeader.FileHeader.PointerToSymbolTable);
	printf("\tNumber of symbols: %lu\n", NTHeader.FileHeader.NumberOfSymbols);
	printf("\tSize of optional header: 0x%X\n", NTHeader.FileHeader.SizeOfOptionalHeader);
	printf("\tCharacteristics: %s\n", FileCharacteristicsToString(NTHeader.FileHeader.Characteristics).c_str());

	printf("Optional header:\n");
	printf("\tMagic: %s\n", MagicToString(NTHeader.OptionalHeader.Magic).c_str());
	printf("\tImage Base: 0x%llX\n", NTHeader.OptionalHeader.ImageBase);
	printf("\tSize of image: 0x%lX (%ld KB)\n", NTHeader.OptionalHeader.SizeOfImage, NTHeader.OptionalHeader.SizeOfImage / 0x400);
	printf("\tAddress of entry point: 0x%lX (0x%llX)\n", NTHeader.OptionalHeader.AddressOfEntryPoint, NTHeader.OptionalHeader.ImageBase + NTHeader.OptionalHeader.AddressOfEntryPoint);
	printf("\tSection alignment: 0x%lX\n", NTHeader.OptionalHeader.SectionAlignment);
	printf("\tSize of headers: 0x%lX\n", NTHeader.OptionalHeader.SizeOfHeaders);
	printf("\tSubsystem: %s\n", SubsystemToString(NTHeader.OptionalHeader.Subsystem).c_str());

	if (CmdLine.bShowSections || CmdLine.bShowAll)
	{
		printf("Sections:\n");

		for (WORD i = 0; i < NTHeader.FileHeader.NumberOfSections; i++)
		{
			FileReader.SetPos(
				NTHeaderStart + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NTHeader.FileHeader.SizeOfOptionalHeader + (IMAGE_SIZEOF_SECTION_HEADER * i)
			);

			IMAGE_SECTION_HEADER Section;
			FileReader.Read(Section);

			printf("\t%s:\n", Section.Name);
			printf("\t\tVirtual size: 0x%lX\n", Section.Misc.VirtualSize);
			printf("\t\tVirtual address: 0x%lX (0x%llX)\n", Section.VirtualAddress, NTHeader.OptionalHeader.ImageBase + Section.VirtualAddress);
			printf("\t\tSize of raw data: 0x%lX\n", Section.SizeOfRawData);
			printf("\t\tPointer to raw data: 0x%lX\n", Section.PointerToRawData);
			printf("\t\tPointer to relocations: 0x%lX\n", Section.PointerToRelocations);
			printf("\t\tPointer to line numbers: 0x%lX\n", Section.PointerToLinenumbers);
			printf("\t\tNumber of relocations: %hu\n", Section.NumberOfRelocations);
			printf("\t\tNumber of line numbers: %hu\n", Section.NumberOfLinenumbers);
			printf("\t\tCharacteristics: %s\n", SectionCharacteristicsToString(Section.Characteristics).c_str());
		}
	}

	if (CmdLine.bShowExports || CmdLine.bShowAll)
	{
		if (NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			DWORD RealExportAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			FileReader.SetPos(RealExportAddress);

			IMAGE_EXPORT_DIRECTORY ExportDirectory;
			FileReader.Read(ExportDirectory);

			DWORD RealNameAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, ExportDirectory.Name);

			printf("Export directory for %s\n", ReadString(FileReader, RealNameAddress).c_str());

			DWORD RealAddressOfNames = ToRealAddress(NTHeader, NTHeaderStart, FileReader, ExportDirectory.AddressOfNames);

			if (RealAddressOfNames)
			{
				FileReader.SetPos(RealAddressOfNames);

				printf("Exports (%ld):\n", ExportDirectory.NumberOfNames);

				for (DWORD i = 0; i < ExportDirectory.NumberOfNames; i++)
				{
					DWORD NameAddress = FileReader.ReadUInt();
					DWORD RealNameAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, NameAddress);

					if (RealNameAddress)
					{
						printf("\t%s\n", ReadString(FileReader, RealNameAddress).c_str());
					}
				}
			}
		}
		else
		{
			printf("No (named) exports.\n");
		}
	}

	if (CmdLine.bShowImports || CmdLine.bShowAll)
	{
		if (NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
			NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			DWORD RealImportAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			FileReader.SetPos(RealImportAddress);

			IMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
			FileReader.Read(ImportDescriptor);

			if (ImportDescriptor.OriginalFirstThunk)
			{
				printf("Imports:\n");
			}

			while (ImportDescriptor.OriginalFirstThunk)
			{
				ULONGLONG OldPos = FileReader.GetPos();

				DWORD RealNameAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, ImportDescriptor.Name);

				if (RealNameAddress)
				{
					printf("\t%s:\n", ReadString(FileReader, RealNameAddress).c_str());
				}

				DWORD RealOriginalFirstThunkAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, ImportDescriptor.OriginalFirstThunk);

				if (RealOriginalFirstThunkAddress)
				{
					FileReader.SetPos(RealOriginalFirstThunkAddress);

					while (ULONGLONG ImportNameAddress = FileReader.ReadULongLong())
					{
						DWORD RealImportNameAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, ImportNameAddress);

						if (RealImportNameAddress)
						{
							// there's a word here, of which i have no clue what it does, so we skip it
							printf("\t\t%s\n", ReadString(FileReader, RealImportNameAddress + 2).c_str());
						}
					}
				}

				FileReader.SetPos(OldPos);
				FileReader.Read(ImportDescriptor);
			}
		}
		else
		{
			printf("No imports.\n");
		}
	}

	if (CmdLine.bShowTlsEntries || CmdLine.bShowAll)
	{
		if (NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress &&
			NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			DWORD RealTlsAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			
			FileReader.SetPos(RealTlsAddress);

			IMAGE_TLS_DIRECTORY TlsDirectory;
			FileReader.Read(TlsDirectory);

			DWORD RealAddressOfCallBacks = ToRealAddress(NTHeader, NTHeaderStart, FileReader, TlsDirectory.AddressOfCallBacks - NTHeader.OptionalHeader.ImageBase);

			FileReader.SetPos(RealAddressOfCallBacks);

			int NumTLSCallbacks = 0;

			while (ULONGLONG TlsCallback = FileReader.ReadULongLong())
			{
				NumTLSCallbacks++;
			}

			if (NumTLSCallbacks > 0)
			{
				printf("TLS callbacks (%d):\n", NumTLSCallbacks);

				int TLSCallbackNum = 1;

				FileReader.SetPos(RealAddressOfCallBacks);

				while (ULONGLONG TlsCallback = FileReader.ReadULongLong())
				{
					printf("\tTLS callback %d: 0x%llX\n", TLSCallbackNum, TlsCallback - NTHeader.OptionalHeader.ImageBase);

					TLSCallbackNum++;
				}

				NumTLSCallbacks--;
			}
		}
		else
		{
			printf("No Tls directory.\n");
		}
	}

	if (CmdLine.bShowDebugDir || CmdLine.bShowAll)
	{
		if (NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress &&
			NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size)
		{
			DWORD RealDebugAddress = ToRealAddress(NTHeader, NTHeaderStart, FileReader, NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

			FileReader.SetPos(RealDebugAddress);

			DWORD DebugDirectoriesSize = NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

			while (DebugDirectoriesSize)
			{
				IMAGE_DEBUG_DIRECTORY DebugDirectory;
				FileReader.Read(DebugDirectory);

				if (DebugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW)
				{
					DWORD RealAddressOfRawData = ToRealAddress(NTHeader, NTHeaderStart, FileReader, DebugDirectory.AddressOfRawData);

					FileReader.SetPos(RealAddressOfRawData);

					FileReader.Skip(4llu); // CV signature
					FileReader.Skip(16llu); // GUID
					FileReader.Skip(4llu); // Age

					printf("PDB is located at %s\n", ReadString(FileReader).c_str());
				}

				DebugDirectoriesSize -= sizeof(DebugDirectory);
			}
		}
		else
		{
			printf("No debug directory.\n");
		}
	}

	return 0;
}

DWORD ToRealAddress(const IMAGE_NT_HEADERS& NTHeader, LONGLONG NTHeaderStart, BinaryReader& Reader, DWORD RVA)
{
	ULONGLONG OldPos = Reader.GetPos();

	DWORD Out = 0;

	for (WORD i = 0; i < NTHeader.FileHeader.NumberOfSections; i++)
	{
		Reader.SetPos(
			NTHeaderStart + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NTHeader.FileHeader.SizeOfOptionalHeader + (IMAGE_SIZEOF_SECTION_HEADER * i)
		);

		IMAGE_SECTION_HEADER Section;
		Reader.Read(Section);

		DWORD SectionStart = Section.VirtualAddress;
		DWORD SectionEnd = SectionStart + max(Section.Misc.VirtualSize, Section.SizeOfRawData);

		if (RVA >= SectionStart && RVA < SectionEnd)
		{
			Out = (RVA - SectionStart) + Section.PointerToRawData;
			break;
		}
	}

	Reader.SetPos(OldPos);

	return Out;
}

std::string ReadString(BinaryReader& Reader, DWORD StringAddress)
{
	ULONGLONG OldPos = Reader.GetPos();

	Reader.SetPos(StringAddress);
	
	std::string Out = ReadString(Reader);

	Reader.SetPos(OldPos);

	return Out;
}

std::string ReadString(BinaryReader& Reader)
{
	ULONGLONG OldPos = Reader.GetPos();

	std::string Out;

	char Char;
	while ((Char = Reader.ReadChar()) != '\0')
	{
		Out += Char;
	}

	Reader.SetPos(OldPos);

	return Out;
}

std::string MachineToString(WORD Machine)
{
#define MACHINETYPE_TO_STRING(MachineType) \
	if (Machine == MachineType) return #MachineType

#define MACHINETYPE_TO_STRING2(Value, Name) \
	if (Machine == Value) return #Name

	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_UNKNOWN);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_ALPHA);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_ALPHA64);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_AM33);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_AMD64);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_ARM);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_ARM64);
	MACHINETYPE_TO_STRING2(0xA641, IMAGE_FILE_MACHINE_ARM64EC);
	MACHINETYPE_TO_STRING2(0xA64E, IMAGE_FILE_MACHINE_ARM64X);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_ARMNT);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_AXP64);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_EBC);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_I386);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_IA64);
	MACHINETYPE_TO_STRING2(0x6232, IMAGE_FILE_MACHINE_LOONGARCH32);
	MACHINETYPE_TO_STRING2(0x6264, IMAGE_FILE_MACHINE_LOONGARCH64);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_M32R);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_MIPS16);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_MIPSFPU);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_MIPSFPU16);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_POWERPC);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_POWERPCFP);
	MACHINETYPE_TO_STRING2(0x160, IMAGE_FILE_MACHINE_R3000BE);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_R3000);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_R4000);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_R10000);
	MACHINETYPE_TO_STRING2(0x5032, IMAGE_FILE_MACHINE_RISCV32);
	MACHINETYPE_TO_STRING2(0x5064, IMAGE_FILE_MACHINE_RISCV64);
	MACHINETYPE_TO_STRING2(0x5128, IMAGE_FILE_MACHINE_RISCV128);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_SH3);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_SH3DSP);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_SH4);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_SH5);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_THUMB);
	MACHINETYPE_TO_STRING(IMAGE_FILE_MACHINE_WCEMIPSV2);

	return {};
}

std::string TimeDateStampToString(DWORD TimeDateStamp)
{
	char Out[] = "Mon Jan 00 00:00:00 0000";

	time_t Time = (time_t)TimeDateStamp;

	tm Tm;
	if (localtime_s(&Tm, &Time) != 0)
	{
		return Out;
	}

	std::strftime(Out, sizeof(Out), "%c", &Tm);

	return Out;
}

std::string FileCharacteristicsToString(WORD Characteristics)
{
	std::string Out;

#define FLAG_TO_STRING(Flag) \
	if (Characteristics & Flag) Out += Out.empty() ? #Flag : " | "#Flag

	FLAG_TO_STRING(IMAGE_FILE_RELOCS_STRIPPED);
	FLAG_TO_STRING(IMAGE_FILE_EXECUTABLE_IMAGE);
	FLAG_TO_STRING(IMAGE_FILE_LINE_NUMS_STRIPPED);
	FLAG_TO_STRING(IMAGE_FILE_LOCAL_SYMS_STRIPPED);
	FLAG_TO_STRING(IMAGE_FILE_AGGRESIVE_WS_TRIM);
	FLAG_TO_STRING(IMAGE_FILE_LARGE_ADDRESS_AWARE);
	FLAG_TO_STRING(IMAGE_FILE_BYTES_REVERSED_LO);
	FLAG_TO_STRING(IMAGE_FILE_32BIT_MACHINE);
	FLAG_TO_STRING(IMAGE_FILE_DEBUG_STRIPPED);
	FLAG_TO_STRING(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
	FLAG_TO_STRING(IMAGE_FILE_NET_RUN_FROM_SWAP);
	FLAG_TO_STRING(IMAGE_FILE_SYSTEM);
	FLAG_TO_STRING(IMAGE_FILE_DLL);
	FLAG_TO_STRING(IMAGE_FILE_UP_SYSTEM_ONLY);
	FLAG_TO_STRING(IMAGE_FILE_BYTES_REVERSED_HI);

	return Out;
}

std::string MagicToString(WORD Magic)
{
#define IMAGESTATE_TO_STRING(ImageState) \
	if (Magic == ImageState) return #ImageState

	// IMAGESTATE_TO_STRING(IMAGE_NT_OPTIONAL_HDR_MAGIC);
	IMAGESTATE_TO_STRING(IMAGE_NT_OPTIONAL_HDR32_MAGIC);
	IMAGESTATE_TO_STRING(IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	IMAGESTATE_TO_STRING(IMAGE_ROM_OPTIONAL_HDR_MAGIC);

	return {};
}

std::string SubsystemToString(WORD Subsystem)
{
#define IMAGE_SUBSYSTEM_TO_STRING(ImageSubsystem) \
	if (Subsystem == ImageSubsystem) return #ImageSubsystem + 16 /* skip 'IMAGE_SUBSYSTEM_' */

	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_UNKNOWN);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_NATIVE);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_WINDOWS_GUI);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_WINDOWS_CUI);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_OS2_CUI);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_POSIX_CUI);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_NATIVE_WINDOWS);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_EFI_APPLICATION);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_EFI_ROM);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_XBOX);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION);
	IMAGE_SUBSYSTEM_TO_STRING(IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG);

	return {};
}

std::string SectionCharacteristicsToString(DWORD Characteristics)
{
	if (Characteristics == 0x0)
	{
		return "0";
	}

	std::string Out;

#define FLAG_TO_STRING(Flag) \
	if (Characteristics & Flag) Out += Out.empty() ? #Flag : " | "#Flag

	FLAG_TO_STRING(IMAGE_SCN_TYPE_NO_PAD);
	FLAG_TO_STRING(IMAGE_SCN_CNT_CODE);
	FLAG_TO_STRING(IMAGE_SCN_CNT_INITIALIZED_DATA);
	FLAG_TO_STRING(IMAGE_SCN_CNT_UNINITIALIZED_DATA);
	FLAG_TO_STRING(IMAGE_SCN_LNK_OTHER);
	FLAG_TO_STRING(IMAGE_SCN_LNK_INFO);
	FLAG_TO_STRING(IMAGE_SCN_LNK_REMOVE);
	FLAG_TO_STRING(IMAGE_SCN_LNK_COMDAT);
	FLAG_TO_STRING(IMAGE_SCN_NO_DEFER_SPEC_EXC);
	FLAG_TO_STRING(IMAGE_SCN_GPREL);
	FLAG_TO_STRING(IMAGE_SCN_MEM_PURGEABLE);
	FLAG_TO_STRING(IMAGE_SCN_MEM_LOCKED);
	FLAG_TO_STRING(IMAGE_SCN_MEM_PRELOAD);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_1BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_2BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_4BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_8BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_16BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_32BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_64BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_128BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_256BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_512BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_1024BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_2048BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_4096BYTES);
	FLAG_TO_STRING(IMAGE_SCN_ALIGN_8192BYTES);
	FLAG_TO_STRING(IMAGE_SCN_LNK_NRELOC_OVFL);
	FLAG_TO_STRING(IMAGE_SCN_MEM_DISCARDABLE);
	FLAG_TO_STRING(IMAGE_SCN_MEM_NOT_CACHED);
	FLAG_TO_STRING(IMAGE_SCN_MEM_NOT_PAGED);
	FLAG_TO_STRING(IMAGE_SCN_MEM_SHARED);
	FLAG_TO_STRING(IMAGE_SCN_MEM_EXECUTE);
	FLAG_TO_STRING(IMAGE_SCN_MEM_READ);
	FLAG_TO_STRING(IMAGE_SCN_MEM_WRITE);

	return Out;
}
