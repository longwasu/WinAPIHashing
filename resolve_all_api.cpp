#include <windows.h>
#include <stdio.h>


UINT GetHash(char* function_name) {
	int hash_value = 0x3228F3D1;
	for (int i = 0; i < strlen(function_name); i++) {
		hash_value = (function_name[i] ^ hash_value) * 0x01000193;
	}
	return hash_value;
}


PIMAGE_SECTION_HEADER FindSection(PIMAGE_SECTION_HEADER section_header, int NumberOfSection, int data_directory_RVA) {
	int i;
	for (i = 0; i < NumberOfSection; i++) {
		int section_start = section_header->VirtualAddress;
		int section_end = section_header->VirtualAddress + section_header->Misc.VirtualSize;
		if (data_directory_RVA >= section_start && data_directory_RVA < section_end)
			return section_header;
		section_header++;
	}
	return 0;
}


int ConvertRVAtoRaw(int RVA, PIMAGE_SECTION_HEADER section) {
	return RVA - section->VirtualAddress + section->PointerToRawData;
}


PIMAGE_EXPORT_DIRECTORY FindExportDirectory(BYTE* base, PIMAGE_SECTION_HEADER& section) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
	if (dosHeader->e_magic != 0x5A4D || ntHeader->Signature != 0x4550)
		return 0;

	DWORD exportDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportDirectorySize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (exportDirectoryRVA == 0 || exportDirectorySize == 0)
		return 0;

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(base + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	section = FindSection(sectionHeader, ntHeader->FileHeader.NumberOfSections, exportDirectoryRVA);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(base + ConvertRVAtoRaw(exportDirectoryRVA, section));

	if (exportDirectory->NumberOfNames < 5)
		return 0;
	return exportDirectory;
}


void GetFunctionByHash(BYTE* base, FILE* outputFile) {
	PIMAGE_SECTION_HEADER section;
	PIMAGE_EXPORT_DIRECTORY exportDirectory = FindExportDirectory(base, section);
	if (!exportDirectory)
		return;

	char* dll_name = (char*)base + ConvertRVAtoRaw(exportDirectory->Name, section);
	fprintf(outputFile, "---------%s---------\n", dll_name);

	DWORD* nameTable = (DWORD*)(base + ConvertRVAtoRaw(exportDirectory->AddressOfNames, section));
	DWORD* addressTable = (DWORD*)(base + ConvertRVAtoRaw(exportDirectory->AddressOfFunctions, section));
	WORD* ordinalTable = (WORD*)(base + ConvertRVAtoRaw(exportDirectory->AddressOfNameOrdinals, section));

	for (int i = 0; i < exportDirectory->NumberOfNames; i++) {
		char* function_name = (char*)base + ConvertRVAtoRaw(nameTable[i], section);
		WORD ordinal = ordinalTable[i];
		DWORD* function_address = (DWORD*)(base + ConvertRVAtoRaw(addressTable[ordinal], section));
		fprintf(outputFile, "0x%04X\t\t%s_%s\n", GetHash(function_name), dll_name, function_name);
	}
	fprintf(outputFile, "\n");
}


int main() {
	FILE* outputFile = nullptr;
	fopen_s(&outputFile, "all_hash.txt", "w");

	char path[MAX_PATH] = "C:\\Windows\\SysWow64\\*.dll";
	WIN32_FIND_DATAA file_info;
	HANDLE hFile = FindFirstFileA(path, &file_info);
	int i = 0;

	while (FindNextFileA(hFile, &file_info)) {
		char file_path[MAX_PATH] = "C:\\Windows\\SysWow64\\";
		lstrcatA(file_path, file_info.cFileName);

		HANDLE hFileOpen = CreateFileA(file_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFileOpen != INVALID_HANDLE_VALUE) {
			DWORD file_size = GetFileSize(hFileOpen, nullptr);
			HANDLE hFileMap = CreateFileMappingA(hFileOpen, nullptr, PAGE_READONLY, 0, 0, nullptr);
			BYTE* base = (BYTE*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

			if (base) {
				printf("Processing %s\n", file_info.cFileName);
				GetFunctionByHash(base, outputFile);
				UnmapViewOfFile(base);
				i++;
			}
			CloseHandle(hFileMap);
			CloseHandle(hFileOpen);
		}
	}

	printf("Processing %i DLL file\n", i);
	fclose(outputFile);
	return 0;
}