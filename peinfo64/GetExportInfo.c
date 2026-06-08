/*
模块3：PE导出表信息
*/
#include <windows.h>
#include <strsafe.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];
extern HANDLE hFileDump;
extern HWND hWinMain;

void _getExportInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR buffer[512];
	TCHAR sectionName[32];
	TCHAR dllName[256];
	TCHAR functionName[256];
	DWORD rva = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY * exportDirectory;
	IMAGE_SECTION_HEADER * section;
	DWORD * addressOfFunctions;
	DWORD * addressOfNames;
	WORD * addressOfNameOrdinals;

	if (!rva)
	{
		MessageBox(hWinMain, TEXT("\r\n这个文件中没有导出函数!\r\n"), NULL, MB_OK);
		WriteTextToDump(hFileDump, TEXT("\r\n这个文件中没有导出函数!\r\n"));
		return;
	}

	exportDirectory = (IMAGE_EXPORT_DIRECTORY *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva));
	section = GetRVASectionHeader((IMAGE_DOS_HEADER *)lpFile, rva);
	CopySectionName(section, sectionName, ARRAYSIZE(sectionName));
	CopyAnsiToWide((const char*)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, exportDirectory->Name)), dllName, ARRAYSIZE(dllName));

	StringCchPrintf(buffer, ARRAYSIZE(buffer),
		TEXT("\r\n\r\n\r\n\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("导出表所处的节：%s\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("原始文件名          %s\r\n")
		TEXT("DLL 名称            %s\r\n")
		TEXT("nBase               %08X\r\n")
		TEXT("NumberOfFunctions   %08X\r\n")
		TEXT("NumberOfNames       %08X\r\n")
		TEXT("AddressOfFunctions  %08X\r\n")
		TEXT("AddressOfNames      %08X\r\n")
		TEXT("AddressOfNameOrd    %08X\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("导出序号  虚拟地址  导出函数名称\r\n")
		TEXT("---------------------------------------------------------\r\n"),
		sectionName,
		szFileName,
		dllName,
		exportDirectory->Base,
		exportDirectory->NumberOfFunctions,
		exportDirectory->NumberOfNames,
		exportDirectory->AddressOfFunctions,
		exportDirectory->AddressOfNames,
		exportDirectory->AddressOfNameOrdinals);
	WriteTextToDump(hFileDump, buffer);

	addressOfFunctions = (DWORD *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, exportDirectory->AddressOfFunctions));
	addressOfNames = (DWORD *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, exportDirectory->AddressOfNames));
	addressOfNameOrdinals = (WORD *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, exportDirectory->AddressOfNameOrdinals));

	for (DWORD functionIndex = 0; functionIndex < exportDirectory->NumberOfFunctions; ++functionIndex)
	{
		StringCchCopy(functionName, ARRAYSIZE(functionName), TEXT("(按照序号导出)"));

		for (DWORD nameIndex = 0; nameIndex < exportDirectory->NumberOfNames; ++nameIndex)
		{
			if (addressOfNameOrdinals[nameIndex] == functionIndex)
			{
				CopyAnsiToWide((const char*)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, addressOfNames[nameIndex])), functionName, ARRAYSIZE(functionName));
				break;
			}
		}
		StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("\r\n%08X  %08X  %s\r\n"), exportDirectory->Base + functionIndex, addressOfFunctions[functionIndex], functionName);
		WriteTextToDump(hFileDump, buffer);
	}
}
