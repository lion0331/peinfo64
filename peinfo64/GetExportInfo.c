/*
模块3：PE导出表信息
*/
#include <windows.h>
#include <strsafe.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];
extern HANDLE hFileDump;
extern HWND hWinMain;

void _getExportInfo(PBYTE lpFile, IMAGE_NT_HEADERS* _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR buffer[512];
	TCHAR sectionName[32];
	TCHAR dllName[256];
	TCHAR functionName[256];
	IMAGE_EXPORT_DIRECTORY* exportDirectory = NULL;
	IMAGE_SECTION_HEADER* section = NULL;
	DWORD* addressOfFunctions = NULL;
	DWORD* addressOfNames = NULL;
	WORD* addressOfNameOrdinals = NULL;
	DWORD* ordinalToNameIndex = NULL;
	DWORD functionCount;
	DWORD nameCount;
	DWORD rva;
	DWORD exportOffset;
	DWORD nameRvaOffset;
	DWORD funcOffset;
	DWORD namesOffset;
	DWORD ordinalsOffset;

	rva = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (!rva)
	{
		MessageBox(hWinMain, TEXT("\r\n这个文件中没有导出函数!\r\n"), NULL, MB_OK);
		WriteTextToDump(hFileDump, TEXT("\r\n这个文件中没有导出函数!\r\n"));
		return;
	}

	exportOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, rva);
	if (!exportOffset)
		return;
	exportDirectory = (IMAGE_EXPORT_DIRECTORY*)OffsetToPtr(lpFile, exportOffset);
	if (!exportDirectory)
		return;

	section = GetRVASectionHeader((IMAGE_DOS_HEADER*)lpFile, rva);
	CopySectionName(section, sectionName, ARRAYSIZE(sectionName));

	{
		DWORD dllNameOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, exportDirectory->Name);
		PBYTE dllNamePtr = dllNameOffset ? OffsetToPtr(lpFile, dllNameOffset) : NULL;
		if (dllNamePtr)
			CopyAnsiToWide((const char*)dllNamePtr, dllName, ARRAYSIZE(dllName));
		else
			StringCchCopy(dllName, ARRAYSIZE(dllName), TEXT("(无法读取)"));
	}

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

	funcOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, exportDirectory->AddressOfFunctions);
	namesOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, exportDirectory->AddressOfNames);
	ordinalsOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, exportDirectory->AddressOfNameOrdinals);

	addressOfFunctions = funcOffset ? (DWORD*)OffsetToPtr(lpFile, funcOffset) : NULL;
	addressOfNames = namesOffset ? (DWORD*)OffsetToPtr(lpFile, namesOffset) : NULL;
	addressOfNameOrdinals = ordinalsOffset ? (WORD*)OffsetToPtr(lpFile, ordinalsOffset) : NULL;

	if (!addressOfFunctions || !addressOfNameOrdinals)
		return;

	functionCount = exportDirectory->NumberOfFunctions;
	if (functionCount > EXPORT_FUNC_LIMIT)
		functionCount = EXPORT_FUNC_LIMIT;

	nameCount = exportDirectory->NumberOfNames;
	if (nameCount > EXPORT_FUNC_LIMIT)
		nameCount = EXPORT_FUNC_LIMIT;

	/*
	 * 构建序号→名称索引的 O(1) 反向查找表
	 * 原实现为 O(n²) 双重循环，对于导出大量函数的 DLL (如 kernel32.dll)
	 * 会导致严重性能问题。此处预先建立映射，将复杂度降至 O(n)。
	 */
	if (addressOfNames && addressOfNameOrdinals && nameCount > 0 && functionCount > 0)
	{
		/* 使用普通 HeapAlloc 即可，紧随其后会显式初始化为 (DWORD)-1 */
		ordinalToNameIndex = (DWORD*)HeapAlloc(GetProcessHeap(), 0, functionCount * sizeof(DWORD));
		if (ordinalToNameIndex)
		{
			/* 初始化为无效值 (DWORD)-1 */
			for (DWORD i = 0; i < functionCount; ++i)
				ordinalToNameIndex[i] = (DWORD)-1;

			for (DWORD nameIndex = 0; nameIndex < nameCount; ++nameIndex)
			{
				DWORD ord = addressOfNameOrdinals[nameIndex];
				if (ord < functionCount)
					ordinalToNameIndex[ord] = nameIndex;
			}
		}
	}

	for (DWORD functionIndex = 0; functionIndex < functionCount; ++functionIndex)
	{
		StringCchCopy(functionName, ARRAYSIZE(functionName), TEXT("(按照序号导出)"));

		if (ordinalToNameIndex && ordinalToNameIndex[functionIndex] != (DWORD)-1)
		{
			DWORD nameIndex = ordinalToNameIndex[functionIndex];
			nameRvaOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, addressOfNames[nameIndex]);
			if (nameRvaOffset)
			{
				PBYTE funcNamePtr = OffsetToPtr(lpFile, nameRvaOffset);
				if (funcNamePtr)
					CopyAnsiToWide((const char*)funcNamePtr, functionName, ARRAYSIZE(functionName));
			}
		}

		StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("\r\n%08X  %08X  %s\r\n"),
			exportDirectory->Base + functionIndex,
			addressOfFunctions[functionIndex],
			functionName);
		WriteTextToDump(hFileDump, buffer);
	}

	if (ordinalToNameIndex)
		HeapFree(GetProcessHeap(), 0, ordinalToNameIndex);
}
