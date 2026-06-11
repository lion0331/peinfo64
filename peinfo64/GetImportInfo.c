/*
模块2：PE导入表信息
*/
#include <windows.h>
#include <strsafe.h>
#include "info.h"

extern HANDLE hFileDump;
extern HWND hWinMain;

static void DumpImportThunk32(PBYTE lpFile, DWORD thunkRva)
{
	TCHAR lineBuffer[256];
	IMAGE_THUNK_DATA32 * thunk = (IMAGE_THUNK_DATA32 *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, thunkRva));

	while (thunk && thunk->u1.AddressOfData)
	{
		if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
		{
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%8u  (无函数名,按序号导入)\r\n"), (DWORD)IMAGE_ORDINAL32(thunk->u1.Ordinal));
		}
		else
		{
			IMAGE_IMPORT_BY_NAME * importByName = (IMAGE_IMPORT_BY_NAME *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, thunk->u1.AddressOfData));
			TCHAR functionName[256];
			CopyAnsiToWide((const char*)importByName->Name, functionName, ARRAYSIZE(functionName));
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%-8u  %s\r\n"), importByName->Hint, functionName);
		}
		WriteTextToDump(hFileDump, lineBuffer);
		++thunk;
	}
}

static void DumpImportThunk64(PBYTE lpFile, DWORD thunkRva)
{
	TCHAR lineBuffer[256];
	IMAGE_THUNK_DATA64 * thunk = (IMAGE_THUNK_DATA64 *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, thunkRva));

	while (thunk && thunk->u1.AddressOfData)
	{
		if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
		{
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%8u  (无函数名,按序号导入)\r\n"), (DWORD)IMAGE_ORDINAL64(thunk->u1.Ordinal));
		}
		else
		{
			DWORD nameRva;
			IMAGE_IMPORT_BY_NAME * importByName;

			if (thunk->u1.AddressOfData > MAXDWORD)
				break;

			nameRva = (DWORD)thunk->u1.AddressOfData;
			importByName = (IMAGE_IMPORT_BY_NAME *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, nameRva));
			TCHAR functionName[256];
			CopyAnsiToWide((const char*)importByName->Name, functionName, ARRAYSIZE(functionName));
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%-8u  %s\r\n"), importByName->Hint, functionName);
		}
		WriteTextToDump(hFileDump, lineBuffer);
		++thunk;
	}
}

void _getImportInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR headerBuffer[512];
	TCHAR dllName[256];
	TCHAR sectionName[32];
	DWORD rva;
	IMAGE_IMPORT_DESCRIPTOR * importDescriptor;
	IMAGE_SECTION_HEADER * section;

	rva = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!rva)
	{
		MessageBox(hWinMain, TEXT("\r\n\r\n未发现该文件有导入函数\r\n"), NULL, MB_OK);
		return;
	}

	importDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva));
	section = GetRVASectionHeader((IMAGE_DOS_HEADER *)lpFile, rva);
	CopySectionName(section, sectionName, ARRAYSIZE(sectionName));

	StringCchPrintf(headerBuffer, ARRAYSIZE(headerBuffer),
		TEXT("\r\n\r\n")
		TEXT("---------------------------------------------------------------------------------------------\r\n")
		TEXT("导入表所处的节：%s\r\n")
		TEXT("---------------------------------------------------------------------------------------------\r\n"),
		sectionName);
	WriteTextToDump(hFileDump, headerBuffer);

	while (importDescriptor->OriginalFirstThunk || importDescriptor->TimeDateStamp || importDescriptor->ForwarderChain || importDescriptor->Name || importDescriptor->FirstThunk)
	{
		CopyAnsiToWide((const char*)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, importDescriptor->Name)), dllName, ARRAYSIZE(dllName));
		StringCchPrintf(headerBuffer, ARRAYSIZE(headerBuffer),
			TEXT("\r\n--------------------------------------------------------\r\n")
			TEXT("导入库： %s\r\n")
			TEXT("----------------------------------------------------------\r\n")
			TEXT("OriginalFirstThunk %08X\r\n")
			TEXT("TimeDateStamp      %08X\r\n")
			TEXT("ForwarderChain     %08X\r\n")
			TEXT("FirstThunk         %08X\r\n")
			TEXT("----------------------------------------------------------\r\n")
			TEXT("导入序号  导入函数名称\r\n")
			TEXT("----------------------------------------------------------\r\n"),
			dllName,
			importDescriptor->OriginalFirstThunk,
			importDescriptor->TimeDateStamp,
			importDescriptor->ForwarderChain,
			importDescriptor->FirstThunk);
		WriteTextToDump(hFileDump, headerBuffer);

		if (IsPe64(_lpPeHead))
			DumpImportThunk64(lpFile, importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk);
		else
			DumpImportThunk32(lpFile, importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk);

		++importDescriptor;
	}
}
