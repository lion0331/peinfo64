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
	TCHAR functionName[256];
	IMAGE_IMPORT_BY_NAME* importByName;
	DWORD thunkOffset32;
	IMAGE_THUNK_DATA32* thunk;

	thunkOffset32 = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, thunkRva);
	if (!thunkOffset32)
		return;
	thunk = (IMAGE_THUNK_DATA32*)OffsetToPtr(lpFile, thunkOffset32);
	DWORD safetyLimit = IMPORT_THUNK_LIMIT;

	if (!thunk)
		return;

	while (thunk->u1.AddressOfData && safetyLimit > 0)
	{
		--safetyLimit;
		if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
		{
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%8u  (无函数名,按序号导入)\r\n"), (DWORD)IMAGE_ORDINAL32(thunk->u1.Ordinal));
		}
		else
		{
			DWORD nameOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, thunk->u1.AddressOfData);
			if (!nameOffset)
				break;
			importByName = (IMAGE_IMPORT_BY_NAME*)OffsetToPtr(lpFile, nameOffset);
			if (!importByName)
				break;
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
	TCHAR functionName[256];
	IMAGE_IMPORT_BY_NAME* importByName;
	DWORD thunkOffset64;
	IMAGE_THUNK_DATA64* thunk;

	thunkOffset64 = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, thunkRva);
	if (!thunkOffset64)
		return;
	thunk = (IMAGE_THUNK_DATA64*)OffsetToPtr(lpFile, thunkOffset64);
	DWORD safetyLimit = IMPORT_THUNK_LIMIT;

	if (!thunk)
		return;

	while (thunk->u1.AddressOfData && safetyLimit > 0)
	{
		--safetyLimit;
		if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
		{
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%8u  (无函数名,按序号导入)\r\n"), (DWORD)IMAGE_ORDINAL64(thunk->u1.Ordinal));
		}
		else
		{
			DWORD nameRva;

			if (thunk->u1.AddressOfData > MAXDWORD)
				break;

			nameRva = (DWORD)thunk->u1.AddressOfData;
			{
				DWORD nameOffset64 = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, nameRva);
				if (!nameOffset64)
					break;
				importByName = (IMAGE_IMPORT_BY_NAME*)OffsetToPtr(lpFile, nameOffset64);
			}
			if (!importByName)
				break;
			CopyAnsiToWide((const char*)importByName->Name, functionName, ARRAYSIZE(functionName));
			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%-8u  %s\r\n"), importByName->Hint, functionName);
		}
		WriteTextToDump(hFileDump, lineBuffer);
		++thunk;
	}
}

void _getImportInfo(PBYTE lpFile, IMAGE_NT_HEADERS* _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR headerBuffer[512];
	TCHAR dllName[256];
	TCHAR sectionName[32];
	DWORD rva;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
	IMAGE_SECTION_HEADER* section;

	rva = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!rva)
	{
		MessageBox(hWinMain, TEXT("\r\n\r\n未发现该文件有导入函数\r\n"), NULL, MB_OK);
		return;
	}

	{
		DWORD importOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, rva);
		if (!importOffset)
			return;
		importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)OffsetToPtr(lpFile, importOffset);
	}
	if (!importDescriptor)
		return;

	section = GetRVASectionHeader((IMAGE_DOS_HEADER*)lpFile, rva);
	CopySectionName(section, sectionName, ARRAYSIZE(sectionName));

	StringCchPrintf(headerBuffer, ARRAYSIZE(headerBuffer),
		TEXT("\r\n\r\n")
		TEXT("---------------------------------------------------------------------------------------------\r\n")
		TEXT("导入表所处的节：%s\r\n")
		TEXT("---------------------------------------------------------------------------------------------\r\n"),
		sectionName);
	WriteTextToDump(hFileDump, headerBuffer);

	{
		DWORD importSafetyLimit = IMPORT_DESC_LIMIT;
		while ((importDescriptor->OriginalFirstThunk || importDescriptor->TimeDateStamp || importDescriptor->ForwarderChain || importDescriptor->Name || importDescriptor->FirstThunk) && importSafetyLimit > 0)
		{
			--importSafetyLimit;
			DWORD dllNameOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, importDescriptor->Name);
			PBYTE dllNamePtr = dllNameOffset ? OffsetToPtr(lpFile, dllNameOffset) : NULL;
			if (dllNamePtr)
				CopyAnsiToWide((const char*)dllNamePtr, dllName, ARRAYSIZE(dllName));
			else
				StringCchCopy(dllName, ARRAYSIZE(dllName), TEXT("(无法读取)"));

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
}
