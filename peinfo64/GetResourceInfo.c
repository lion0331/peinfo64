/*
模块5：PE资源信息
*/
#include <windows.h>
#include <strsafe.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];
extern HANDLE hFileDump;
extern HWND hWinMain;

static void CopyResourceName(PBYTE resourceBase, DWORD nameOffset, TCHAR* buffer, size_t bufferCount)
{
	IMAGE_RESOURCE_DIR_STRING_U* resourceName;
	DWORD copyCount;

	if (!buffer || bufferCount == 0)
		return;

	buffer[0] = TEXT('\0');

	if (!resourceBase || nameOffset == 0)
		return;

	resourceName = (IMAGE_RESOURCE_DIR_STRING_U*)(resourceBase + nameOffset);
	copyCount = resourceName->Length;

	if (copyCount >= bufferCount)
		copyCount = (DWORD)bufferCount - 1;

	CopyMemory(buffer, resourceName->NameString, copyCount * sizeof(WCHAR));
	buffer[copyCount] = TEXT('\0');
}

static void ProcessRes(PBYTE lpFile, PBYTE lpRes, IMAGE_RESOURCE_DIRECTORY* lpResDir, DWORD dwLevel)
{
	if (dwLevel > 8)
		return;

	TCHAR buffer[256];
	TCHAR resName[256];
	const TCHAR szType[][16] = {
		TEXT("光标"), TEXT("位图"), TEXT("图标"), TEXT("菜单"),
		TEXT("对话框"), TEXT("字符串"), TEXT("字体目录"), TEXT("字体"),
		TEXT("加速键"), TEXT("未格式化资源"), TEXT("消息表"), TEXT("光标组"),
		TEXT("未知类型"), TEXT("图标组"), TEXT("未知类型"), TEXT("版本信息")
	};
	DWORD number = (DWORD)lpResDir->NumberOfIdEntries + (DWORD)lpResDir->NumberOfNamedEntries;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* entry;

	if (number > 5000)
		number = 5000;
	entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((PBYTE)lpResDir + sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (DWORD index = 0; index < number; ++index, ++entry)
	{
		if (entry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
		{
			IMAGE_RESOURCE_DIRECTORY* childDir = (IMAGE_RESOURCE_DIRECTORY*)(lpRes + (entry->OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY));

			if (dwLevel == 1)
			{
				if (entry->NameIsString)
					CopyResourceName(lpRes, entry->NameOffset, resName, ARRAYSIZE(resName));
				else if (entry->Id >= 1 && entry->Id <= 16)
					StringCchCopy(resName, ARRAYSIZE(resName), szType[entry->Id - 1]);
				else
					StringCchPrintf(resName, ARRAYSIZE(resName), TEXT("%u (自定义编号)"), entry->Id);

				StringCchPrintf(buffer, ARRAYSIZE(buffer),
					TEXT("\r\n---------------------------------------------------------\r\n")
					TEXT("资源类型：%s\r\n")
					TEXT("---------------------------------------------------------\r\n"),
					resName);
				WriteTextToDump(hFileDump, buffer);
			}
			else if (dwLevel == 2)
			{
				if (entry->NameIsString)
				{
					CopyResourceName(lpRes, entry->NameOffset, resName, ARRAYSIZE(resName));
					StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("  Name: %s\r\n"), resName);
				}
				else
				{
					StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("  ID: %u\r\n"), entry->Id);
				}
				WriteTextToDump(hFileDump, buffer);
			}

			ProcessRes(lpFile, lpRes, childDir, dwLevel + 1);
		}
		else
		{
			IMAGE_RESOURCE_DATA_ENTRY* dataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)(lpRes + entry->OffsetToData);
			DWORD address = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, dataEntry->OffsetToData);
			if (address)
				StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("     文件偏移：%08X (代码页=%04X, 长度%u字节)\r\n"), address, dataEntry->CodePage, dataEntry->Size);
			else
				StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("     文件偏移：无法解析 (代码页=%04X, 长度%u字节)\r\n"), dataEntry->CodePage, dataEntry->Size);
			WriteTextToDump(hFileDump, buffer);
		}
	}
}

void _getResourceInfo(PBYTE lpFile, IMAGE_NT_HEADERS* _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR buffer[256];
	TCHAR sectionName[32];
	DWORD rva = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	IMAGE_RESOURCE_DIRECTORY* resourceDir;
	IMAGE_SECTION_HEADER* section;

	if (!rva)
	{
		MessageBox(hWinMain, TEXT("\r\n这个文件中没有包含资源!"), NULL, MB_OK);
		WriteTextToDump(hFileDump, TEXT("\r\n这个文件中没有包含资源!"));
		return;
	}

	{
		DWORD resRvaOffset = RVAToOffset((IMAGE_DOS_HEADER*)lpFile, rva);
		if (!resRvaOffset)
			return;
		resourceDir = (IMAGE_RESOURCE_DIRECTORY*)OffsetToPtr(lpFile, resRvaOffset);
	}
	if (!resourceDir)
		return;

	section = GetRVASectionHeader((IMAGE_DOS_HEADER*)lpFile, rva);
	CopySectionName(section, sectionName, ARRAYSIZE(sectionName));

	StringCchPrintf(buffer, ARRAYSIZE(buffer),
		TEXT("\r\n\r\n文件名：%s\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("资源所处的节：%s\r\n"),
		szFileName,
		sectionName);
	WriteTextToDump(hFileDump, buffer);

	ProcessRes(lpFile, (PBYTE)resourceDir, resourceDir, 1);
}
