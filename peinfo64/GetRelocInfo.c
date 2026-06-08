/*
模块4：PE重定位表信息
*/
#include <windows.h>
#include <strsafe.h>
#include "info.h"

extern HANDLE hFileDump;
extern HWND hWinMain;

void _getRelocInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR buffer[256];
	TCHAR lineBuffer[64];
	TCHAR sectionName[32];
	DWORD rva = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD size = IsPe64(_lpPeHead)
		? ((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
		: ((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	IMAGE_BASE_RELOCATION * reloc;
	IMAGE_SECTION_HEADER * section;
	PBYTE relocEnd;

	if (!rva)
	{
		MessageBox(hWinMain, TEXT("\r\n未发现该文件有重定位信息!"), NULL, MB_OK);
		WriteTextToDump(hFileDump, TEXT("\r\n未发现该文件有重定位信息!"));
		return;
	}

	reloc = (IMAGE_BASE_RELOCATION *)OffsetToPtr(lpFile, RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva));
	relocEnd = (PBYTE)reloc + size;
	section = GetRVASectionHeader((IMAGE_DOS_HEADER *)lpFile, rva);
	CopySectionName(section, sectionName, ARRAYSIZE(sectionName));

	StringCchPrintf(buffer, ARRAYSIZE(buffer), TEXT("\r\n重定位表所处的节：%s\r\n"), sectionName);
	WriteTextToDump(hFileDump, buffer);

	while ((PBYTE)reloc < relocEnd && reloc->VirtualAddress && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
	{
		WORD * entries = (WORD *)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
		DWORD entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		StringCchPrintf(buffer, ARRAYSIZE(buffer),
			TEXT("\r\n---------------------------------------------------------\r\n")
			TEXT("重定位基地址：     %08X\r\n")
			TEXT("重定位项数量：     %u\r\n")
			TEXT("\r\n---------------------------------------------------------\r\n")
			TEXT("需要重定位的地址列表(ffffffff表示对齐用,不需要重定位)\r\n")
			TEXT("---------------------------------------------------------\r\n"),
			reloc->VirtualAddress,
			entryCount);
		WriteTextToDump(hFileDump, buffer);

		for (DWORD index = 0; index < entryCount; ++index)
		{
			WORD entry = entries[index];
			WORD type = (entry >> 12) & 0xF;
			DWORD offset = entry & 0x0FFF;
			DWORD address = 0xFFFFFFFF;

			if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
				address = reloc->VirtualAddress + offset;

			StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%08X  "), address);
			WriteTextToDump(hFileDump, lineBuffer);
			if ((index + 1) % 4 == 0)
				WriteTextToDump(hFileDump, TEXT("\r\n"));
		}
		WriteTextToDump(hFileDump, TEXT("\r\n"));
		reloc = (IMAGE_BASE_RELOCATION *)((PBYTE)reloc + reloc->SizeOfBlock);
	}
}
