/*
将 RVA 转换成实际的数据位置和查找 RVA 所在的节区
*/
#include <windows.h>
#include "info.h"

BOOL IsPe64(const IMAGE_NT_HEADERS* ntHeader)
{
	return ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

PBYTE OffsetToPtr(PBYTE fileBase, DWORD fileOffset)
{
	if (!fileBase)
		return NULL;
	return fileBase + fileOffset;
}

BOOL WriteTextToDump(HANDLE hFile, const TCHAR* text)
{
	DWORD bytesWritten = 0;

	if (hFile == NULL || hFile == INVALID_HANDLE_VALUE || text == NULL)
		return FALSE;

	return WriteFile(hFile, text, lstrlen(text) * sizeof(TCHAR), &bytesWritten, NULL);
}

void CopyAnsiToWide(const char* source, TCHAR* buffer, size_t bufferCount)
{
	if (!buffer || bufferCount == 0)
		return;

	buffer[0] = TEXT('\0');
	if (!source)
		return;

	int result = MultiByteToWideChar(CP_ACP, 0, source, -1, buffer, (int)bufferCount);
	if (result == 0)
	{
		buffer[0] = TEXT('\0');
		return;
	}

	if ((size_t)result >= bufferCount)
		buffer[bufferCount - 1] = TEXT('\0');
}

void CopySectionName(const IMAGE_SECTION_HEADER* section, TCHAR* buffer, size_t bufferCount)
{
	char ansiName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };

	if (!buffer || bufferCount == 0)
		return;

	buffer[0] = TEXT('\0');
	if (!section)
		return;

	CopyMemory(ansiName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
	CopyAnsiToWide(ansiName, buffer, bufferCount);
}

DWORD RVAToOffset(IMAGE_DOS_HEADER* lpFileHead, DWORD dwRVA)
{
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_SECTION_HEADER* section;

	if (!lpFileHead)
		return 0;

	if (lpFileHead->e_lfanew == 0 || lpFileHead->e_lfanew < sizeof(IMAGE_DOS_HEADER))
	{
		SetLastError(ERROR_INVALID_DATA);
		return 0;
	}
	ntHeader = (IMAGE_NT_HEADERS*)((PBYTE)lpFileHead + lpFileHead->e_lfanew);
	section = IMAGE_FIRST_SECTION(ntHeader);

	if (dwRVA < ntHeader->OptionalHeader.SizeOfHeaders)
		return dwRVA;

	for (WORD index = 0; index < ntHeader->FileHeader.NumberOfSections; ++index, ++section)
	{
		DWORD sectionSize = section->Misc.VirtualSize;
		if (sectionSize < section->SizeOfRawData)
			sectionSize = section->SizeOfRawData;

		if (dwRVA >= section->VirtualAddress && dwRVA < section->VirtualAddress + sectionSize)
			return section->PointerToRawData + (dwRVA - section->VirtualAddress);
	}

	SetLastError(ERROR_NOT_FOUND);
	return 0;
}

IMAGE_SECTION_HEADER* GetRVASectionHeader(IMAGE_DOS_HEADER* lpFileHead, DWORD dwRVA)
{
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_SECTION_HEADER* section;

	if (!lpFileHead)
		return NULL;

	if (lpFileHead->e_lfanew == 0 || lpFileHead->e_lfanew < sizeof(IMAGE_DOS_HEADER))
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}
	ntHeader = (IMAGE_NT_HEADERS*)((PBYTE)lpFileHead + lpFileHead->e_lfanew);
	section = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD index = 0; index < ntHeader->FileHeader.NumberOfSections; ++index, ++section)
	{
		DWORD sectionSize = section->Misc.VirtualSize;
		if (sectionSize < section->SizeOfRawData)
			sectionSize = section->SizeOfRawData;

		if (dwRVA >= section->VirtualAddress && dwRVA < section->VirtualAddress + sectionSize)
			return section;
	}

	SetLastError(ERROR_NOT_FOUND);
	return NULL;
}
