/*
将 RVA 转换成实际的数据位置和查找 RVA 所在的节区
*/

#include <windows.h>
#include "info.h"


static IMAGE_NT_HEADERS* ValidatePeHeader(IMAGE_DOS_HEADER* lpFileHead)
{
	IMAGE_NT_HEADERS* ntHeader;

	if (!lpFileHead)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	if (lpFileHead->e_lfanew < offsetof(IMAGE_DOS_HEADER, e_lfanew) + sizeof(DWORD))
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}

	ntHeader = (IMAGE_NT_HEADERS*)((PBYTE)lpFileHead + lpFileHead->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}

	return ntHeader;
}

static DWORD FindRvaOffset(IMAGE_NT_HEADERS* ntHeader, DWORD dwRVA)
{
	IMAGE_SECTION_HEADER* section;
	WORD sectionCount;
	DWORD sectionSize;

	if (!ntHeader)
		return 0;

	sectionCount = ntHeader->FileHeader.NumberOfSections;
	if (sectionCount == 0)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	section = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < sectionCount; ++i, ++section)
	{
		sectionSize = section->Misc.VirtualSize;
		if (sectionSize < section->SizeOfRawData)
			sectionSize = section->SizeOfRawData;

		if (dwRVA >= section->VirtualAddress &&
			dwRVA < section->VirtualAddress + sectionSize)
		{
			return section->PointerToRawData + (dwRVA - section->VirtualAddress);
		}
	}

	SetLastError(ERROR_NOT_FOUND);
	return 0;
}

static IMAGE_SECTION_HEADER* FindSectionHeader(IMAGE_NT_HEADERS* ntHeader, DWORD dwRVA)
{
	IMAGE_SECTION_HEADER* section;
	WORD sectionCount;
	DWORD sectionSize;

	if (!ntHeader)
		return NULL;

	sectionCount = ntHeader->FileHeader.NumberOfSections;
	if (sectionCount == 0)
	{
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	section = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < sectionCount; ++i, ++section)
	{
		sectionSize = section->Misc.VirtualSize;
		if (sectionSize < section->SizeOfRawData)
			sectionSize = section->SizeOfRawData;

		if (dwRVA >= section->VirtualAddress &&
			dwRVA < section->VirtualAddress + sectionSize)
		{
			return section;
		}
	}

	SetLastError(ERROR_NOT_FOUND);
	return NULL;
}

BOOL IsPe64(const IMAGE_NT_HEADERS* ntHeader)
{
	if (!ntHeader)
		return FALSE;
	return ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

PBYTE OffsetToPtr(PBYTE fileBase, DWORD_PTR fileOffset)
{
	if (!fileBase)
		return NULL;
	return fileBase + fileOffset;
}

BOOL WriteTextToDump(HANDLE hFile, const TCHAR* text)
{
	DWORD bytesWritten = 0;
	DWORD textLength;

	if (hFile == NULL || hFile == INVALID_HANDLE_VALUE || text == NULL)
		return FALSE;

	textLength = (DWORD)(lstrlen(text) * sizeof(TCHAR));
	if (!WriteFile(hFile, text, textLength, &bytesWritten, NULL))
		return FALSE;

	return bytesWritten == textLength;
}

void CopyAnsiToWide(const char* source, TCHAR* buffer, size_t bufferCount)
{
	int result;

	if (!buffer || bufferCount == 0)
		return;

	buffer[0] = TEXT('\0');
	if (!source)
		return;

	result = MultiByteToWideChar(CP_ACP, 0, source, -1, buffer, (int)bufferCount);
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

	if (dwRVA == 0)
		return 0;

	ntHeader = ValidatePeHeader(lpFileHead);
	if (!ntHeader)
		return 0;

	if (dwRVA < ntHeader->OptionalHeader.SizeOfHeaders)
		return dwRVA;

	return FindRvaOffset(ntHeader, dwRVA);
}

IMAGE_SECTION_HEADER* GetRVASectionHeader(IMAGE_DOS_HEADER* lpFileHead, DWORD dwRVA)
{
	IMAGE_NT_HEADERS* ntHeader;

	if (dwRVA == 0)
		return NULL;

	ntHeader = ValidatePeHeader(lpFileHead);
	if (!ntHeader)
		return NULL;

	return FindSectionHeader(ntHeader, dwRVA);
}
