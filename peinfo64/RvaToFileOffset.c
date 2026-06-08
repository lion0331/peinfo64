/*
将 RVA 转换成实际的数据位置和查找 RVA 所在的节区
*/
#include <windows.h>
#include "info.h"

extern HWND hWinEdit;

const TCHAR szNotFound[] = TEXT("无法查找");

BOOL IsPe64(const IMAGE_NT_HEADERS * ntHeader)
{
	return ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

PBYTE OffsetToPtr(PBYTE fileBase, DWORD fileOffset)
{
	if (!fileBase)
		return NULL;
	return fileBase + fileOffset;
}

BOOL WriteTextToDump(HANDLE hFile, const TCHAR * text)
{
	DWORD bytesWritten = 0;

	if (hFile == NULL || hFile == INVALID_HANDLE_VALUE || text == NULL)
		return FALSE;

	return WriteFile(hFile, text, lstrlen(text) * sizeof(TCHAR), &bytesWritten, NULL);
}

void CopyAnsiToWide(const char * source, TCHAR * buffer, size_t bufferCount)
{
	if (!buffer || bufferCount == 0)
		return;

	buffer[0] = TEXT('\0');
	if (!source)
		return;

	MultiByteToWideChar(CP_ACP, 0, source, -1, buffer, (int)bufferCount);
}

void CopySectionName(const IMAGE_SECTION_HEADER * section, TCHAR * buffer, size_t bufferCount)
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

DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA)
{
	IMAGE_NT_HEADERS * ntHeader;
	IMAGE_SECTION_HEADER * section;

	ntHeader = (IMAGE_NT_HEADERS *)((PBYTE)lpFileHead + lpFileHead->e_lfanew);
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

	MessageBox(hWinEdit, szNotFound, NULL, MB_OK);
	return 0;
}

IMAGE_SECTION_HEADER * GetRVASectionHeader(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA)
{
	IMAGE_NT_HEADERS * ntHeader;
	IMAGE_SECTION_HEADER * section;

	ntHeader = (IMAGE_NT_HEADERS *)((PBYTE)lpFileHead + lpFileHead->e_lfanew);
	section = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD index = 0; index < ntHeader->FileHeader.NumberOfSections; ++index, ++section)
	{
		DWORD sectionSize = section->Misc.VirtualSize;
		if (sectionSize < section->SizeOfRawData)
			sectionSize = section->SizeOfRawData;

		if (dwRVA >= section->VirtualAddress && dwRVA < section->VirtualAddress + sectionSize)
			return section;
	}

	MessageBox(hWinEdit, szNotFound, NULL, MB_OK);
	return NULL;
}
