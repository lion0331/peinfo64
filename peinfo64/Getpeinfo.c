/*
模块1：PE文件主要信息
*/
#include <windows.h>
#include <strsafe.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];
extern HANDLE hFileDump;

void _getMainInfo(PBYTE lpFile, IMAGE_NT_HEADERS* _lpPeHead, int _dwSize)
{
	UNREFERENCED_PARAMETER(lpFile);
	UNREFERENCED_PARAMETER(_dwSize);

	TCHAR headerBuffer[1024];
	TCHAR lineBuffer[256];
	TCHAR sectionName[32];
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(_lpPeHead);
	ULONG_PTR imageBase;

	imageBase = IsPe64(_lpPeHead)
		? (ULONG_PTR)((IMAGE_NT_HEADERS64*)_lpPeHead)->OptionalHeader.ImageBase
		: (ULONG_PTR)((IMAGE_NT_HEADERS32*)_lpPeHead)->OptionalHeader.ImageBase;

	StringCchPrintf(headerBuffer, ARRAYSIZE(headerBuffer),
		TEXT("文件名：%s\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("运行平台：          0x%04X\r\n")
		TEXT("节区数量：          %u\r\n")
		TEXT("文件属性：          0x%04X\r\n")
		TEXT("建议装入基地址：    %p\r\n")
		TEXT("文件执行入口(RVA地址)：  0x%08X\r\n\r\n"),
		szFileName,
		_lpPeHead->FileHeader.Machine,
		_lpPeHead->FileHeader.NumberOfSections,
		_lpPeHead->FileHeader.Characteristics,
		(void*)imageBase,
		_lpPeHead->OptionalHeader.AddressOfEntryPoint);
	WriteTextToDump(hFileDump, headerBuffer);

	WriteTextToDump(hFileDump,
		TEXT("\r\n--------------------------------------------------------\r\n")
		TEXT("节的属性参考：\r\n")
		TEXT("  00000020h  包含代码\r\n")
		TEXT("  00000040h  包含已经初始化的数据，如.const\r\n")
		TEXT("  00000080h  包含未初始化数据，如 .bss\r\n")
		TEXT("  02000000h  数据在进程开始以后被丢弃，如.reloc\r\n")
		TEXT("  04000000h  节中数据不经过缓存\r\n")
		TEXT("  08000000h  节中数据不会被交换到磁盘\r\n")
		TEXT("  10000000h  数据将被不同进程共享\r\n")
		TEXT("  20000000h  可执行\r\n")
		TEXT("  40000000h  可读\r\n")
		TEXT("  80000000h  可写\r\n")
		TEXT("---------------------------------------------------------------------------------\r\n\r\n")
		TEXT("节的名称  未对齐前真实长度  内存中的偏移(对齐后的) 文件中对齐后的长度 文件中的偏移  节的属性\r\n")
		TEXT("\r\n---------------------------------------------------------------------------------------------\r\n"));

	for (DWORD index = 0; index < _lpPeHead->FileHeader.NumberOfSections; ++index, ++section)
	{
		CopySectionName(section, sectionName, ARRAYSIZE(sectionName));
		StringCchPrintf(lineBuffer, ARRAYSIZE(lineBuffer), TEXT("%-8s     %08X         %08X              %08X           %08X     %08X\r\n"),
			sectionName,
			section->Misc.VirtualSize,
			section->VirtualAddress,
			section->SizeOfRawData,
			section->PointerToRawData,
			section->Characteristics);
		WriteTextToDump(hFileDump, lineBuffer);
	}
}
