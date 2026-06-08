/*
模块1：PE文件主要信息
*/
#include <windows.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];	//pemian.c模块中定义
extern HANDLE hWinEdit,hFileDump;
void _AppendInfo(const TCHAR * _lpsz);

void _getMainInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	static TCHAR szBuffer1[512];
	static TCHAR szBuffer2[94];
	static TCHAR szSectionName[16];
	static TCHAR szName[16];
	IMAGE_NT_HEADERS * lpstNT;		//PE文件头
	IMAGE_SECTION_HEADER * lpstSE;	//节表，8个字节的节区名称为ASCII码字符
	DWORD dwBytesWrite;

	const TCHAR szMsg[] = TEXT("文件名：%s\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("运行平台：          0x%04X  (014c:Intel 386   014dh:Intel 486  014eh:Intel 586)\r\n")
		TEXT("节区数量：          %d\r\n")
		TEXT("文件属性：          0x%04X  (大尾-禁止多处理器-DLL-系统文件-禁止网络运行-禁止优盘运行-无调试-32位-小尾-X-X-X-无符号-无行-可执行-无重定位)\r\n")
		TEXT("建议装入基地址：    0x%08X\r\n")
		TEXT("文件执行入口(RVA地址)：  0x%04x\r\n\r\n");
	const TCHAR szMsgSec[] = TEXT("\r\n--------------------------------------------------------\r\n")
		TEXT("节的属性参考：\r\n")
		TEXT("  00000020h  包含代码\r\n")
		TEXT("  00000040h  包含已经初始化的数据，如.const\r\n")
		TEXT("  00000080h  包含未初始化数据，如 .data?\r\n")
		TEXT("  02000000h  数据在进程开始以后被丢弃，如.reloc\r\n")
		TEXT("  04000000h  节中数据不经过缓存\r\n")
		TEXT("  08000000h  节中数据不会被交换到磁盘\r\n")
		TEXT("  10000000h  数据将被不同进程共享\r\n")
		TEXT("  20000000h  可执行\r\n")
		TEXT("  40000000h  可读\r\n")
		TEXT("  80000000h  可写\r\n")
		TEXT("常见的代码节一般为：60000020h,数据节一般为：c0000040h，常量节一般为：40000040h\r\n")
		TEXT("---------------------------------------------------------------------------------\r\n\r\n")
		TEXT("节的名称  未对齐前真实长度  内存中的偏移(对齐后的) 文件中对齐后的长度 文件中的偏移  节的属性\r\n")
		TEXT("\r\n---------------------------------------------------------------------------------------------\r\n");

	const TCHAR szFmtSec[] = TEXT("%-8s     %08x         %08x              %08x           %08x     %08x\r\n");
	WORD unicodeFlag = 0xFEFF;

	lpstNT = _lpPeHead;
	//显示PE文件头中的一些信息
	wsprintf(szBuffer1, szMsg, szFileName, lpstNT->FileHeader.Machine, lpstNT->FileHeader.NumberOfSections,
		lpstNT->FileHeader.Characteristics, lpstNT->OptionalHeader.ImageBase);
	//SetWindowText(hWinEdit, szBuffer);
	//写入Dump文件
	dwBytesWrite = 0;
	//插入UNICODE文本标识符，否则打开后会显示为乱字符
	WriteFile(hFileDump,&unicodeFlag,2,&dwBytesWrite,NULL);
	WriteFile(hFileDump, szBuffer1, sizeof(szBuffer1), &dwBytesWrite, NULL);

	//循环显示每个节区的信息
	//_AppendInfo(szMsgSec);
	WriteFile(hFileDump, szMsgSec, sizeof(szMsgSec), &dwBytesWrite, NULL);
	int count = lpstNT->FileHeader.NumberOfSections;
	//lpstSE = (IMAGE_SECTION_HEADER *)lpstNT + sizeof(IMAGE_NT_HEADERS);//错误

	lpstSE = (IMAGE_SECTION_HEADER *)(lpstNT + 1);//指向节表
	//if (lpstNT->FileHeader.SizeOfOptionalHeader == 0xf0) //64位PE文件
	//或者
	if (lpstNT->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		//lstrcpy(szSectionName,(LPCWSTR)lpstSE);//SectionName不是以0结尾的标准字符串
		lpstSE = (IMAGE_SECTION_HEADER *)((PBYTE)lpstSE + 16);
	}
	do
	{
		RtlZeroMemory(szSectionName, sizeof(szSectionName));
		RtlZeroMemory(szBuffer2, sizeof(szBuffer2));

		RtlCopyMemory(szSectionName, (LPCWSTR)lpstSE, 8);//改用内存拷贝
		//需要将节区名称ASCII码字符转为Unicode字符
		MultiByteToWideChar(CP_ACP, 0, (LPCCH)szSectionName, 8, szName, 16);
		wsprintf(szBuffer2, szFmtSec, szName, lpstSE->Misc.VirtualSize,//节区的尺寸
			lpstSE->VirtualAddress, lpstSE->SizeOfRawData,		//节区的RVA地址和文件中对齐后的尺寸
			lpstSE->PointerToRawData, lpstSE->Characteristics);//在文件中的偏移和节区属性
		//_AppendInfo(szBuffer);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szBuffer2, sizeof(szBuffer2), &dwBytesWrite, NULL);
		//lpstSE += sizeof(IMAGE_SECTION_HEADER);//错误
		lpstSE++;
		count--;
	} while (count > 0);

}