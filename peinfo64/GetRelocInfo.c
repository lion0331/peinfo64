/*
模块4：PE重定位表信息
*/
#include <windows.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];	//pemian.c模块中定义
extern HANDLE hWinEdit,hFileDump;
extern HWND hWinMain;

void _AppendInfo(const TCHAR * _lpsz);
DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);
DWORD GetRVASection(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);

void _getRelocInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	const TCHAR szMsgReloc1[] = TEXT("\r\n")
		TEXT("重定位表所处的节：%s\r\n");
	const TCHAR szMsgReloc2[] = TEXT("\r\n---------------------------------------------------------\r\n")
		TEXT("重定位基地址：     %08X\r\n")
		TEXT("重定位项数量：     %d\r\n")
		TEXT("\r\n---------------------------------------------------------\r\n")
		TEXT("需要重定位的地址列表(ffffffff表示对齐用,不需要重定位)\r\n")
		TEXT("---------------------------------------------------------\r\n");
	const TCHAR szMsgReloc3[] = TEXT("%08X  ");
	const TCHAR szCrLf[] = TEXT("\r\n");
	const TCHAR szErrNoReloc[] = TEXT("\r\n未发现该文件有重定位信息!");

	static TCHAR szBuffer[256];
	static TCHAR szBuffer2[16];
	static TCHAR szSectionName[16];
	static TCHAR szNameB[256];
	IMAGE_NT_HEADERS32 * lpstNT32;		//PE32文件头
	IMAGE_NT_HEADERS64 * lpstNT64;		//PE64文件头
	IMAGE_BASE_RELOCATION * lpstREL;	//重定位表
	DWORD rva, address, dwBytesWrite;


	lpstNT32 = _lpPeHead;
	lpstNT64 = (IMAGE_NT_HEADERS64 *)_lpPeHead;
	//从数据目录中获取重定位表位置--数据目录第5项
	if (lpstNT64->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		rva = lpstNT64->OptionalHeader.DataDirectory[5].VirtualAddress;
	}
	else
		rva = lpstNT32->OptionalHeader.DataDirectory[5].VirtualAddress;
	if (!rva)
	{
		MessageBox(hWinMain, szErrNoReloc, NULL, MB_OK);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szErrNoReloc, sizeof(szErrNoReloc), &dwBytesWrite, NULL);
		return;
	}
	//将 RVA 转换成实际的数据位置
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva);
	if (!address)
		return;
	lpstREL = (IMAGE_BASE_RELOCATION *)(address + (DWORD)lpFile);//重定位表的实际地址

	//获取节区名
	address = GetRVASection((IMAGE_DOS_HEADER *)lpFile, rva);
	if (!address)
		return;
	RtlCopyMemory(szNameB, (LPCWSTR)address, 8);//改用内存拷贝
	//需要将节区名称ASCII码字符转为Unicode字符
	MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 8, szSectionName, 16);
	//显示信息
	RtlZeroMemory(szBuffer, sizeof(szBuffer));
	wsprintf(szBuffer, szMsgReloc1,szSectionName);
	//SetWindowText(hWinEdit, szBuffer);
	//写入Dump文件
	dwBytesWrite = 0;
	WriteFile(hFileDump, szBuffer, sizeof(szBuffer), &dwBytesWrite, NULL);

	//循环处理每个重定位块
	int count = 0;	//重定位项的数量
	DWORD lpAddr;	//重定位表起始地址
	DWORD baseAddr; //重定位表基地址
	short words = 0;//重定位项数据-字
	/*64位PE文件内核地址
	//ULONG_PTR  OriginalImageBase;//内核文件的imagebase

	//获取内核文件的imagebase，以便后面做偏移修改。
	//OriginalImageBase = lpstNT64->OptionalHeader.ImageBase;
	*/
	lpAddr = (DWORD)lpstREL;
	while (lpstREL->VirtualAddress)
	{
		RtlZeroMemory(szBuffer,sizeof(szBuffer));
		baseAddr = *(PDWORD)lpAddr;
		count = ((*(PDWORD)(lpAddr + 4) - sizeof(IMAGE_BASE_RELOCATION)) / 2);
		wsprintf(szBuffer, szMsgReloc2, baseAddr, count);
		//_AppendInfo(szBuffer);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szBuffer, sizeof(szBuffer), &dwBytesWrite, NULL);
		//获取重定位项
		lpAddr += sizeof(IMAGE_BASE_RELOCATION);//移动指针
		for (int i = 1; i <= count; i++)
		{
			words = *(PWORD)lpAddr;
			lpAddr += 2;
			//处理 IMAGE_REL_BASED_HIGHLOW 类型的重定位项
			if ((words & 0x0f000) == 0x03000)
				address = words & 0x0fff + baseAddr;//12位地址+重定位基地址
			//处理 IMAGE_REL_BASED_DIR64 64位PE文件类型的重定位项
			else if ((words & 0x0f000) == 0x0a000)//IMAGE_REL_BASED_DIR64
			{
				/*64位地址
				//修改地址，相对地址加上一个新内核地址，使其成为一个实际地址
				address = (ULONG64 *)(words & 0x0fff + baseAddr + (ULONG64)lpFile);
				//再加上内核首地址到imagebase的偏移
				*address = *address + (OrigImage - OriginalImageBase);
				*/
				//因为尚未取得内核首地址，暂且按照32位地址显示
				address = words & 0x0fff + baseAddr;//12位地址+重定位基地址
			}
			else
				address = -1;
			RtlZeroMemory(szBuffer2, sizeof(szBuffer2));
			wsprintf(szBuffer2, szMsgReloc3, address);
			//每显示4个项目换行
			if (i % 4 == 0)
				lstrcat(szBuffer2, szCrLf);
			//_AppendInfo(szBuffer2);
			//写入Dump文件
			dwBytesWrite = 0;
			WriteFile(hFileDump, szBuffer2, sizeof(szBuffer2), &dwBytesWrite, NULL);
		}
		//处理下一页
		lpstREL = (IMAGE_BASE_RELOCATION *)(lpAddr + 2);
	}
	_AppendInfo(szCrLf);
}