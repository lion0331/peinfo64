/*
模块2：PE导入表信息
实现流程：
1、获取数据目录项第1项导入表的数据初始RVA，
2、将导入表的数据初始RVA转换为FOA PE文件地址，即导入表的数据区，该地址为导入表的描述符IMAGE_IMPORT_DESCRIPTOR
3、将导入表描述符的桥1 lpstIM->OriginalFirstThunk处的RVA转换为FOA地址，即桥1指向的INT表（IMAGE_THUNK_DATA）在PE文件中的地址
4、将INT表的RVA地址转换为PE文件FOA地址，即要查找的导入函数编号+函数名的地址
总结：经过三级指针，3次RVA->FOA地址转换，最终找到导入函数所在的地址
*/
#include <windows.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];	//pemian.c模块中定义
extern HANDLE hWinEdit,hFileDump;
extern HWND hWinMain;

void _AppendInfo(const TCHAR * _lpsz);
DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);
DWORD GetRVASection(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);

void _getImportInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	const TCHAR szMsg1[] = TEXT("\r\n\r\n")
		TEXT("---------------------------------------------------------------------------------------------\r\n")
		TEXT("导入表所处的节：%s\r\n")
		TEXT("---------------------------------------------------------------------------------------------\r\n");

	const TCHAR szMsgImport[] = TEXT("\r\n--------------------------------------------------------\r\n")
		TEXT("导入库： %s\r\n")
		TEXT("----------------------------------------------------------\r\n")
		TEXT("OriginalFirstThunk %08X\r\n")
		TEXT("TimeDateStamp      %08X\r\n")
		TEXT("ForwarderChain     %08X\r\n")
		TEXT("FirstThunk         %08X\r\n")
		TEXT("----------------------------------------------------------\r\n")
		TEXT("导入序号  导入函数名称\r\n")
		TEXT("----------------------------------------------------------\r\n");

	const TCHAR szMsg2[] = TEXT("%-8u  %-s\r\n");
	const TCHAR szMsg3[] = TEXT("%8u  (无函数名,按序号导入)\r\n");
	const TCHAR szErrNoImport[] = TEXT("\r\n\r\n未发现该文件有导入函数\r\n");

	static TCHAR szBuffer1[512];
	static TCHAR szBuffer2[64];
	static TCHAR szSectionName[16];
	static TCHAR szNameB[256];
	static TCHAR szNameW[256];
	IMAGE_NT_HEADERS32 * lpstNT32;		//PE32文件头
	IMAGE_NT_HEADERS64 * lpstNT64;		//PE64文件头
	IMAGE_IMPORT_DESCRIPTOR * lpstIM;	//导入表描述符地址
	IMAGE_IMPORT_BY_NAME * lpstBN;	//导入函数名称
	DWORD rva, address;
	PDWORD lpAddr;
	TCHAR * szName;
	DWORD dwBytesWrite;

	lpstNT32 = _lpPeHead;
	lpstNT64 = (IMAGE_NT_HEADERS64 *)_lpPeHead;
	//访问数据目录表--数据目录第1项
	if (lpstNT64->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		rva = lpstNT64->OptionalHeader.DataDirectory[1].VirtualAddress;
	}
	else
		rva = lpstNT32->OptionalHeader.DataDirectory[1].VirtualAddress;
	if (!rva)
	{
		MessageBox(hWinMain, szErrNoImport, NULL, MB_OK);
		return;
	}
	//将 RVA 转换成实际的数据位置
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva);
	if (!address)
		return;
	lpstIM = (IMAGE_IMPORT_DESCRIPTOR *)(address + (DWORD)lpFile);
	//获取节区名，并显示PE文件名
	address = GetRVASection((IMAGE_DOS_HEADER *)lpFile, lpstIM->OriginalFirstThunk);
	if (!address)
		return;
	szName = (TCHAR *)address;
	RtlCopyMemory(szSectionName, (LPCWSTR)szName, 8);//改用内存拷贝
	//需要将节区名称ASCII码字符转为Unicode字符
	MultiByteToWideChar(CP_ACP, 0, (LPCCH)szName, 8, szSectionName, 16);
	wsprintf(szBuffer1, szMsg1,szSectionName);
	//SetWindowText(hWinEdit, szBuffer);
	//写入Dump文件
	dwBytesWrite = 0;
	WriteFile(hFileDump, szBuffer1, sizeof(szBuffer1), &dwBytesWrite, NULL);

	//循环处理 IMAGE_IMPORT_DESCRIPTOR 直到遇到全零的则结束
	while (lpstIM->OriginalFirstThunk || lpstIM->TimeDateStamp ||
		lpstIM->ForwarderChain || lpstIM->Name || lpstIM->FirstThunk)
	{
		//获取导入库DLL字符串名的实际地址
		address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstIM->Name);
		if (!address)
			break;
		lpAddr = (PDWORD)(address + (DWORD)lpFile);
		lstrcpy(szNameB, (LPCWSTR)lpAddr);//拷贝导入库名
		MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 256, szNameW, 256);//转宽字符
		RtlZeroMemory(szBuffer1, sizeof(szBuffer1));
		wsprintf(szBuffer1, szMsgImport, szNameW,
			lpstIM->OriginalFirstThunk, lpstIM->TimeDateStamp,
			lpstIM->ForwarderChain, lpstIM->FirstThunk);
		//_AppendInfo(szBuffer);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szBuffer1, sizeof(szBuffer1), &dwBytesWrite, NULL);
		//获取IMAGE_THUNK_DATA列表地址：OriginalFirstThunk地址或FirstThunk地址
		if (lpstIM->OriginalFirstThunk)
		{
			address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstIM->OriginalFirstThunk);
		}
		else
		{
			address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstIM->FirstThunk);
		}
		if (!address)
			break;
		address += (DWORD)lpFile;
		lpAddr = (PDWORD)address;
		//循环处理所有的IMAGE_THUNK_DATA
		while (*lpAddr)
		{
			//按序号导入
			if (*lpAddr & IMAGE_ORDINAL_FLAG32)
			{
				RtlZeroMemory(szBuffer2, sizeof(szBuffer2));
				wsprintf(szBuffer2, szMsg3, *lpAddr & 0xFFF);
			}
			else//按函数名导入
			{
				//获取导入函数名的实际地址
				address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, *lpAddr);
				if (!address)
					break;
				lpstBN = (IMAGE_IMPORT_BY_NAME *)(address + (DWORD)lpFile);
				lstrcpy(szNameB, (LPCWSTR)lpstBN->Name);//拷贝导入库名
				MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 256, szNameW, 256);//转宽字符				

				RtlZeroMemory(szBuffer2, sizeof(szBuffer2));
				wsprintf(szBuffer2, szMsg2, lpstBN->Hint, szNameW);
			}
			//_AppendInfo(szBuffer);
			//写入Dump文件
			dwBytesWrite = 0;
			WriteFile(hFileDump, szBuffer2, sizeof(szBuffer2), &dwBytesWrite, NULL);
			lpAddr++;
		}
		lpstIM++;
	}
}