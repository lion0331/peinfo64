/*
模块3：PE导出表信息
*/
#include <windows.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];	//pemian.c模块中定义
extern HANDLE hWinEdit,hFileDump;
extern HWND hWinMain;

void _AppendInfo(const TCHAR * _lpsz);
DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);
DWORD GetRVASection(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);

void _getExportInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	const TCHAR szMsgExport[] = TEXT("\r\n\r\n\r\n\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("导出表所处的节：%s\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("原始文件名          %s\r\n")
		TEXT("nBase               %08X\r\n")
		TEXT("NumberOfFunctions   %08X\r\n")
		TEXT("NumberOfNames       %08X\r\n")
		TEXT("AddressOfFunctions  %08X\r\n")
		TEXT("AddressOfNames      %08X\r\n")
		TEXT("AddressOfNameOrd    %08X\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("导出序号  虚拟地址  导出函数名称\r\n")
		TEXT("---------------------------------------------------------\r\n");
	const TCHAR szMsg4[] = TEXT("\r\n%08X  %08X  %s\r\n");
	const TCHAR szExportByOrd[] = TEXT("(按照序号导出)");
	const TCHAR szErrNoExport[] = TEXT("\r\n这个文件中没有导出函数!\r\n");

	static TCHAR szBuffer[256];
	static TCHAR szSectionName[16];
	static TCHAR szNameB[256];
	static TCHAR szNameW[256];
	IMAGE_NT_HEADERS32 * lpstNT32;		//PE32文件头
	IMAGE_NT_HEADERS64 * lpstNT64;		//PE64文件头
	IMAGE_EXPORT_DIRECTORY * lpstEX;	//导出表地址
	DWORD rva, address;
	PBYTE lpAddressOfNames, lpAddressOfNamesOrdinals, lpAddressOfFunctions;
	PBYTE lpFuctionName = NULL;
	TCHAR * lpDllName;
	PDWORD lpAddr = NULL;
	WORD dwIndex;
	DWORD dwBytesWrite;

	lpstNT32 = _lpPeHead;
	lpstNT64 = (IMAGE_NT_HEADERS64 *)_lpPeHead;
	//从数据目录中获取导出表的位置--数据目录第0项
	if (lpstNT64->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		rva = lpstNT64->OptionalHeader.DataDirectory[0].VirtualAddress;
	}
	else
		rva = lpstNT32->OptionalHeader.DataDirectory[0].VirtualAddress;

	if (!rva)
	{
		MessageBox(hWinMain, szErrNoExport, NULL, MB_OK);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szErrNoExport, sizeof(szErrNoExport), &dwBytesWrite, NULL);
		return;
	}
	//将 RVA 转换成实际的数据位置
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva);
	if (!address)
		return;
	lpstEX = (IMAGE_EXPORT_DIRECTORY *)(address + (DWORD)lpFile);//导出表的实际地址
	if (lpstNT64->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		//lstrcpy(szSectionName,(LPCWSTR)lpstSE);//SectionName不是以0结尾的标准字符串
		lpstEX = (IMAGE_EXPORT_DIRECTORY *)((PBYTE)lpstEX + 16);
	}
	//获取原始DLL文件名
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstEX->Name);
	if (!address)
		return;
	lpDllName = (TCHAR *)(address + (DWORD)lpFile);
	RtlCopyMemory(szNameB, (char*)lpDllName, strlen((char*)lpDllName));//拷贝导入库名
	MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 256, szNameW, 256);//转宽字符

	//获取节区名
	address = GetRVASection((IMAGE_DOS_HEADER *)lpFile, lpstEX->Name);
	if (!address)
		return;
	RtlCopyMemory(szNameB, (LPCWSTR)address, 8);//改用内存拷贝
	//需要将节区名称ASCII码字符转为Unicode字符
	MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 8, szSectionName, 16);
	//显示一些常用的信息
	RtlZeroMemory(szBuffer, sizeof(szBuffer));
	wsprintf(szBuffer, szMsgExport, szFileName, szSectionName, szNameW, lpstEX->Base,
		lpstEX->NumberOfFunctions, lpstEX->NumberOfNames, lpstEX->AddressOfFunctions,
		lpstEX->AddressOfNames, lpstEX->AddressOfNameOrdinals);
	//SetWindowText(hWinEdit, szBuffer);

	//指向导出函数名地址表的 RVA
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstEX->AddressOfNames);
	if (!address)
		return;
	lpAddressOfNames = (PBYTE)(address + (DWORD)lpFile);

	//指向导出函数名序号表的 RVA
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstEX->AddressOfNameOrdinals);
	if (!address)
		return;
	lpAddressOfNamesOrdinals = (PBYTE)(address + (DWORD)lpFile);

	//指向导出函数地址表的 RVA
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstEX->AddressOfFunctions);
	if (!address)
		return;
	lpAddressOfFunctions = (PBYTE)(address + (DWORD)lpFile);

	//循环显示导出函数的信息
	int count = lpstEX->NumberOfFunctions;
	dwIndex = 0;
	while (count--)
	{
		//在按名称导出的索引表中查找函数名
		int i = lpstEX->NumberOfNames;
		PBYTE lptemp = lpAddressOfNamesOrdinals;
		while (i--)
		{
			if (dwIndex == (WORD)*lptemp)//索引为WORD类型数组
			{
				//索引表中的相对偏移（即函数名地址表的相对偏移） + 函数名表的基址 =函数名字符串的RVA
				lpAddr = (PDWORD)((lptemp - lpAddressOfNamesOrdinals) * 2 + lpAddressOfNames);
				address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, *lpAddr);
				lpFuctionName = (PBYTE)(address + (DWORD)lpFile);//函数名地址
				break;
			}
			else
				lpFuctionName = (PBYTE)szExportByOrd;	//未找到函数名
			lptemp += 2;
		}

		//序号
		int number = dwIndex + lpstEX->Base;

		RtlCopyMemory(szNameB, (char*)lpFuctionName,strlen((char*)lpFuctionName));//拷贝函数名
		MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 256, szNameW, 256);//转宽字符
		RtlZeroMemory(szBuffer, sizeof(szBuffer));
		wsprintf(szBuffer, szMsg4, number, *lpAddressOfFunctions, szNameW);
		//_AppendInfo(szBuffer);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szBuffer, sizeof(szBuffer), &dwBytesWrite, NULL);
		lpAddressOfFunctions += 4;
		dwIndex++;
	}

}