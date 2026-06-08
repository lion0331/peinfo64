/*
模块5：PE资源信息
*/
#include <windows.h>
#include "info.h"

extern TCHAR szFileName[MAX_PATH];	//pemian.c模块中定义
extern HANDLE hWinEdit,hFileDump;
extern HWND hWinMain;

void _AppendInfo(const TCHAR * _lpsz);
DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);
DWORD GetRVASection(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);

//参数1：PE文件地址；参数2：资源块起始地址；参数3：目录项地址：参数4：层级
void ProcessRes(PBYTE lpFile, PBYTE lpRes, IMAGE_RESOURCE_DIRECTORY * lpResDir, DWORD dwLevel)
{
	const TCHAR szLevel1[] = TEXT("\r\n---------------------------------------------------------\r\n")
		TEXT("资源类型：%s\r\n")
		TEXT("---------------------------------------------------------\r\n");
	const TCHAR szResData[] = TEXT("     文件偏移：%08X (代码页=%04X, 长度%d字节)\r\n");
	const TCHAR szLevel1byID[] = TEXT("%d (自定义编号)");
	const TCHAR szLevel2byID[] = TEXT("  ID: %d\r\n");
	const TCHAR szLevel2byName[] = TEXT("  Name: %s\r\n");
	const TCHAR szType[][16] = {
							TEXT("光标        "),	//1
							TEXT("位图        "),//2
							TEXT("图标        "),//3
							TEXT("菜单        "),//4
							TEXT("对话框      "),//5
							TEXT("字符串      "),//6
							TEXT("字体目录    "),//7
							TEXT("字体        "),//8
							TEXT("加速键      "),//9
							TEXT("未格式化资源 "),//10
							TEXT("消息表      "),//11
							TEXT("光标组      "),//12
							TEXT("未知类型    "),//13
							TEXT("图标组      "),//14
							TEXT("未知类型    "),//15
							TEXT("版本信息    ")	//16
	};

	DWORD dwNextLevel;
	static TCHAR szBuffer[256];
	static TCHAR szResName[256];
	IMAGE_RESOURCE_DIRECTORY * lpstRES_DIR;//资源目录
	IMAGE_RESOURCE_DIRECTORY_ENTRY * lpstRES_DIR_ENT;
	IMAGE_RESOURCE_DATA_ENTRY * lpstRES_DATA_ENT;
	int number;	//资源数量
	DWORD lpAddr, address;
	DWORD IDname, dwBytesWrite;

	dwNextLevel = dwLevel + 1;
	//检查资源目录表，得到资源目录项的数量
	lpstRES_DIR = lpResDir;
	number = lpstRES_DIR->NumberOfIdEntries + lpstRES_DIR->NumberOfNamedEntries;
	//IMAGE_RESOURCE_DIRECTORY结构后面紧跟着是IMAGE_RESOURCE_DIRECTORY_ENTRY结构
	lpstRES_DIR_ENT = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)((PBYTE)lpstRES_DIR + sizeof(IMAGE_RESOURCE_DIRECTORY));

	//循环处理每个资源目录项
	while (number--)
	{
		RtlZeroMemory(szBuffer, sizeof(szBuffer));
		//OffsetToData字段最高位为1，后七位指向下层目录块的起始地址IMAGE_RESOURCE_DIRECTORY结构
		lpAddr = lpstRES_DIR_ENT->OffsetToData;
		if (lpAddr & 0x80000000)
		{
			lpAddr &= 0x7fffffff;
			lpAddr += (DWORD)lpRes;
			//第一层：资源类型
			if (dwLevel == 1)
			{
				IDname = lpstRES_DIR_ENT->Name;//目录项名称字符串或ID
				//最高位为1时，低7位值作为指向UNICODE编码的资源名IAMGE_RESOURCE_STRING_U结构
				if (IDname & 0x80000000)
				{
					IDname &= 0x7fffffff;
					IDname += (DWORD)lpRes;
					//复制UNICODE资源名
					lstrcpy(szResName, (LPCWSTR)(IDname + 2));
					address = (DWORD)szResName;
				}
				//高位为0时，表示字段的值作为ID使用
				else
				{
					if (IDname <= 16)	//为预定义资源
					{
						address = (DWORD)&szType[IDname - 1];
					}
					else //大于16，自定义资源
					{
						wsprintf(szResName, szLevel1byID, IDname);
						address = (DWORD)szResName;
					}
				}
				wsprintf(szBuffer, szLevel1, (PBYTE)address);
			}
			//第二层：资源（ID或名称）
			else if (dwLevel == 2)
			{
				IDname = lpstRES_DIR_ENT->Name;//目录项名称字符串或ID
				//资源以字符串方式命名
				if (IDname & 0x80000000)
				{
					IDname &= 0x7fffffff;
					IDname += (DWORD)lpRes;
					//复制UNICODE资源名
					lstrcpy(szResName, (LPCWSTR)(IDname + 2));
					wsprintf(szBuffer, szLevel2byName, szResName);
				}
				//资源以 ID 命名
				else
				{
					wsprintf(szBuffer, szLevel2byID, IDname);
				}
			}
			else
				break;
			//_AppendInfo(szBuffer);
			//写入Dump文件
			dwBytesWrite = 0;
			WriteFile(hFileDump, szBuffer, sizeof(szBuffer), &dwBytesWrite, NULL);
			ProcessRes(lpFile, lpRes, (IMAGE_RESOURCE_DIRECTORY *)lpAddr, dwNextLevel);	//递归调用
		}
		//OffsetToData字段最高位为0，不是资源目录则显示资源详细信息,
		//后七位指向用来描述资源数据块的IMAGE_RESOURCE_DATA_ENTRY结构
		else
		{
			lpAddr += (DWORD)lpRes;
			lpstRES_DATA_ENT = (IMAGE_RESOURCE_DATA_ENTRY *)lpAddr;
			address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, lpstRES_DATA_ENT->OffsetToData);
			if (!address)
				return;

			wsprintf(szBuffer, szResData, address,
				lpstRES_DIR_ENT->Name, lpstRES_DATA_ENT->Size);
			//_AppendInfo(szBuffer);
			//写入Dump文件
			dwBytesWrite = 0;
			WriteFile(hFileDump, szBuffer, sizeof(szBuffer), &dwBytesWrite, NULL);
		}
		lpstRES_DIR_ENT++;
	}
}

void _getResourceInfo(PBYTE lpFile, IMAGE_NT_HEADERS * _lpPeHead, int _dwSize)
{
	const TCHAR szMsg5[] = TEXT("\r\n\r\n文件名：%s\r\n")
		TEXT("---------------------------------------------------------\r\n")
		TEXT("资源所处的节：%s\r\n");
	const TCHAR szErrNoRes[] = TEXT("\r\n这个文件中没有包含资源!");

	static TCHAR szBuffer[256];
	static TCHAR szSectionName[16];
	static TCHAR szNameB[256];
	static TCHAR szNameW[256];
	IMAGE_NT_HEADERS32 * lpstNT32;		//PE32文件头
	IMAGE_NT_HEADERS64 * lpstNT64;		//PE64文件头
	IMAGE_RESOURCE_DIRECTORY * lpstRES_DIR;////资源目录
	DWORD rva, address, dwBytesWrite;

	lpstNT32 = _lpPeHead;
	lpstNT64 = (IMAGE_NT_HEADERS64 *)_lpPeHead;
	//检测是否存在资源--数据目录第2项
	if (lpstNT64->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		rva = lpstNT64->OptionalHeader.DataDirectory[2].VirtualAddress;//数据目录项的第3项
	}
	else
		rva = lpstNT32->OptionalHeader.DataDirectory[2].VirtualAddress;
	if (!rva)
	{
		MessageBox(hWinMain, szErrNoRes, NULL, MB_OK);
		//写入Dump文件
		dwBytesWrite = 0;
		WriteFile(hFileDump, szErrNoRes, sizeof(szErrNoRes), &dwBytesWrite, NULL);
		return;
	}
	//将 RVA 转换成实际的数据位置
	address = RVAToOffset((IMAGE_DOS_HEADER *)lpFile, rva);
	if (!address)
		return;
	lpstRES_DIR = (IMAGE_RESOURCE_DIRECTORY *)(address + (DWORD)lpFile);//资源目录的实际地址

	//获取资源目录所在的节区名
	address = GetRVASection((IMAGE_DOS_HEADER *)lpFile, rva);
	if (!address)
		return;
	RtlCopyMemory(szNameB, (LPCWSTR)address, 8);//改用内存拷贝
	//需要将节区名称ASCII码字符转为Unicode字符
	MultiByteToWideChar(CP_ACP, 0, (LPCCH)szNameB, 8, szSectionName, 16);
	//显示一些常用的信息
	RtlZeroMemory(szBuffer, sizeof(szBuffer));
	wsprintf(szBuffer, szMsg5, szFileName, szSectionName);
	//SetWindowText(hWinEdit, szBuffer);
	//写入Dump文件
	dwBytesWrite = 0;
	WriteFile(hFileDump, szBuffer, sizeof(szBuffer), &dwBytesWrite, NULL);

	//显示所有资源目录块的信息
	ProcessRes(lpFile, (PBYTE)lpstRES_DIR, lpstRES_DIR, 1);
}