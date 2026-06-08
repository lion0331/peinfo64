/*
将 RVA 转换成实际的数据位置和查找 RVA 所在的节区
*/
#include <windows.h>

extern HANDLE hWinEdit;
extern HWND hWinMain;

const TCHAR szNotFound[] = TEXT("无法查找");

//将 RVA 转换成实际的数据位置
DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead,DWORD dwRVA)
{
	DWORD dwReturn;
	IMAGE_NT_HEADERS * lpstNT;		//PE文件头
	IMAGE_SECTION_HEADER * lpstSE;	//节表，8个字节的节区名称为ASCII码字符
	IMAGE_DOS_HEADER * lpstDOS;

	lpstDOS = lpFileHead;
	lpstNT = (IMAGE_NT_HEADERS *)((PBYTE)lpstDOS + lpstDOS->e_lfanew);			//PE文件头地址
	lpstSE = (IMAGE_SECTION_HEADER *)((PBYTE)lpstNT + sizeof(IMAGE_NT_HEADERS));//节表地址
	if (lpstNT->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		lpstSE = (IMAGE_SECTION_HEADER *)((PBYTE)lpstSE + 16);
	}
	int count = lpstNT->FileHeader.NumberOfSections;	//节区数目
	//扫描每个节区并判断 RVA 是否位于这个节区内
	for (int i = 0; i < count;i++)
	{
		if ((dwRVA >= lpstSE->VirtualAddress) &&						//节区的RVA地址
			(dwRVA < (lpstSE->VirtualAddress + lpstSE->SizeOfRawData))) //在文件中对齐后的尺寸
		{
			//实际位置FOA=在文件内的偏移+节区偏移 ---（节区偏移=数据目录项中的数据起始dwRVA-节区的RVA地址）
			dwReturn = (DWORD)(lpstSE->PointerToRawData + (dwRVA - lpstSE->VirtualAddress));
			return dwReturn;
		}
		lpstSE++;
	}
	MessageBox(hWinEdit, szNotFound, NULL, MB_OK);
	return dwReturn = 0;
}

//查找 RVA 所在的节区
/*
根据导入表描述符桥1所在的地址区间判断所属的节区
dwRVA = pstIM->OriginalFirstThunk
dwRVA >= lpstSE->VirtualAddress && 
dwRVA < (lpstSE->VirtualAddress + lpstSE->SizeOfRawData)
*/
DWORD GetRVASection(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA)
{
	DWORD dwReturn;
	IMAGE_NT_HEADERS * lpstNT;		//PE文件头
	IMAGE_SECTION_HEADER * lpstSE;	//节表，8个字节的节区名称为ASCII码字符
	IMAGE_DOS_HEADER * lpstDOS;

	lpstDOS = lpFileHead;
	lpstNT = (IMAGE_NT_HEADERS *)((PBYTE)lpstDOS + lpstDOS->e_lfanew);			//PE文件头地址
	lpstSE = (IMAGE_SECTION_HEADER *)((PBYTE)lpstNT + sizeof(IMAGE_NT_HEADERS));//节表地址
	if (lpstNT->OptionalHeader.Magic == 0x020B) //64位PE文件
	{
		lpstSE = (IMAGE_SECTION_HEADER *)((PBYTE)lpstSE + 16);
	}
	int count = lpstNT->FileHeader.NumberOfSections;	//节区数目
	//扫描每个节区并判断 RVA 是否位于这个节区内
	for (int i = 0; i < count; i++)
	{
		if ((dwRVA >= lpstSE->VirtualAddress) &&
			(dwRVA < (lpstSE->VirtualAddress + lpstSE->SizeOfRawData)))
		{
			//实际位置=在文件内的偏移+RVA虚拟地址+节区偏移
			dwReturn = (DWORD)lpstSE;
			return dwReturn;
		}
		lpstSE++;
	}
	MessageBox(hWinEdit, szNotFound, NULL, MB_OK);
	return dwReturn = 0;
}