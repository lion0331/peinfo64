/*
PEInfo工具的实现
支持32位和64位PE文件
*/
#include <strsafe.h>
#include <stdlib.h>
#include "resource.h"
#include "info.h"

HINSTANCE hInstance;
HWND hWinMain, hWinEdit;
HMODULE hRichEdit;
TCHAR szFileName[MAX_PATH];
TCHAR szDumpFileName[MAX_PATH];
HANDLE hFileDump;

static BOOL BuildDumpPath(const TCHAR * sourcePath, TCHAR * dumpPath, size_t dumpPathCount)
{
	TCHAR * fileNamePart = NULL;

	if (!sourcePath || !dumpPath || dumpPathCount == 0)
		return FALSE;

	if (FAILED(StringCchCopy(dumpPath, dumpPathCount, sourcePath)))
		return FALSE;

	for (TCHAR * current = dumpPath; *current; ++current)
	{
		if (*current == TEXT('\\') || *current == TEXT('/'))
			fileNamePart = current + 1;
	}

	if (fileNamePart)
		*fileNamePart = TEXT('\0');
	else
		dumpPath[0] = TEXT('\0');

	return SUCCEEDED(StringCchCat(dumpPath, dumpPathCount, TEXT("PEInfo.txt")));
}

void ShowErrMsg()
{
	LPVOID lpMsgBuf = NULL;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL);

	MessageBox(NULL, (LPCTSTR)lpMsgBuf, TEXT("系统错误"), MB_OK | MB_ICONSTOP);
	LocalFree(lpMsgBuf);
}

int WINAPI WinMain(_In_ HINSTANCE instance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nShowCmd);

	hRichEdit = LoadLibrary(TEXT("RichEd20.dll"));
	hInstance = instance;
	DialogBoxParam(hInstance, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgProc, 0);
	if (hRichEdit)
		FreeLibrary(hRichEdit);
	return 0;
}

void init()
{
	CHARFORMAT stCf;
	TCHAR szFont[] = TEXT("宋体");
	HICON hIcon;

	hWinEdit = GetDlgItem(hWinMain, IDC_INFO);
	hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(ICO_MAIN));
	SendMessage(hWinMain, WM_SETICON, ICON_BIG, (LPARAM)hIcon);

	SendMessage(hWinEdit, EM_SETTEXTMODE, TM_PLAINTEXT, 0);
	RtlZeroMemory(&stCf, sizeof(stCf));
	stCf.cbSize = sizeof(stCf);
	stCf.yHeight = 9 * 20;
	stCf.dwMask = CFM_FACE | CFM_SIZE | CFM_BOLD;
	StringCchCopy(stCf.szFaceName, ARRAYSIZE(stCf.szFaceName), szFont);
	SendMessage(hWinEdit, EM_SETCHARFORMAT, 0, (LPARAM)&stCf);
	SendMessage(hWinEdit, EM_EXLIMITTEXT, 0, -1);
}

BOOL CALLBACK DlgProc(HWND hWnd, UINT wMsg, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	const TCHAR szErr[] = TEXT("文件格式错误！");
	const TCHAR szErrFormat[] = TEXT("这个文件不是PE格式的文件!");

	switch (wMsg)
	{
	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return TRUE;

	case WM_INITDIALOG:
		hWinMain = hWnd;
		init();
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDM_EXIT:
			EndDialog(hWnd, 0);
			return TRUE;
		case IDM_OPEN:
			_OpenFile();
			return TRUE;
		case IDM_1:
		case IDM_2:
		case IDM_3:
			MessageBox(NULL, szErrFormat, szErr, MB_ICONWARNING);
			return TRUE;
		}
		break;
	}

	return FALSE;
}

int CALLBACK _Handler(EXCEPTION_POINTERS * lpExceptionPoint)
{
	static TCHAR szBuffer[256];
	TCHAR szAddress[32];
	PCONTEXT pContext = lpExceptionPoint->ContextRecord;
	PEXCEPTION_RECORD pException = lpExceptionPoint->ExceptionRecord;

#ifdef _WIN64
	ULONG_PTR exceptionAddress = (ULONG_PTR)pContext->Rip;
#else
	ULONG_PTR exceptionAddress = (ULONG_PTR)pContext->Eip;
#endif

	StringCchPrintf(szAddress, ARRAYSIZE(szAddress), TEXT("%p"), (void*)exceptionAddress);
	StringCchPrintf(szBuffer, ARRAYSIZE(szBuffer), TEXT("异常发生位置：%s，异常代码：%08X，标志：%08X"), szAddress, pException->ExceptionCode, pException->ExceptionFlags);
	MessageBox(NULL, szBuffer, NULL, MB_OK);
	return EXCEPTION_EXECUTE_HANDLER;
}

void _OpenFile()
{
	OPENFILENAME stOF;
	HANDLE hFile = NULL;
	HANDLE hMapFile = NULL;
	PBYTE lpMemory = NULL;
	LARGE_INTEGER fileSize;
	DWORD dumpBytesWritten = 0;
	WORD unicodeFlag = 0xFEFF;
	const TCHAR szDefaultExt[] = TEXT("exe");
	const TCHAR szFilter[] = TEXT("PE Files (*.exe)\0*.exe\0")
		TEXT("DLL Files(*.dll)\0*.dll\0")
		TEXT("SCR Files(*.scr)\0*.scr\0")
		TEXT("FON Files(*.fon)\0*.fon\0")
		TEXT("DRV Files(*.drv)\0*.drv\0")
		TEXT("All Files(*.*)\0*.*\0\0");
	const TCHAR szErrFormat[] = TEXT("操作文件时出现错误！");
	IMAGE_DOS_HEADER * lpstDOS;
	IMAGE_NT_HEADERS * lpstNT;

	RtlZeroMemory(&stOF, sizeof(stOF));
	RtlZeroMemory(szFileName, sizeof(szFileName));
	RtlZeroMemory(szDumpFileName, sizeof(szDumpFileName));

	stOF.lStructSize = sizeof(stOF);
	stOF.hwndOwner = hWinMain;
	stOF.lpstrFilter = szFilter;
	stOF.lpstrFile = szFileName;
	stOF.nMaxFile = MAX_PATH;
	stOF.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	stOF.lpstrDefExt = szDefaultExt;
	if (!GetOpenFileName(&stOF))
		return;

	if (!BuildDumpPath(szFileName, szDumpFileName, ARRAYSIZE(szDumpFileName)))
	{
		MessageBox(hWinMain, TEXT("生成输出文件路径失败！"), NULL, MB_ICONWARNING);
		return;
	}

	hFileDump = CreateFile(szDumpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileDump == INVALID_HANDLE_VALUE)
	{
		hFileDump = NULL;
		MessageBox(NULL, TEXT("创建输出文件失败！"), NULL, MB_ICONWARNING);
		return;
	}

	WriteFile(hFileDump, &unicodeFlag, sizeof(unicodeFlag), &dumpBytesWritten, NULL);

	hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, TEXT("打开文件失败！"), NULL, MB_ICONWARNING);
		CloseHandle(hFileDump);
		hFileDump = NULL;
		return;
	}

	if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > MAXDWORD)
		goto ErrorFormat;

	hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapFile)
		goto ErrorFormat;

	SetUnhandledExceptionFilter(_Handler);
	lpMemory = (PBYTE)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!lpMemory)
		goto ErrorFormat;

	lpstDOS = (IMAGE_DOS_HEADER *)lpMemory;
	if (lpstDOS->e_magic != IMAGE_DOS_SIGNATURE)
		goto ErrorFormat;

	lpstNT = (IMAGE_NT_HEADERS *)(lpMemory + lpstDOS->e_lfanew);
	if (lpstNT->Signature != IMAGE_NT_SIGNATURE)
		goto ErrorFormat;

	_getMainInfo(lpMemory, lpstNT, (int)fileSize.QuadPart);
	_getImportInfo(lpMemory, lpstNT, (int)fileSize.QuadPart);
	_getExportInfo(lpMemory, lpstNT, (int)fileSize.QuadPart);
	_getRelocInfo(lpMemory, lpstNT, (int)fileSize.QuadPart);
	_getResourceInfo(lpMemory, lpstNT, (int)fileSize.QuadPart);
	goto Cleanup;

ErrorFormat:
	MessageBox(hWinMain, szErrFormat, NULL, MB_OK);

Cleanup:
	if (lpMemory)
		UnmapViewOfFile(lpMemory);
	if (hMapFile)
		CloseHandle(hMapFile);
	if (hFile)
		CloseHandle(hFile);
	if (hFileDump)
	{
		CloseHandle(hFileDump);
		hFileDump = NULL;
	}

	_readToRichEdit();
}

void _AppendInfo(const TCHAR * _lpsz)
{
	CHARRANGE stCR;

	stCR.cpMin = GetWindowTextLength(hWinEdit);
	stCR.cpMax = stCR.cpMin;
	SendMessage(hWinEdit, EM_EXSETSEL, 0, (LPARAM)&stCR);
	SendMessage(hWinEdit, EM_REPLACESEL, FALSE, (LPARAM)_lpsz);
}

void _Init()
{
	CHARFORMAT stCf;
	static TCHAR szFont[] = TEXT("宋体");

	hWinEdit = GetDlgItem(hWinMain, IDC_INFO);
	SendMessage(hWinEdit, EM_SETTEXTMODE, TM_PLAINTEXT, 0);
	RtlZeroMemory(&stCf, sizeof(stCf));
	stCf.cbSize = sizeof(stCf);
	stCf.yHeight = 9 * 20;
	stCf.dwMask = CFM_FACE | CFM_SIZE | CFM_BOLD;
	StringCchCopy(stCf.szFaceName, ARRAYSIZE(stCf.szFaceName), szFont);
	SendMessage(hWinEdit, EM_SETCHARFORMAT, 0, (LPARAM)&stCf);
	SendMessage(hWinEdit, EM_EXLIMITTEXT, 0, -1);
}

void Exception(void)
{
	MessageBox(hWinMain, TEXT("获得文件在内存的映象起始位置失败!"), NULL, MB_OK);
}

void _readToRichEdit()
{
	const TCHAR szErrOpenFile[] = TEXT("无法打开源文件!");
	HANDLE hFile;
	DWORD dwBytesRead = 0;
	LARGE_INTEGER fileSize;
	TCHAR * pContent;

	hFile = CreateFile(szDumpFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(hWinMain, szErrOpenFile, NULL, MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > (MAXDWORD - sizeof(TCHAR)))
	{
		CloseHandle(hFile);
		return;
	}

	pContent = (TCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)fileSize.QuadPart + sizeof(TCHAR));
	if (!pContent)
	{
		CloseHandle(hFile);
		return;
	}

	if (!ReadFile(hFile, pContent, (DWORD)fileSize.QuadPart, &dwBytesRead, NULL))
	{
		HeapFree(GetProcessHeap(), 0, pContent);
		CloseHandle(hFile);
		return;
	}

	SetWindowText(hWinEdit, TEXT(""));
	if (dwBytesRead >= sizeof(WORD) && *((WORD*)pContent) == 0xFEFF)
		SetWindowText(hWinEdit, pContent + 1);
	else
		SetWindowText(hWinEdit, pContent);

	HeapFree(GetProcessHeap(), 0, pContent);
	CloseHandle(hFile);
}
