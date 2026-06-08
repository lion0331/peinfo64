/*
PEInfo工具的实现
支持32位和64位PE文件
*/
#include <strsafe.h>	//StringCchCopy
#include "resource.h"
#include "info.h"

HANDLE hInstance;
HWND hWinMain, hWinEdit;
HMODULE hRichEdit;
TCHAR szFileName[MAX_PATH];
HANDLE hFileDump;

void ShowErrMsg()
{
	//TCHAR szBuf[80];
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	MessageBox(NULL, lpMsgBuf, L"系统错误", MB_OK | MB_ICONSTOP);

	LocalFree(lpMsgBuf);
}

int WINAPI WinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd)
{
	TCHAR	szDllEdit[] = TEXT("RichEd20.dll");
	TCHAR	szClassEdit[] = TEXT("RichEdit20W");//peinfo.rc中定义
	hRichEdit = LoadLibrary((LPCWSTR)&szDllEdit);
	hInstance = GetModuleHandle(NULL);
	DialogBoxParam(hInstance, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgProc, (LPARAM)0);
	FreeLibrary(hRichEdit);
	return 0;
}

//初始化窗口函数
void init()
{
	CHARFORMAT stCf;
	TCHAR	szClassEdit[] = TEXT("RichEdit20A");
	TCHAR	szFont[] = TEXT("宋体");
	HINSTANCE hInstance;

	hWinEdit = GetDlgItem(hWinMain, IDC_INFO);
	//为窗口程序设置图标
	hInstance = GetModuleHandle(NULL);
	HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(ICO_MAIN));
	//HICON hIcon = LoadIcon(hInstance, TEXT("#111"));
	SendMessage(hWinMain,WM_SETICON,ICON_BIG,(LPARAM)hIcon);

	//设置编辑控件
	SendMessage(hWinEdit, EM_SETTEXTMODE, TM_PLAINTEXT, 0);
	RtlZeroMemory(&stCf, sizeof(stCf));
	stCf.cbSize = sizeof(stCf);
	stCf.yHeight = 9 * 20;
	stCf.dwMask = CFM_FACE | CFM_SIZE | CFM_BOLD;
	StringCchCopy((LPTSTR)&stCf.szFaceName, lstrlen(szFont) + 1, (LPCTSTR)&szFont);
	SendMessage(hWinEdit, EM_SETCHARFORMAT, 0, (LPARAM)&stCf);
	SendMessage(hWinEdit, EM_EXLIMITTEXT, 0, -1);//设为-1表示无限制
}

//富文本窗口回调函数
BOOL CALLBACK DlgProc(HWND hWnd, UINT wMsg, WPARAM wParam, LPARAM lParam)
{
	const TCHAR szErr[] = TEXT("文件格式错误！");
	const TCHAR szErrFormat[] = TEXT("这个文件不是PE格式的文件!");
	switch (wMsg)
	{
	case WM_CLOSE:
		EndDialog(hWnd,0);
		return TRUE;

	case WM_INITDIALOG:
		hWinMain = hWnd;
		init();	//初始化
		return TRUE;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDM_EXIT:
			EndDialog(hWnd,0);
			return TRUE;

		case IDM_OPEN:
			_OpenFile();
			return TRUE;
		case IDM_1:
			MessageBox(NULL,szErrFormat,szErr,MB_ICONWARNING);
			return TRUE;
		case IDM_2:
			MessageBox(NULL, szErrFormat, szErr, MB_ICONWARNING);
			return TRUE;
		case IDM_3:
			MessageBox(NULL, szErrFormat, szErr, MB_ICONWARNING);
			return TRUE;
		}
	}
	return FALSE;
}


//异常回调函数
int  CALLBACK _Handler(EXCEPTION_POINTERS * lpExceptionPoint)
{
	const TCHAR szMsg[] = TEXT("异常发生位置：%08X，异常代码：%08X，标志：%08X");
	static TCHAR szBuffer[256];
	PCONTEXT pContext;
	PEXCEPTION_RECORD pException;

	pContext = lpExceptionPoint->ContextRecord;
	pException = lpExceptionPoint->ExceptionRecord;
#ifdef _WIN64
	DWORD64 exceptionAddress = pContext->Rip;
#else
	DWORD exceptionAddress = pContext->Eip;
#endif
	wsprintf(szBuffer, szMsg, (void*)exceptionAddress, pException->ExceptionCode, pException->ExceptionFlags);
	MessageBox(NULL, szBuffer, NULL, MB_OK);
	//mov [edi].regEip,offset _SafePlace	//修改EIP指令地址
	//pContext->Eip = _SafePlace;	//	C语言函数之间无法共享地址标号
	//goto _SafePlace;
	/*
EXCEPTION_EXECUTE_HANDLER equ 1 表示我已经处理了异常,可以优雅地结束了
EXCEPTION_CONTINUE_SEARCH equ 0 表示我不处理,其他人来吧,于是windows调用默认的处理程序显示一个错误框,并结束
EXCEPTION_CONTINUE_EXECUTION equ -1 表示错误已经被修复,请从异常发生处继续执行
	*/
	return EXCEPTION_EXECUTE_HANDLER;//结束程序
	//return EXCEPTION_CONTINUE_SEARCH;//异常不被识别，系统将继续到上一层的try-except域中继续查找一个恰当的__except模块
	//return EXCEPTION_CONTINUE_EXECUTION;//错误已经被修复,请从异常发生处继续执行
	/*注意：EXCEPTION_CONTINUE_EXECUTION将导致死循环，因为mov dword ptr[eax], 0的机器指令依然存在，并未被
	修改，恢复保护栈，并使用汇编指令修改EIP地址，才可以继续执行。*/
}
//执行比对PE文件
void _OpenFile()
{
	OPENFILENAME stOF;
	HANDLE hFile = NULL;
	HANDLE hMapFile = NULL;
	PBYTE lpMemory = NULL;	//PE文件内存映射文件地址
	int dwFileSize;
	const TCHAR szDefaultExt[] = TEXT("exe");
	const TCHAR szFilter[] = TEXT("PE Files (*.exe)\0*.exe\0")\
		TEXT("DLL Files(*.dll)\0*.dll\0")\
		TEXT("SCR Files(*.scr)\0*.scr\0")\
		TEXT("FON Files(*.fon)\0*.fon\0")\
		TEXT("DRV Files(*.drv)\0*.drv\0")\
		TEXT("All Files(*.*)\0*.*\0\0");
	const TCHAR szErr[] = TEXT("文件格式错误！");
	const TCHAR szErrFormat[] = TEXT("操作文件时出现错误！");
	IMAGE_DOS_HEADER *lpstDOS;	//DOS块地址
	IMAGE_NT_HEADERS *lpstNT;	//PE文件头地址

	//显示打开文件对话框
	RtlZeroMemory(&stOF, sizeof(stOF));
	stOF.lStructSize = sizeof(stOF);
	stOF.hwndOwner = hWinMain;
	stOF.lpstrFilter = szFilter;
	stOF.lpstrFile = szFileName;
	stOF.nMaxFile = MAX_PATH;
	stOF.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	stOF.lpstrDefExt = szDefaultExt;
	if (!GetOpenFileName(&stOF))
		return;
	//创建一个dump文件
	hFileDump = CreateFile(TEXT("E:\\Source\\PE_SourceCode\\PE_C\\chapter2\\PEInfo64\\PEInfo.txt"),
		GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE, 
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileDump == INVALID_HANDLE_VALUE)
		MessageBox(NULL, TEXT("打开文件失败！"), NULL, MB_ICONWARNING);

	//打开PE文件
	hFile = CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_WRITE,NULL,
		OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		MessageBox(NULL,TEXT("打开文件失败！"),NULL,MB_ICONWARNING);
	else
	{
		//获取文件大小
		dwFileSize = GetFileSize(hFile, NULL);
		//创建内存映射文件
		if (dwFileSize)
		{
			if (hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL))
			{
				//异常处理方法1：注册异常处理回调函数---运行exe程序进行异常处理，VS中运行不会进行异常处理
				SetUnhandledExceptionFilter(_Handler);
				//获得文件在内存的映象起始位置
				lpMemory = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
				//异常处理方法2：
				if (!lpMemory)
				{
					atexit(Exception);
					goto _ErrFormat;
					exit(EXIT_FAILURE);
				}

				//检查PE文件是否有效
				lpstDOS = (IMAGE_DOS_HEADER *)lpMemory;
				if (lpstDOS->e_magic != IMAGE_DOS_SIGNATURE)
				{
					//如果非PE文件-异常处理
					atexit(Exception);
					goto _ErrFormat;
					exit(EXIT_FAILURE);
				}
				lpstNT = (IMAGE_NT_HEADERS *)(lpMemory + lpstDOS->e_lfanew);
				if (lpstNT->Signature != IMAGE_NT_SIGNATURE)
				{
					//如果非PE文件-异常处理
					atexit(Exception);
					goto _ErrFormat;
					exit(EXIT_FAILURE);
				}
				//到此为止，该文件的验证已经完成。为PE结构文件
				//接下来分析分件映射到内存中的数据，并显示主要参数
				_getMainInfo(lpMemory, lpstNT, dwFileSize);
				//显示导入表
				_getImportInfo(lpMemory, lpstNT, dwFileSize);
				//显示导出表
				_getExportInfo(lpMemory, lpstNT, dwFileSize);
				//显示重定位信息
				_getRelocInfo(lpMemory, lpstNT, dwFileSize);
				//显示资源信息
				_getResourceInfo(lpMemory, lpstNT, dwFileSize);

				//错误检查
				//ShowErrMsg();
				goto _ErrorExit;
			_ErrFormat:
				MessageBox(hWinMain,szErrFormat,NULL,MB_OK);
			_ErrorExit:
				if(lpMemory)
					UnmapViewOfFile(lpMemory);
			}
			if(hMapFile)
				CloseHandle(hMapFile);
		}
		if (hFile)
			CloseHandle(hFile);
		if (hFileDump)
			CloseHandle(hFileDump);
	}
	_readToRichEdit();
	return;
}
/*获取RichEdit控件文本结尾的位置
void SetCaretToLast(HWND hWnd)
{
	CHARRANGE   cr;
	GETTEXTLENGTHEX gtl;//计算富编辑控件的文本长度的信息
	DWORD       dwPos = 0;

	memset(&cr, 0x0000, sizeof(cr));
	memset(&gtl, 0x0000, sizeof(gtl));

	// Get text max length
	gtl.codepage = 1200;//Unicode
	gtl.flags = GTL_PRECISE;//确定文本长度的方法的值-计算精确答案；GTL_DEFAULT	返回字符数
	dwPos = SendMessage(hWnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);

	// Set caret to the last
	cr.cpMax = dwPos;
	cr.cpMin = dwPos;
	SendMessage(hWnd, EM_EXSETSEL, 0, (LPARAM)&cr);
}
//获取文本控件中文本的字节数
int GetTxtLength(HWND hWnd)
{
	CHARRANGE   cr;
	memset(&cr, 0x0000, sizeof(cr));

	SetCaretToLast(hWnd);
	SendMessage(hWnd, EM_EXGETSEL, 0, (LPARAM)&cr);
	return cr.cpMax;
}*/
//RITCH控件添加文本信息--以 null 结尾的字符串
void _AppendInfo(const TCHAR * _lpsz)
{
	CHARRANGE stCR;
	//检索文本控件内文本的长度
	stCR.cpMin = GetWindowTextLength(hWinEdit);
	stCR.cpMax = stCR.cpMin;
	//择并替换文本控件的选定内容
	SendMessage(hWinEdit, EM_EXSETSEL, 0, (LPARAM)&stCR);
	//EM_REPLACESEL以 null 结尾的字符串的指针替换
	SendMessage(hWinEdit, EM_REPLACESEL, FALSE, (LPARAM)_lpsz);
}
void _Init()
{
	CHARFORMAT stCf;
	static TCHAR szClassEdit[] = TEXT("RichEdit20W");	//UNICODE版本
	//static TCHAR szClassEdit[] = TEXT("RichEdit20A");	//ASCII码版本
	static TCHAR szFont[] = TEXT("宋体");
	//设置编辑控件
	hWinEdit = GetDlgItem(hWinMain, IDC_INFO);
	SendMessage(hWinEdit, EM_SETTEXTMODE, TM_PLAINTEXT, 0);
	RtlZeroMemory(&stCf, sizeof(stCf));
	stCf.cbSize = sizeof(stCf);
	stCf.yHeight = 9 * 20;
	stCf.dwMask = CFM_FACE | CFM_SIZE | CFM_BOLD;
	StringCchCopy((LPTSTR)&stCf.szFaceName, lstrlen(szFont) + 1, (LPCTSTR)&szFont);
	SendMessage(hWinEdit, EM_SETCHARFORMAT, 0, (LPARAM)&stCf);
	SendMessage(hWinEdit, EM_EXLIMITTEXT, 0, -1);
}
//异常处理
void Exception(void)
{
	MessageBox(hWinMain, TEXT("获得文件在内存的映象起始位置失败!"), NULL, MB_OK);
}

//将PEInfo.txt文本信息读入RichEdit控件
void _readToRichEdit()
{
	const TCHAR szErrOpenFile[] = TEXT("无法打开源文件!");
	const TCHAR szFileName[] = TEXT("E:\\Source\\PE_SourceCode\\PE_C\\chapter2\\PEInfo64\\\\PEInfo.txt");
	HANDLE hFile;
	DWORD dwBytesRead;
	TCHAR lpServicesBuffer[1024];		//每行的缓冲区

	//打开文件
	hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(hWinMain, szErrOpenFile, NULL, MB_OK | MB_ICONEXCLAMATION);
		return;
	}
	//将PEInfo.txt的dump信息读入富文本控件
	DWORD dwFileSize = GetFileSize(hFileDump, NULL);
	int len = dwFileSize / 2 + 1;
	TCHAR* pContent = NULL;//保存从文件中读取的内容
	//申请分配默认堆--由操作系统维护，也可以使用CreateHeap申请私有堆
	pContent = (TCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * 2);

	/*检测是否UNICODE文件
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	WORD wdHead;
	ReadFile(hFile, &wdHead, 2, &dwBytesRead, NULL);
		if (wdHead != 0xfeff) //UNICODE文件头0xfeff
		{
			SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		}
	*/
	/*while (TRUE)	//没有考虑文本中可能存在的"00 00"
	{
		RtlZeroMemory(lpServicesBuffer, 1024);//每行的缓冲区
		//读取文本
		ReadFile(hFileDump, lpServicesBuffer, 1024, &dwBytesRead, NULL);
		_AppendInfo(lpServicesBuffer);
		if(!dwBytesRead)
			break;
	}*/
	/*
	//读取文本，//没有考虑文本中可能存在的"00 00"
	ReadFile(hFileDump, pContent, dwFileSize, &dwBytesRead, NULL);
	_AppendInfo(pContent);//追加以null结尾的字符串
	*/
	
	//读取文本
	ReadFile(hFileDump, pContent, dwFileSize, &dwBytesRead, NULL);
	int bytes = 0;
	TCHAR* ptrString = pContent;
	//添加到RichEdit控件
	while (len > 0)
	{
		_AppendInfo(ptrString);//追加以null结尾的字符串
		bytes = lstrlen(ptrString);
		ptrString += (bytes + 2);
		len -= (bytes + 2);
	}
		
	//释放内存---默认堆由系统维护，这里也可以不用自己释放
	BOOL bRes = HeapFree(GetProcessHeap(), 0, pContent);
	if (bRes != TRUE)
	{
		MessageBox(NULL, L"释放内存出错！", L"", MB_OK | MB_ICONEXCLAMATION);
	}
	CloseHandle(hFile);

}