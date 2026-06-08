#pragma once
#ifndef INFO_H_
#define INFO_H_

#include <windows.h>
#include <richedit.h>	//CHARFORMAT富文本结构定义
#include <commctrl.h>	//通用控件
#pragma comment(lib,"comctl32.lib")
#include <strsafe.h>	//StringCchCopy
#include <stdlib.h>

//函数声明
BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void Exception(void);
void init(); //初始化
void  _OpenFile();//打开PE文件并处理
DWORD RVAToOffset(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);// 将内存偏移量RVA转换为文件偏移
DWORD GetRVASection(IMAGE_DOS_HEADER * lpFileHead, DWORD dwRVA);//查找 RVA 所在的节区
int  CALLBACK _Handler(EXCEPTION_POINTERS * lpExceptionPoint);
void ShowErrMsg();
void _AppendInfo(const TCHAR * _lpsz);//往文本框中追加文本
//PE文件处理模块
void _getMainInfo(PBYTE, IMAGE_NT_HEADERS *, int);//从内存中获取PE文件的主要信息
void _getImportInfo(PBYTE, IMAGE_NT_HEADERS *, int);//获取PE文件的导入表
void _getExportInfo(PBYTE, IMAGE_NT_HEADERS *, int);//获取PE文件的导出表
void _getRelocInfo(PBYTE, IMAGE_NT_HEADERS *, int);//获取PE文件的重定位信息
void _getResourceInfo(PBYTE, IMAGE_NT_HEADERS *, int);//获取PE文件的资源信息
//将PEInfo.txt文本信息读入RichEdit控件
void _readToRichEdit();

#endif
