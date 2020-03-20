#include <stdio.h>
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif // for old compilers

const char ACCESS_FOR_ADMINS_SECURITY_DESCRIPTOR[] = SDDL_OWNER SDDL_DELIMINATOR 
SDDL_BUILTIN_ADMINISTRATORS SDDL_GROUP SDDL_DELIMINATOR SDDL_BUILTIN_ADMINISTRATORS
 
    SDDL_DACL SDDL_DELIMINATOR SDDL_PROTECTED
 
        SDDL_ACE_BEGIN
 
            SDDL_ACCESS_ALLOWED SDDL_SEPERATOR
            SDDL_CONTAINER_INHERIT SDDL_OBJECT_INHERIT SDDL_SEPERATOR
            SDDL_GENERIC_ALL SDDL_SEPERATOR
            SDDL_SEPERATOR
            SDDL_SEPERATOR
            SDDL_BUILTIN_ADMINISTRATORS
 
        SDDL_ACE_END;

BOOL isVistaPlus(void)
{
OSVERSIONINFOW osv;
osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
GetVersionExW(&osv);
wprintf(L"Windows is %d.%d\n",osv.dwMajorVersion,osv.dwMinorVersion);

if (osv.dwMajorVersion >= 6) //return (osv.dwMajorVersion >= 6)
	return TRUE;
else 
	return FALSE;
}

BOOL EnableWindowsPrivilege(WCHAR* Privilege)
{
LUID luid = {0};
TOKEN_PRIVILEGES tp;
HANDLE currentToken,currentProcess = GetCurrentProcess();

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) 
		{
		wprintf(L"LookupPrivilegeValue failed %d\n",GetLastError());
		return FALSE;
		}
	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) 		
		{
		wprintf(L"OpenProcessToken for priv8 failed %d\n",GetLastError());
		return FALSE;
		}
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) 
		{
		wprintf(L"AdjustTokenPrivileges failed %d\n",GetLastError());		
		return FALSE;
		}
	return TRUE;
}


int GetSystemPid(void)
{
int dwPid = 0; //0
HANDLE hSnapshot = NULL;
PROCESSENTRY32W p_e;
p_e.dwSize = sizeof(PROCESSENTRY32W);

hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
		{
		wprintf(L"Error CreateToolhelp32Snapshot %d\n",GetLastError());
        goto E;
 		}

    if (!Process32FirstW(hSnapshot, &p_e))
		{
		wprintf(L"Error Process32FirstW %d\n",GetLastError());
        CloseHandle(hSnapshot);
        goto E;
	    }

    do
	{
		/* QUERY_INF не будет работать, нужно сессия та же + отсутствие протекшн
			{
			dwPid = p_e.th32ProcessID;
            break;
			} */

        if(lstrcmpiW(p_e.szExeFile,L"winlogon.exe") == 0) //add wininit,smss and other
			{
			dwPid = p_e.th32ProcessID;
            break;
			}
    } while(Process32NextW(hSnapshot, &p_e));

CloseHandle(hSnapshot);

E:
	return dwPid;
}

BOOL RunAsSystemNt5(void) 
{

    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetSystemPid());
    if (NULL == hProcess) {
        printf("OpenProcess failed, error code: 0x%0.8lX", GetLastError());
        goto Cleanup;
    }
   
    if (!OpenProcessToken(hProcess, WRITE_DAC, &hToken)) {
        printf("OpenProcessToken failed, error code: 0x%0.8lX", GetLastError());
        goto Cleanup;
    }
   
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
        ACCESS_FOR_ADMINS_SECURITY_DESCRIPTOR, SDDL_REVISION_1, &pSD, NULL))
    {
        printf("ConvertStringSecurityDescriptorToSecurityDescriptor failed, "
            "error code: 0x%0.8lX", GetLastError());
        goto Cleanup;
    }
 
    if (!SetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pSD)) {
        printf("SetKernelObjectSecurity failed, error code: 0x%0.8lX", GetLastError());
        goto Cleanup;
    }
 
    CloseHandle(hToken);
    hToken = NULL;
 
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        printf("OpenProcessToken failed, error code: 0x%0.8lX", GetLastError());
        goto Cleanup;
    }
   
    if (!DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary,
        &hNewToken))
    {
        printf("DuplicateTokenEx failed, error code: 0x%0.8lX", GetLastError());
        goto Cleanup;
    }
 
	if (!ImpersonateLoggedOnUser(hNewToken))
		{
		wprintf(L"err impersonated %d\n",GetLastError());
		return FALSE;
		}

	STARTUPINFOW si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(STARTUPINFO);

	//EnableWindowsPrivilege(L"SeIncreaseQuotaPrivilege"); //dont need with impersonation?
	//EnableWindowsPrivilege(L"SeAssignPrimaryTokenPrivilege"); 

	BOOL bRet = CreateProcessAsUserW(hNewToken,L"C:\\Windows\\system32\\cmd.exe",NULL,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);
	if (!bRet) 
		{
		printf ("ERROR CreateProcessAsUserW %d\n",GetLastError());
		return FALSE;
		}



Cleanup:
 
    if (NULL != pSD) LocalFree((HLOCAL)pSD);  
    if (NULL != hNewToken) CloseHandle(hToken);  
    if (NULL != hToken) CloseHandle(hNewToken);
    if (NULL != hProcess) CloseHandle(hProcess);
 
    return TRUE;
}

 
BOOL RunAsSystemNt6(void)
{
HANDLE hProcess,TokenHandle,phNewToken;
DWORD dwProcessId;
HWND hShellwnd;
BOOL bRet = FALSE;
SECURITY_ATTRIBUTES TokenAttributes =
	{
  	.lpSecurityDescriptor = NULL,
 	.bInheritHandle = FALSE,
	.nLength = sizeof(SECURITY_ATTRIBUTES)
	}; //if don't have c99 compiler, change this definition

dwProcessId = GetSystemPid();
if (dwProcessId == 0)
	{ wprintf(L"Error , can't get valid system pid\n"); return FALSE; }
else
	{ wprintf(L"pid received %d..\n",dwProcessId); }

DWORD dAccess = PROCESS_QUERY_LIMITED_INFORMATION; //in win10 use this instead PROCESS_QUERY_INFORMATION;

hProcess = OpenProcess(dAccess, FALSE, dwProcessId);
	if (hProcess == NULL) //проверку на getlasteror access denied
		{ wprintf(L"Error , can't open process %d\n",GetLastError()); return FALSE; }
	else
		{ wprintf(L"process opened..\n"); }

dAccess = MAXIMUM_ALLOWED;
bRet = OpenProcessToken(hProcess, dAccess, &TokenHandle);
	if (bRet == FALSE)
		{wprintf(L"Error , can't open process token %d\n",GetLastError()); return FALSE; }
	else
		{ wprintf(L"token getted..\n"); }

dAccess = TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
bRet = DuplicateTokenEx(TokenHandle,dAccess,&TokenAttributes,SecurityImpersonation,TokenPrimary,&phNewToken);
	if (bRet == FALSE)
			{ wprintf(L"Error , can't duplicate token %d\n",GetLastError()); return FALSE; }
	else
			{ wprintf(L"token duplicated..\n"); }


PROCESS_INFORMATION pi = {0};
STARTUPINFOW si = {0};
si.cb = sizeof(STARTUPINFOW);

bRet =  CreateProcessWithTokenW(phNewToken, LOGON_NETCREDENTIALS_ONLY, L"cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (bRet == FALSE)
			{ wprintf(L"Error , can't create process %d\n",GetLastError()); return FALSE; }
	else
			{ wprintf(L"process created..\n"); }
return TRUE;
}


int wmain(int argc,WCHAR* argv[])
{
wprintf(L"Elevate to system\n");
//check IL < high  - error or runas

EnableWindowsPrivilege(L"SeDebugPrivilege");

if (isVistaPlus())
		RunAsSystemNt6();
else
		RunAsSystemNt5();
	return 0;
}
