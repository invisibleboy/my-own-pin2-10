/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <stdio.h>
#include <windows.h>
#include <iostream>
using namespace std;

volatile int doloop = 1;

__declspec(dllexport) int DoLoop()
{
    return doloop;
} 


DWORD WINAPI ThreadProc1(VOID * p)
{
    while(DoLoop())
    {
        HMODULE h1 = LoadLibraryW(L"version.dll");
        FARPROC a1 = GetProcAddress(h1, "GetFileVersionInfoW");
        Sleep(1);
        FreeLibrary(h1);
    }
    return 0;
}

DWORD WINAPI ThreadProc2(VOID * p)
{
    while(DoLoop())
    {
        static int i = 0;
        i++;
        i = i % 0x10;
        LPVOID aaa = VirtualAlloc(0, i * 0x1000000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Sleep(1);
        VirtualFree(aaa, 0, MEM_RELEASE);
    }
    return 0;
}

__declspec(dllexport) void ShortFunction1(DWORD h)
{
    volatile DWORD i = h;
    Sleep(1);
    if(i != 1)
    {
        exit(-1);
    }   
}

__declspec(dllexport) void ShortFunction2(DWORD h)
{
    volatile DWORD i = h;
    Sleep(1);
    if(i != 2)
    {
        exit(-1);
    }       
}

DWORD WINAPI ThreadProc3(VOID * p)
{
    while(DoLoop())
    {
        ShortFunction1(1);
    }
    return 0;   
}

DWORD WINAPI ThreadProc4(VOID * p)
{
    while(DoLoop())
    {
        ShortFunction2(2);
    }
    return 0;   
}


DWORD WINAPI ThreadProc5(VOID * p)
{
    DWORD recursionDepth = DWORD(p);
    if(recursionDepth == 3)
    {
        return 0;
    }

    DWORD childRecursionDepth = recursionDepth + 1;
    HANDLE threads[2];
    while(DoLoop())
    {
        threads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc5, (VOID *)childRecursionDepth, 0, NULL);
        threads[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc5, (VOID *)childRecursionDepth, 0, NULL);
        WaitForMultipleObjects(2, threads, TRUE, INFINITE);
        CloseHandle(threads[0]);
        CloseHandle(threads[1]);
    }
    return 0;   
}

//Wait for a process completion
//Verify it returned the expected exit code
bool WaitAndVerify(HANDLE process)
{
    if(WaitForSingleObject( process, INFINITE ) == WAIT_FAILED)
    {
        cerr << "WaitForSingleObject failed" << endl;
        return FALSE;
    }
    DWORD processExitCode;
    if(GetExitCodeProcess (process, &processExitCode) == FALSE)
    {
        cerr << "GetExitCodeProcess Failed" << endl;
        return FALSE;
    }
    if(processExitCode != 0)
    {
        cerr << "Got unexpected exit code" << endl;
        return FALSE;
    }
    return TRUE;
}

typedef WINADVAPI BOOL WINAPI OPEN_PROCESS_TOKEN_FUNC(HANDLE, DWORD, PHANDLE);

typedef WINADVAPI BOOL WINAPI CREATE_PROCESS_AS_USER_A_FUNC (HANDLE,LPCSTR, LPSTR,
        LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
        LPSTARTUPINFOA, LPPROCESS_INFORMATION);

DWORD WINAPI ThreadProc6(VOID * p)
{
    STARTUPINFO         si;
    PROCESS_INFORMATION  pi;

    while(DoLoop())
    {
        {
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(STARTUPINFO);
            memset(&pi, 0, sizeof(pi));
            string cmdLine = "cmd /c";

            HMODULE advapi32Handle = LoadLibraryW(L"advapi32.dll");
            if(advapi32Handle == NULL)
            {
                cerr << "w_app1 failed! (load library advapi32.dll)" << endl;
                exit(-1);
            }
            HANDLE tokenHandle;
            if(!((OPEN_PROCESS_TOKEN_FUNC *)GetProcAddress(advapi32Handle, "OpenProcessToken"))
                (GetCurrentProcess(), TOKEN_ALL_ACCESS, &tokenHandle))
            {
                cerr << "w_app1 failed! (open process token)" << endl;
                exit(-1);
            }
            if (!((CREATE_PROCESS_AS_USER_A_FUNC *)GetProcAddress(advapi32Handle, "CreateProcessAsUserA"))
                (tokenHandle, NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
            {
                cerr << "w_app1 failed! (create process as user)" << endl;
                exit(-1);
            }
            else
            {
                if(!WaitAndVerify(pi.hProcess))
                {
                    cerr << "w_app1 failed! (on WaitAndVerify())" << endl;
                    exit(-1);
                }
                CloseHandle(tokenHandle);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

            FreeLibrary(advapi32Handle);
        }

        {
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(STARTUPINFO);
            memset(&pi, 0, sizeof(pi));
            string cmdLine = "cmd /c";

            if(!CreateProcess(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
            {
                cerr << "w_app1 failed! (create process)" << endl;
                exit(-1);
            }
            else
            {
                if(!WaitAndVerify(pi.hProcess))
                {
                    cerr << "w_app1 failed! (on WaitAndVerify())" << endl;
                    exit(-1);
                }
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        Sleep(1);
    }
    return 0;
}

int main()
{   
    HANDLE threads[64];
    threads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc1, NULL, 0, NULL);
    threads[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc2, NULL, 0, NULL);
    threads[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc2, NULL, 0, NULL);
    threads[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc2, NULL, 0, NULL);    
    threads[4] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc2, NULL, 0, NULL);
    for(int i = 5; i < 30; i++)
    {
        threads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc3, NULL, 0, NULL);
    }
    for(int i = 30; i < 62; i++)
    {
        threads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc4, NULL, 0, NULL);
    }
    DWORD recursionDepth = 0;
    threads[62] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc5, (VOID *)recursionDepth, 0, NULL);
    threads[63] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc6, NULL, 0, NULL);

    DWORD ret = WaitForMultipleObjects(64, threads, TRUE, 420*1000);
    if(ret == WAIT_TIMEOUT)
    {
        cerr << "w_app1 failed!" << endl;
        doloop = 0;
        //let the threads the opportunity to terminate cleanly
        WaitForMultipleObjects(64, threads, TRUE, 10*1000);
        exit(-1);
    }
    return 0;
}