---
title: "Named Pipe & Anonymous Pipe"
published: 2026-04-30
description: "Windows의 Named Pipe와 Anonymous Pipe 동작 과정 설명"
image: ""
tags: ["Windows", "Pipe", "Named Pipe", "Anonymous Pipe"]
category: "Windows"
draft: false
---

# 1. What is Pipe?

Windows에서는 프로세스 간의 통신을 위해 IPC(Inter-Process Communication)라는 것을 사용한다.  
IPC는 간단히 말해 프로세스끼리 어떻게 통신을 할지 정해 놓은 규약이라고 생각하면 된다.  

그렇다면 Pipe는 뭘까?  
이 IPC에는 Shared Memory나 Socket, Mailslot 등 여러 방법들이 존재하는데, 그 중 하나가 Pipe이다.  
그런데 Pipe도 종류가 2개로 나뉜다.  
바로 Named Pipe랑 Anonymous Pipe다.  

Named Pipe랑 Anonymous Pipe 둘 다 직역하면 이름 있는 Pipe랑 이름 없는 Pipe인데, 이름이 대체 뭘까?  
여기서 말하는 이름은 간단하게 말해서 Pipe의 주소를 뜻한다.  
즉, Named Pipe는 Pipe의 주소가 존재하기 때문에 다른 프로세스끼리 Pipe 주소를 통해 IPC가 가능하고, Anonymous Pipe는 불가능하다.  
Anonymous Pipe가 IPC로 프로세스끼리 통신하기 위한 방법인데, IPC가 불가능하면 대체 얘는 왜 존재하는 걸까?  

## 1-1. Anonymous Pipe creation

먼저 Anonymous Pipe는 단방향 특성을 가지고 있고, 부모→자식 프로세스의 통신에서 사용한다.  
Anonymous Pipe는 이름이 없어서 다른 프로세스끼리 서로 통신할 수 있는 접점이 없지만, 부모→자식 관계에선 상속이 존재하기 때문에 IPC가 가능하다.  
물론 아예 다른 프로세스와 통신을 할 수 없는 건 아니고, DuplicateHandle 함수를 활용하여 통신이 가능하긴 하다.  
하지만 그렇게 하려면 다른 수단을 거쳐서 핸들 값을 넘겨줘야 하기에 실용적인 측면에서 부모→자식 프로세스의 통신용이라 하는 것이다.  
이에 대해 좀 자세히 알아보자.  

```cpp
BOOL CreatePipe(
  [out]          PHANDLE               hReadPipe,
  [out]          PHANDLE               hWritePipe,
  [in, optional] LPSECURITY_ATTRIBUTES lpPipeAttributes,
  [in]           DWORD                 nSize
);
```

Anonymous Pipe는 CreatePipe 함수를 사용하여 Pipe를 생성한다.  
이때, 첫 번째와 두 번째 인자가 각각 hRead와 hWrite 핸들이고, 이곳에 각 핸들이 저장된다.  

```cpp
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
```

lpPipeAttributes 변수의 자료형인 _SECURITY_ATTRIBUTES 구조체를 보면 bInheritHandle 변수가 존재하는 것을 볼 수 있다.  
bInheritHandle이 True일 경우, 해당 Pipe는 상속이 가능해진다.  
근데 이것만 가지고 바로 상속되는 건 아니다.  

```cpp
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

CreatePipe 함수를 호출 후, CreateProcessA 함수를 통해 자식 프로세스를 생성하게 되는데, CreateProcessA 함수의 bInheritHandles도 True로 설정해야 비로소 자식 프로세스가 상속될 수 있게 된다.  
이 이후로는 CreateProcessA 함수로 자식 프로세스를 생성할 때마다 자식 프로세스의 handle table에 부모 프로세스의 handle table과 같은 index에 Pipe가 반환한 같은 핸들(hRead와 hWrite) 값이 설정되며, 이를 통해 부모 프로세스와 자식 프로세스가 통신할 수 있게 된다.  

## 1-2. Named Pipe creation

이제 Anonymous Pipe가 어떻게 생성되는지 알게 되었으니, Named Pipe도 어떻게 생성되는지 알아보자.  
우선 Named Pipe는 단방향과 양방향 두 특성 모두 가지며, 부모→자식이 아닌 서로 접점이 없는 프로세스끼리 통신할 때 사용한다.  
Named Pipe에는 서버와 클라이언트로 구분하는데, Pipe를 생성하는 쪽이 서버이고, 생성된 Pipe를 사용하는 쪽이 클라이언트이다.  

```cpp
HANDLE CreateNamedPipeA(
  [in]           LPCSTR                lpName,
  [in]           DWORD                 dwOpenMode,
  [in]           DWORD                 dwPipeMode,
  [in]           DWORD                 nMaxInstances,
  [in]           DWORD                 nOutBufferSize,
  [in]           DWORD                 nInBufferSize,
  [in]           DWORD                 nDefaultTimeOut,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
```

Anonymous Pipe는 CreatePipe 함수로 Pipe를 생성했다면, Named Pipe는 CreateNamedPipeA 함수로 생성한다.  
CreateNamedPipeA 함수의 lpName에는 실제 Pipe의 이름이 들어가며, \\.\pipe\pipename 양식을 맞춰야 한다.  
클라이언트가 Pipe에 연결하기 위해선 해당 Pipe의 이름(lpName)을 알아야 한다.  
이는 뒤에서 왜 필요한지 알게 될 것이다.  

추가로 nMaxInstance가 중요한데, nMaxInstances에 설정되는 값만큼 Pipe가 한 번에 클라이언트들과 연결할 수 있다.  
자 이게 무슨 말이냐 하면, 원래 하나의 Pipe는 하나의 클라이언트에만 연결이 된다.  
하지만 nMaxInstances만큼 같은 이름의 Pipe가 생성되며, 각 Pipe마다 하나의 클라이언트와 연결이 되기 때문에 한 번에 nMaxInstances의 값만큼 연결할 수 있는 것이다.  
예를 들어, nMaxInstances 값이 10이라면, 10개의 Pipe가 존재하며 한 번에 10개의 클라이언트랑 연결할 수 있는 것이다.  
만약 13개나 14개 같은 10개 이상의 클라이언트가 연결하려 한다면, 10개의 클라이언트가 연결하고 남은 클라이언트는 연결이 끝날 때까지 대기 상태에 들어간다.  
그럼 클라이언트는 Pipe에 어떻게 연결할까?  

```cpp
BOOL ConnectNamedPipe(
  [in]                HANDLE       hNamedPipe,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

우선 클라이언트에서 Pipe에 연결하기 위해선 서버에서 Pipe를 생성한 후, ConnectNamedPipe 함수를 실행 시켜야 한다.  
ConnectNamedPipe 함수가 실행되면, Pipe는 클라이언트의 연결을 기다리는 대기 상태가 되고, 클라이언트는 Pipe에 연결할 수 있게 된다.  
근데 클라이언트가 Pipe랑 연결하기 위해선, 해당 Pipe의 핸들이 필요하다.  

```cpp
HANDLE CreateFileA(                                                                 BOOL CallNamedPipeA(
  [in]           LPCSTR                lpFileName,                                      [in]  LPCSTR  lpNamedPipeName,
  [in]           DWORD                 dwDesiredAccess,                                 [in]  LPVOID  lpInBuffer,
  [in]           DWORD                 dwShareMode,                                     [in]  DWORD   nInBufferSize,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,                            [out] LPVOID  lpOutBuffer,
  [in]           DWORD                 dwCreationDisposition,                           [in]  DWORD   nOutBufferSize,
  [in]           DWORD                 dwFlagsAndAttributes,                            [out] LPDWORD lpBytesRead,
  [in, optional] HANDLE                hTemplateFile                                    [in]  DWORD   nTimeOut
);                                                                                  );
```

핸들을 얻는 방법에는 CreateFileA 함수와 CallNamedPipeA 함수가 존재하는데, CallNamedPipeA 함수는 Pipe에 대해 핸들 획득 → 쓰기/읽기 수행 → 닫기까지 한 번에 진행하는 일회용 스타일이므로 CallNamedPipeA 함수는 넘어가고 CreateFileA 함수를 기준으로 설명하도록 하겠다.  
CreateFileA 함수를 보면 lpFileName이 있는데, 이곳에 연결하고 싶은 Pipe의 이름을 넣는다.  
그러면 CreateFileA 함수가 해당 Pipe에 연결이 가능하다면 핸들 획득과 함께 Pipe와 연결해주고, 서버에서 실행되어 계속 대기 상태였던 CallNamedPipe 함수는 return이 되며 클라이언트와 해당 PIpe가 연결되었음을 알려준다.  

이러한 과정을 통해 서버와 연결된 클라이언트는 클라이언트 측에서 CloseHandle로 연결을 끊거나, 서버측에서 DisconnectNamedPipe 함수로 클라이언트의 연결을 끊지 않는 이상 계속해서 통신할 수 있게 된다.  
참고로 서버에서 DisconnectNamedPipe 함수를 실행 시켰다고 해서 서버의 핸들이 닫히는 것은 아니고, 클라이언트의 연결만 끊기는 것이다.  

# 2. How to communicate with Pipe?

## 2-1. Anonymous Pipe communication

Anonymous Pipe는 부모와 자식끼리 통신을 한다고 했다.  
그럼 이제 실제 부모와 자식 프로세스의 예제 코드를 보며 동작을 이해해 보자.  

```cpp
#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>

#define BUFSIZE 4096 
 
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

HANDLE g_hInputFile = NULL;
 
void CreateChildProcess(void); 
void WriteToPipe(void); 
void ReadFromPipe(void); 
void ErrorExit(PCTSTR); 
 
int _tmain(int argc, TCHAR *argv[]) 
{ 
   SECURITY_ATTRIBUTES saAttr; 

	 printf("\n->Start of parent execution.\n");

   saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
   saAttr.bInheritHandle = TRUE; 
   saAttr.lpSecurityDescriptor = NULL; 

   if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0) ) 
      ErrorExit(TEXT("StdoutRd CreatePipe")); 

   if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
      ErrorExit(TEXT("Stdout SetHandleInformation")); 

   if (! CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) 
      ErrorExit(TEXT("Stdin CreatePipe")); 

   if ( ! SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0) )
      ErrorExit(TEXT("Stdin SetHandleInformation")); 
 
   CreateChildProcess();

// ... (get a handle to an input file for the parent)

   WriteToPipe(); 
   printf( "\n->Contents of %S written to child STDIN pipe.\n", argv[1]);

   printf( "\n->Contents of child process STDOUT:\n\n");
   ReadFromPipe(); 

   printf("\n->End of parent execution.\n");

   return 0; 
} 
 
// ... (function definitions omitted)
```

위는 부모 프로세스의 예제 코드다.  
_tmain 함수의 코드를 보면 먼저 CreatePipe의 lpPipeAttributes 매개변수에 넣어줄 saAttr 인자를 설정해준다.  

```cpp
saAttr.bInheritHandle = TRUE;
```

saAttr의 값들을 설정하는 코드 중간에 위처럼 bInheritHandle을 TRUE로 설정하며 자식 프로세스가 핸들을 상속 받을 수 있도록 한다.  
그 후, CreatePipe 함수를 통해 입출력의 Read와 Write 핸들을 생성해준다.  
근데 그렇게 되면 stdin과 stdout에 ㅐ한 read/write 핸들이 만들어지므로 총 4개의 핸들이 생성된다.  

자식 프로세스에서 필요한 것은 stdin에 대한 read 핸들과 stdout에 대한 write 핸들이므로 CreatePipe 함수 호출 후, SetHandleInformation 함수를 통해 stdin의 write 핸들과 stdout의 read 핸들을 자식 프로세스가 상속 받을 수 없도록 만든다.  
그리고 해당 stdin의 write 핸들과 stdout의 read 핸들은 부모 프로세스가 사용한다.  

||Parent Process|Child Process|
|---|---|---|
|stdin|g_hChildStd_IN_Wr|g_hChildStd_IN_Rd|
|stdout|g_hChildStd_OUT_Rd|g_hChildStd_OUT_Wr|

즉, 위처럼 각 프로세스가 handle을 갖게 된다.  
그 후, CreateChildProcess 함수를 호출하여 자식 프로세스를 생성한 후, WriteToPipe랑 ReadFromPipe 함수를 통해 반복 루프를 돌며 통신하게 된다.  

```cpp
#include <windows.h>
#include <stdio.h>

#define BUFSIZE 4096 
 
int main(void) 
{ 
   CHAR chBuf[BUFSIZE]; 
   DWORD dwRead, dwWritten; 
   HANDLE hStdin, hStdout; 
   BOOL bSuccess; 
 
   hStdout = GetStdHandle(STD_OUTPUT_HANDLE); 
   hStdin = GetStdHandle(STD_INPUT_HANDLE); 
   if ( 
       (hStdout == INVALID_HANDLE_VALUE) || 
       (hStdin == INVALID_HANDLE_VALUE) 
      ) 
      ExitProcess(1); 

   printf("\n ** This is a message from the child process. ** \n");

   for (;;) 
   { 
      bSuccess = ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL); 
      
      if (! bSuccess || dwRead == 0) 
         break; 

      bSuccess = WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL); 
      
      if (! bSuccess) 
         break; 
   } 
   return 0;
}
```

그럼 이제 자식 프로세스의 에제 코드를 보겠다.  
main 함수가 시작되면 가장 먼저 stdout의 write 핸들과 stdin의 read 핸들을 가져온다.  
그 후, 반복 루프를 돌며 부모 프로세스가 쓰는 내용을 자식 프로세스가 ReadFile 함수로 읽는다.  
한 번에 쓰거나 읽을 수 있는 크기는 BUFSIZE로 정해지며, 부모 프로세스가 BUFSIZE 값보다 큰 크기의 값을 자식 프로세스에게 통신하려고 한다면, BUFSIZE 단위로 나눠져서 보내지게 된다.  
위의 에제 코드에서는 반복 루프에서 WriteFile 함수도 호출하는데, 그냥 ReadFile처럼 자식 프로세스면 부모 프로세스에게, 부모 프로세스면 자식 프로세스에게 데이터를 써주는 작업을 진행한다.  

부모 프로세스와 자식 프로세스의 통신 과정은 알아봤으니, 어떻게 통신이 끊기게 되는지 알아보겠다.  
먼저 흐름을 간단하게 보면, 부모 프로세스에서 자식에게 보낼 데이터를 모두 쓴 후, 부모 프로세스의 쓰기 핸들을 닫는다. 그러면 자식 프로세스에선 부모 프로세스가 쓴 내용을 다 읽고, 부모 프로세스가 다 쓰고 핸들을 닫았다는 힌호를 받아서 자기 자신의 프로세스를 종료한다. 이렇게 되면 부모 프로세스와 자식 프로세스의 Pipe는 끊기게 되고, 부모 프로세스에선 이를 인지하여 남아있는 모든 핸들(read 핸들)을 닫아서 통신을 종료하게 된다.  

```cpp
void WriteToPipe(void) 
{ 
   DWORD dwRead, dwWritten; 
   CHAR chBuf[BUFSIZE];
   BOOL bSuccess = FALSE;
 
   for (;;) 
   { 
      bSuccess = ReadFile(g_hInputFile, chBuf, BUFSIZE, &dwRead, NULL);
      if ( ! bSuccess || dwRead == 0 ) break; 
      
      bSuccess = WriteFile(g_hChildStd_IN_Wr, chBuf, dwRead, &dwWritten, NULL);
      if ( ! bSuccess ) break; 
   } 
 
   if ( ! CloseHandle(g_hChildStd_IN_Wr) ) 
      ErrorExit(TEXT("StdInWr CloseHandle")); 
} 
```

부모 프로세스의 WriteToPipe 함수를 보면 반복 루프 안에서 입력 파일의 내용을 읽고, 이를 WriteFile 함수를 통해 stdin write로 자식 프로세스에게 데이터를 쓴다.  

```cpp
BOOL ReadFile(
  [in]                HANDLE       hFile,
  [out]               LPVOID       lpBuffer,
  [in]                DWORD        nNumberOfBytesToRead,
  [out, optional]     LPDWORD      lpNumberOfBytesRead,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

ReadFile을 보면 네 번째 매개변수로 lpNumberOfBytesRead가 존재하는데, 이 변수가 읽은 byte의 수를 저장하는 역할을 한다.  
위의 WriteToPipe 함수의 ReadFile에선 dwRead가 읽은 byte의 수를 저장하는 역할인데, 입력 파일에서 내용을 다 읽었을 때, 즉 EOF면 반복 루프가 종료되며 부모 프로세스의 stdin write 핸들이 닫히게 된다.  

||Parent Process|Child Process|
|---|---|---|
|stdin||g_hChildStd_IN_Rd|
|stdout|g_hChildStd_OUT_Rd|g_hChildStd_OUT_Wr|

그러면 이제 각 프로세스는 위처럼 핸들을 갖고 있는 상태다.  
부모 프로세스가 현재 write를 한 상태이니 자섹 프로세스로 이동해 보자.  

```cpp
for (;;) 
   { 
      bSuccess = ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL); 
      
      if (! bSuccess || dwRead == 0) 
         break; 

      bSuccess = WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL); 
      
      if (! bSuccess) 
         break; 
   } 
   return 0;
```

위는 자식 프로세스에서 통신하는 부분인데, 반복 루프 안에서 부모 프로세스가 쓴 데이터를 읽고, 이를 다시 써주는 간단한 작업을 진행한다.  
아까 부모 프로세스가 더 쓸 내용이 없어서 stdin write 핸들이 닫혔으므로, 자식 프로세스가 계속해서 ReadFile 함수로 부모 프로세스가 쓴 데이터를 읽고 있다 보면 언젠가 다 읽는 상태가 될 것이다.  
그럼 그때 자식 프로세스도 dwRead 값이 0으로 되며 반복 루프가 끝나고, return을 호출하며 자식 프로세스가 종료된다.  
하지만 현재는 자식 프로세스가 종료만 된 것이지 stdin read 핸들과 stdout write 핸들이 닫힌 것은 아니다.  

그럼 stdin read 핸들과 stdout write 핸들은 어떻게 닫히는 것일까?  
프로세스는 종료 되면 운영체제가 해당 프로세스가 갖고 있던 커널 객체 핸들을 자동으로 닫는다.  
이 과정에서 자식 프로세스가 갖고 있던 stdin read 핸들과 stdout write 핸들이 닫히게 되는 것이다.  

||Parent Process|Child Process|
|---|---|---|
|stdin|||
|stdout|g_hChildStd_OUT_Rd||

그럼 현재는 위와 같이 각 프로세스가 핸들을 갖고 있게 된다.  
자식 프로세스는 부모 프로세스한테서 데이터를 받고, 이를 다시 부모 프로세스에게 써줬다.  
즉, 부모 프로세스는 아직 ReadFromPipe 함수를 통해 자식 프로세스가 쓴 데이터를 읽고 있는 상태다.  

```cpp
void ReadFromPipe(void) 
{ 
   DWORD dwRead, dwWritten; 
   CHAR chBuf[BUFSIZE]; 
   BOOL bSuccess = FALSE;
   HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

   for (;;) 
   { 
      bSuccess = ReadFile( g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
      if( ! bSuccess || dwRead == 0 ) break; 

      bSuccess = WriteFile(hParentStdOut, chBuf, 
                           dwRead, &dwWritten, NULL);
      if (! bSuccess ) break; 
   } 
} 
```

ReadFromPipe 함수를 보면 위에 나왔던 코드들처럼 ReadFile 함수를 통해 자식 프로세스가 쓴 데이터를 읽고 있다.  
하지만 자식 프로세스가 쓴 데이터도 언젠가 다 읽게 될 것이고, dwRead에는 0이 들어오면서 반복 루프가 종료된다.  
그러면 부모 프로세스도 return을 호출하게 되고, 자식 프로세스처럼 운영체제가 마지막 남은 stdout read 핸들을 닫게 되며 모든 핸들이 닫히고 통신은 끝나게 된다.  

## 2-2. Named Pipe communication

Anonymous Pipe에 대해 알아봤으니, 이제 서버와 클라이언트 간의 통신에 대해 알아보자.  

```cpp
#include <windows.h> 
#include <stdio.h> 
#include <tchar.h>
#include <strsafe.h>

#define BUFSIZE 512
 
DWORD WINAPI InstanceThread(LPVOID); 
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD); 
 
int _tmain(VOID) 
{ 
   BOOL   fConnected = FALSE; 
   DWORD  dwThreadId = 0; 
   HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL; 
   LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe"); 

   for (;;) 
   { 
      _tprintf( TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
      hPipe = CreateNamedPipe( 
          lpszPipename,             // pipe name 
          PIPE_ACCESS_DUPLEX,       // read/write access 
          PIPE_TYPE_MESSAGE |       // message type pipe 
          PIPE_READMODE_MESSAGE |   // message-read mode 
          PIPE_WAIT,                // blocking mode 
          PIPE_UNLIMITED_INSTANCES, // max. instances  
          BUFSIZE,                  // output buffer size 
          BUFSIZE,                  // input buffer size 
          0,                        // client time-out 
          NULL);                    // default security attribute 

      if (hPipe == INVALID_HANDLE_VALUE) 
      {
          _tprintf(TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError()); 
          return -1;
      }

      fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
 
      if (fConnected) 
      { 
         printf("Client connected, creating a processing thread.\n"); 

         hThread = CreateThread( 
            NULL,              // no security attribute 
            0,                 // default stack size 
            InstanceThread,    // thread proc
            (LPVOID) hPipe,    // thread parameter 
            0,                 // not suspended 
            &dwThreadId);      // returns thread ID 

         if (hThread == NULL) 
         {
            _tprintf(TEXT("CreateThread failed, GLE=%d.\n"), GetLastError()); 
            return -1;
         }
         else CloseHandle(hThread); 
       } 
      else 
         CloseHandle(hPipe); 
   } 

   return 0; 
} 
```

먼저 서버의 에제 코드부터 보겠다.  
코드를 보면 변수 선언 및 초기화 후, 바로 반복 루프를 시작한다.  

```cpp
HANDLE CreateNamedPipeA(
  [in]           LPCSTR                lpName,
  [in]           DWORD                 dwOpenMode,
  [in]           DWORD                 dwPipeMode,
  [in]           DWORD                 nMaxInstances,
  [in]           DWORD                 nOutBufferSize,
  [in]           DWORD                 nInBufferSize,
  [in]           DWORD                 nDefaultTimeOut,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
```

반복 루프 안에선 CreateNamedPipe 함수를 통해 Pipe를 생성하는데, 해당 Pipe의 이름은 첫 번째 인자로 결정된다.  
즉, 현재 에제 코드 기준으로는 \\.\pipe\mynamedpipe가 생성되는 Pipe의 이름이다.  

```cpp
BOOL ConnectNamedPipe(
  [in]                HANDLE       hNamedPipe,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

Pipe를 생성한 후에는 ConnectNamedPipe 함수를 통해 클라이언트가 서버에 연결되는 것을 기다리게 된다.  

```cpp
fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
```

여기서 연결이 성공하는 조건을 잘 봐야 하는데, 성공 조건은 두 개가 있다.  
TRUE 값으로 설정이 되거나, GetLastError 함수의 값이 ERROR_PIPE_CONNECTED이면 연결이 성공했다는 뜻이다.  
ConnectNamedPipe 함수는 서버와 클라이언트가 연결을 실패하면 0, 성공하면 0이 아닌 값을 반환하므로 제대로 연결만 되면 TRUE 값으로 설정된다.  
그렇다면 ConnectNamedPipe 함수가 0을 반환했을 때, 즉 GetLastError()로 분기 되는 경우는 모두 연결 실패로 봐야 할까?  
CreateNamedPipe로 Pipe를 만든 후, ConnectNamedPipe를 호출하기까지는 분명 짧은 시간이지만 중간에 공백이 존재할 것이다.  
만약 이때 클라이언트가 서버에 연결하게 되면, ConnectNamedPipe를 호출했을 때는 이미 연결이 되어 있는 상태라 0을 반환하게 된다.  
그러면 GetLastError() 분기로 가게 되며, GetLastError()의 값으로는 ERROR_PIPE_CONNECTED가 뜨게 되어 이 경우에도 연결에 성공했다는 의미가 된다.  

```cpp
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

서버와 클라이언트가 연결에 성공하면 CreateThread 함수에게 Pipe 핸들을 넘겨주며 클라이언트랑 통신할 인스턴트 스레드를 생성해 주고, 메인 스레드는 계속해서 다른 클라이언트의 연결을 기다린다.  
CreateThread의 매개변수를 보면 lpStartAddress와 lpParameter가 있는데, 이는 각각 스레드가 실행할 함수의 포인터와 함수에 넘겨줄 인자를 나타낸다.  
예제 코드를 기준으로 보면 인스턴트 스레드가 실행할 함수는 InstanceThread 함수인 것이고, 해당 함수의 인자로는 hPipe, 즉 Pipe 핸들이 들어가는 것이다.  

```cpp
DWORD WINAPI InstanceThread(LPVOID lpvParam)
{ 
   HANDLE hHeap      = GetProcessHeap();
   TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(TCHAR));
   TCHAR* pchReply   = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(TCHAR));

   DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0; 
   BOOL fSuccess = FALSE;
   HANDLE hPipe  = NULL;

   // ... (null checks for lpvParam, pchRequest, and pchReply with cleanup and early return on failure)

   hPipe = (HANDLE) lpvParam; 

   while (1) 
   { 
      fSuccess = ReadFile( 
         hPipe,        // handle to pipe 
         pchRequest,    // buffer to receive data 
         BUFSIZE*sizeof(TCHAR), // size of buffer 
         &cbBytesRead, // number of bytes read 
         NULL);        // not overlapped I/O 

      if (!fSuccess || cbBytesRead == 0)
      {   
          if (GetLastError() == ERROR_BROKEN_PIPE)
          {
              _tprintf(TEXT("InstanceThread: client disconnected.\n")); 
          }
          else
          {
              _tprintf(TEXT("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError()); 
          }
          break;
      }

      GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes); 

      fSuccess = WriteFile( 
         hPipe,        // handle to pipe 
         pchReply,     // buffer to write from 
         cbReplyBytes, // number of bytes to write 
         &cbWritten,   // number of bytes written 
         NULL);        // not overlapped I/O 

      if (!fSuccess || cbReplyBytes != cbWritten)
      {   
          _tprintf(TEXT("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError()); 
          break;
      }
  }

   FlushFileBuffers(hPipe); 
   DisconnectNamedPipe(hPipe); 
   CloseHandle(hPipe); 

   HeapFree(hHeap, 0, pchRequest);
   HeapFree(hHeap, 0, pchReply);

   printf("InstanceThread exiting.\n");
   return 1;
}
```

그럼 인스턴트 스레드에서 무슨 작업을 하는지 InstanceThread 함수를 봐보자.  
함수가 시작되면 반복 루프를 시작하고, 안에서는 ReadFile 함수를 통해 클라이언트가 보낸 데이터를 읽어온다.  
그 후, GetAnswerToRequest 함수를 호출하는데, 해당 함수는 실제 서버가 클라이언트한테서 데이터를 받아서 처리하는 작업을 하는 함수다.  

```cpp
VOID GetAnswerToRequest(LPTSTR pchRequest, LPTSTR pchReply, LPDWORD pchBytes)
{
    size_t len = lstrlen(pchRequest);
    for (size_t i = 0; i < len; i++) {
        pchReply[i] = pchRequest[len - 1 - i];
    }
    pchReply[len] = TEXT('\0');
    *pchBytes = (len + 1) * sizeof(TCHAR);
}
```

예를 들어 이 서버가 클라이언트한테 받은 문자열을 거꾸로 뒤집어서 돌려주는 서버라면, GetAnswerToRequest 함수는 위처럼 작성될 것이다.  
현재 예제 코드에서는 GetAnswerToRequest 함수가 단순히 클라이언트한테 받은 문자열을 출력하고, 문자열을 복사하여 전체 문자열 수를 pchBytes에 설정해주는 작업이 끝이므로 넘어가겠다.  

클라이언트에게 받은 데이터를 처리하고 나면 WriteFile 함수를 사용하여 다시 클라이언트에게 데이터를 써준다.  
반복 루프를 나오고 나면 FlushFileBuffers 함수를 사용하여 클라이언트가 파이프에 적힌 데이터를 다 읽을 때까지 기다린 후, DisconnectNamedPipe 함수를 호출하여 서버쪽에서 연결을 끊고, 파이프 핸들을 닫는다.  

```cpp
#include <windows.h> 
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define BUFSIZE 512

int _tmain(int argc, TCHAR* argv[])
{
    HANDLE hPipe;
    LPTSTR lpvMessage = TEXT("Default message from client.");
    TCHAR  chBuf[BUFSIZE];
    BOOL   fSuccess = FALSE;
    DWORD  cbRead, cbToWrite, cbWritten, dwMode;
    LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

    if (argc > 1).
        lpvMessage = argv[1];

    while (1)
    {
        hPipe = CreateFile(
            lpszPipename,   // pipe name 
            GENERIC_READ |  // read and write access 
            GENERIC_WRITE,
            0,              // no sharing 
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe 
            0,              // default attributes 
            NULL);          // no template file 

        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            _tprintf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());
            return -1;
        }

        if (!WaitNamedPipe(lpszPipename, 20000))
        {
            printf("Could not open pipe: 20 second wait timed out.");
            return -1;
        }
    }

    dwMode = PIPE_READMODE_MESSAGE;
    fSuccess = SetNamedPipeHandleState(
        hPipe,    // pipe handle 
        &dwMode,  // new pipe mode 
        NULL,     // don't set maximum bytes 
        NULL);    // don't set maximum time 
    if (!fSuccess)
    {
        _tprintf(TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError());
        return -1;
    }

    cbToWrite = (lstrlen(lpvMessage) + 1) * sizeof(TCHAR);
    _tprintf(TEXT("Sending %d byte message: \"%s\"\n"), cbToWrite, lpvMessage);

    fSuccess = WriteFile(
        hPipe,                  // pipe handle 
        lpvMessage,             // message 
        cbToWrite,              // message length 
        &cbWritten,             // bytes written 
        NULL);                  // not overlapped 

    if (!fSuccess)
    {
        _tprintf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
        return -1;
    }

    printf("\nMessage sent to server, receiving reply as follows:\n");

    do
    {
        fSuccess = ReadFile(
            hPipe,    // pipe handle 
            chBuf,    // buffer to receive reply 
            BUFSIZE * sizeof(TCHAR),  // size of buffer 
            &cbRead,  // number of bytes read 
            NULL);    // not overlapped 

        if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
            break;

        _tprintf(TEXT("\"%s\"\n"), chBuf);
    } while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 

    if (!fSuccess)
    {
        _tprintf(TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError());
        return -1;
    }

    printf("\n<End of message, press ENTER to terminate connection and exit>");
    _getch();

    CloseHandle(hPipe);

    return 0;
}
```

이제 서버가 어떤 식으로 동작하는지 알았으니 클라이언트의 예제 코드를 봐보자.  
변수 선언 및 초기화는 넘어가고, 반복 루프부터 보면 서버와 연결하기 위해 서버 Pipe와 같은 이름인 \\.\pipe\mynamedpipe로 CreateFile 함수를 호출한다.  
그 밑에 3개의 조건이 있는데, 이 조건들을 한 번 봐보자.  

우선 첫 번째 조건으로 올바른 핸들이 반환 됐는지 확인한다.  
CreateFile은 서버의 Pipe에 대해 핸들을 획득하면 해당 핸들을 반환해 주고, 핸들 획득에 실패하면 INVALID_HANDLE_VALUE를 반환해 준다.  
즉, 해당 조건이 참이라면 올바른 핸들을 획득했단 뜻이므로 반복 루프를 종료해준다.  

두 번째 조건은 핸들 획득에 실패한 원인이 ERROR_PIPE_BUSY인지 확인한다.  
Named Pipe는 서버가 생성될 때 설정된 nMaxINstances 개수만큼 한 번에 클라이언트와 연결할 수 있고, 클라이언트가 그 개수보다 많을 경우 남은 클라이언트들을 대기 상태로 기다린다고 했다.  
서버의 인스턴스가 모두 사용 중일 때, 클라이언트가 인스턴스에 연결하려고 하면 이미 사용 중이므로 당연히 실패하게 된다.  
이때 클라이언트는 CreateFile 함수에서 핸들 획득에 실패했다고 결고를 받고, 핸들 획득에 실패한 자세한 원인은 ERROR_PIPE_BUSY라는 에러 코드를 통해 알 수 있다.  
즉, GetLastError 함수의 값이 ERROR_PIPE_BUSY인지 확인하는 조건은 인스턴스가 모두 사용 중인지, 아니면 진짜 다른 기타 원인으로 실패했는지 확인하는 과정이고, ERROR_PIPE_BUSY가 아닌 다른 에러인 경우에는 return을 통해 프로세스를 종료하게 된다.  

마지막 세 번째 조건은 모든 인스턴스가 사용 중일 경우, 20초간 기다리는 조건이다.  
클라이언트는 WaitNamedPipe 함수를 통해 20초 동안 서버의 인스턴스가 비는 것을 기다린다.  
만약 20초 안에 빈 인스턴스가 생기면 다시 반복 루프를 통해 CreateFile 함수를 호출하여 서버와 연결한다.  
하지만 20초 안에도 빈 인스턴스가 안 생긴다면 return을 통해 프로세스를 종료하게 된다.  

```cpp
BOOL SetNamedPipeHandleState(
  [in]           HANDLE  hNamedPipe,
  [in, optional] LPDWORD lpMode,
  [in, optional] LPDWORD lpMaxCollectionCount,
  [in, optional] LPDWORD lpCollectDataTimeout
);
```

서버와 연결되면 반복 루프를 나와 해당 핸들을 메시지 단위로 읽도록 모드를 설정한다.  
SetNamedPipeHandleState 함수에는 데이터를 읽는 방법에 대해 2개의 모드가 존재한다.  
첫 번째는 byte 단위로 읽는 모드고, 두 번째는 메시지 단위로 읽는 모드다.  
둘이 무슨 차이인지 예를 들어 설명하자면, 서버가 WriteFile을 두 번 호출하여 "hello"랑 "world"를 썼다고 하자. 그리고 클라이언트는 100byte 버퍼로 ReadFile을 한 번 호출하게 되면, byte 단위인 경우에는 한 번에 "helloworld"를 받지만, 메시지 단위인 경우에는 "hello"만 받는다.  

클라이언트의 핸들이 어떤 모드로 읽을지 설정한 다음에는 서버에게 보낼 데이터의 byte 크기를 계산하여 cbToWrite에 저장한 뒤, WriteFile 함수를 통해 서버에게 보내준다.  
그 후, do-while문을 통해 반복 루프를 돌며 서버한테서 데이터를 읽어온다.  
ReadFile은 한 번에 데이터를 다 못 읽었을 경우, 일부만 읽고 0을 반환한다. 그래서 ReadFile 밑의 조건을 통해 다 못 읽었을 경우, GetLastError 함수의 값이 ERROR_MORE_DATA인지 확인하여 참이면 아직 남은 데이터가 있다고 판단하여 계속 루프를 돌린다.  

서버한테서 데이터를 읽어오는 루프가 종료되고 나면, _getch 함수를 통해 사용자가 데이터를 확인하고 키를 입력할 때까지 기다린 후, CloseHandle로 핸들을 닫는다.  
클라이언트가 핸들을 닫게 되면 서버는 이를 감지하고 DisconnectNamedPipe 함수와 CloseHandle 함수를 호출하여 해당 인스턴스를 정리한 뒤, 다음 클라이언트를 받을 준비를 하는 것이다.  

# References

- https://spacefriend.tistory.com/105
- https://hackyboiz.github.io/2025/05/12/ogu123/NamedPipe/KR/
- https://csandker.io/2021/01/10/Offensive-Windows-IPC-1-NamedPipes.html
- https://learn.microsoft.com/ko-kr/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe
- https://learn.microsoft.com/ko-kr/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
- https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
- https://learn.microsoft.com/ko-kr/windows/win32/api/winbase/nf-winbase-createnamedpipea
- https://learn.microsoft.com/ko-kr/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
- https://learn.microsoft.com/ko-kr/windows/win32/api/fileapi/nf-fileapi-createfilea
- https://learn.microsoft.com/ko-kr/windows/win32/api/winbase/nf-winbase-callnamedpipea
- https://learn.microsoft.com/ko-kr/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
- https://learn.microsoft.com/ko-kr/windows/win32/api/fileapi/nf-fileapi-readfile
- https://learn.microsoft.com/ko-kr/windows/win32/ipc/multithreaded-pipe-server
- https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
- https://learn.microsoft.com/ko-kr/windows/win32/ipc/named-pipe-client?source=recommendations
- https://learn.microsoft.com/ko-kr/windows/win32/api/namedpipeapi/nf-namedpipeapi-setnamedpipehandlestate