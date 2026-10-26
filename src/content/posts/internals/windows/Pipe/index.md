---
title: "Named Pipe & Anonymous Pipe"
published: 2026-04-30
description: "Windows의 Named Pipe와 Anonymous Pipe 동작 과정 설명"
image: ""
tags: ["Windows", "Pipe", "Named Pipe", "Anonymous Pipe"]
category: "Windows"
draft: true
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

