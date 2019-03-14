#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wtsapi32.h>
#include <thread>
#include <cstdio>
#include <cstdint>
#include "EventSink.h"

#define MAX_ATTENDEE 1

void StartServer();
void ImpersonateActiveUserAndRun();

IRDPSRAPISharingSession *session = NULL;
IRDPSRAPIInvitationManager *invitationManager = NULL;
IRDPSRAPIInvitation *invitation = NULL;
IRDPSRAPIAttendeeManager *attendeeManager = NULL;
IRDPSRAPIAttendee *attendee = NULL;

IConnectionPointContainer* picpc = NULL;
IConnectionPoint* picp = NULL;
EventSink ev;
BSTR inviteString;

DWORD WINAPI ThreadInviteString(LPVOID arg);



//Function to run a process as active user from windows service
void ImpersonateActiveUserAndRun()
{
	//DWORD session_id = -1;
	//HANDLE hUserToken;
	//HANDLE hTheToken;

	//session_id = WTSGetActiveConsoleSessionId();
	//BOOL bret = WTSQueryUserToken(session_id, &hUserToken);
	////if (bret == FALSE)
	////{
	////	return;
	////}
	//if (!DuplicateTokenEx(hUserToken,
	//	//0,
	//	//MAXIMUM_ALLOWED,
	//	TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS | MAXIMUM_ALLOWED,
	//	NULL,
	//	SecurityImpersonation,
	//	TokenPrimary,
	//	&hTheToken))
	//{
	//	//return;
	//}

	//ImpersonateLoggedOnUser(hTheToken);
	//StartServer();
	//RevertToSelf();

}
int ConnectEvent(IUnknown* Container, REFIID riid, IUnknown* Advisor, IConnectionPointContainer** picpc, IConnectionPoint** picp)
{
	HRESULT hr = 0;
	unsigned long tid = 0;
	IConnectionPointContainer* icpc = 0;
	IConnectionPoint* icp = 0;
	*picpc = 0;
	*picp = 0;
	Container->QueryInterface(IID_IConnectionPointContainer, (void **)&icpc);
	if (icpc)
	{
		*picpc = icpc;
		icpc->FindConnectionPoint(riid, &icp);
		if (icp)
		{
			*picp = icp;
			hr = icp->Advise(Advisor, &tid);
		}
	}
	return tid;
}

void Disconnect()
{
	if (session)
	{
		session->Close();
		session->Release();
		session = NULL;
	}
}

const TCHAR* printfString(const TCHAR* format, ...) {
	static TCHAR strBuffer_g[1024];
	va_list args;
	va_start(args, format);

#if _DEBUG
	int len = _vsctprintf(format, args);
	if (len >= 1024)
		_ASSERT(0);
#endif

	_vstprintf(strBuffer_g, format, args);
	return strBuffer_g;
}

void EnableDisableUAC(bool flag)
{
	TCHAR* value;
	int ret;

	TCHAR* reg_true = _T("%windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f");
	TCHAR* reg_false = _T("%windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f");

	value = (flag == true) ? reg_true : reg_false;
	ret = _wsystem(value);
	printf("PromptOnSecureDesktop=%s.result=%d\n", value, ret);
}
void EnableDisableUACAdmin(bool flag)
{
	TCHAR* value;
	int ret;

	TCHAR* reg_true = _T("%windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f");
	TCHAR* reg_false = _T("%windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f");

	value = (flag == true) ? reg_true : reg_false;
	ret = _wsystem(value);
	printf("ConsentPromptBehaviorAdmin=%s.result=%d\n", value, ret);
}
void OnAttendeeConnected(IDispatch *pAttendee)
{
	BSTR remoteName;
	IRDPSRAPIAttendee *pRDPAtendee;
	pAttendee->QueryInterface(__uuidof(IRDPSRAPIAttendee), (void**)&pRDPAtendee);
	pRDPAtendee->put_ControlLevel(CTRL_LEVEL::CTRL_LEVEL_VIEW);
	if(pRDPAtendee->get_RemoteName(&remoteName) == S_OK);
		printf("%S Connected.\n", remoteName);

	// UAC ON
	EnableDisableUAC(false);
	EnableDisableUACAdmin(false);
}

void OnAttendeeDisconnected(IDispatch *pAttendee)
{
	BSTR remoteName;
	IRDPSRAPIAttendee *pRDPAtendee;
	IRDPSRAPIAttendeeDisconnectInfo *info;
	ATTENDEE_DISCONNECT_REASON reason;
	pAttendee->QueryInterface(__uuidof(IRDPSRAPIAttendeeDisconnectInfo), (void**)&info);
	if (info->get_Reason(&reason) == S_OK)
	{
		switch (reason)
		{
		case ATTENDEE_DISCONNECT_REASON_APP:
			break;
		case ATTENDEE_DISCONNECT_REASON_ERR:
			break;
		case ATTENDEE_DISCONNECT_REASON_CLI:
			break;
		default:
			break;
		}
	}
	if (info->get_Attendee(&pRDPAtendee) == S_OK)
	{
		if (pRDPAtendee->get_RemoteName(&remoteName) == S_OK);
			printf("%S Disconnected.\n", remoteName);
	}
	pAttendee->Release();
	picp = 0;
	picpc = 0;
	//Disconnect();
	// UAC OFF
	EnableDisableUAC(true);
	EnableDisableUACAdmin(true);

}

void OnControlLevelChangeRequest(IDispatch  *pAttendee, CTRL_LEVEL RequestedLevel)
{
	IRDPSRAPIAttendee *pRDPAtendee;
	pAttendee->QueryInterface(__uuidof(IRDPSRAPIAttendee), (void**)&pRDPAtendee);
	if (pRDPAtendee->put_ControlLevel(RequestedLevel) == S_OK)
	{
		switch (RequestedLevel)
		{
		case CTRL_LEVEL_NONE:
			printf("Control set to CTRL_LEVEL_NONE.\n");
			break;
		case CTRL_LEVEL_VIEW:
			printf("Control set to CTRL_LEVEL_VIEW.\n");
			break;
		case CTRL_LEVEL_INTERACTIVE:
			printf("Control set to CTRL_LEVEL_INTERACTIVE.\n");
			break;
		}
	}
}

void StartServer()
{
	TCHAR hostname[260];
	DWORD dwSize = 260;
	GetComputerName(hostname, &dwSize);
	lstrcat(hostname, _T(".xml"));

	CoInitialize(NULL);

	if (CoCreateInstance(__uuidof(RDPSession), NULL, CLSCTX_INPROC_SERVER, __uuidof(IRDPSRAPISharingSession), (void**)&session) != S_OK)
	{
		printf("CoCreateInstance failed with err=%d.\n", GetLastError());
		return;
	}

	ConnectEvent((IUnknown*)session, __uuidof(_IRDPSessionEvents), (IUnknown*)&ev, &picpc, &picp);

	if (session->Open() != S_OK)
	{
		printf("session->Open failed with err=%d.\n", GetLastError());
		return;
	}

	if (session->get_Invitations(&invitationManager) != S_OK)
	{
		printf("session->get_Invitations failed with err=%d.\n", GetLastError());
		return;
	}

	//if (invitationManager->CreateInvitation(L"WinPresenter", L"PresentationGroup", L"", MAX_ATTENDEE, &invitation) != S_OK)
	if (invitationManager->CreateInvitation(L"tokuda@tuk2ku.com", L"PresentationGroup", L"", MAX_ATTENDEE, &invitation) != S_OK)
	{
		printf("invitationManager->CreateInvitation failed with err=%d.\n", GetLastError());
		return;
	}

	ev.SetEventFunction(OnAttendeeConnected, OnAttendeeDisconnected, OnControlLevelChangeRequest);

	FILE *invite = _tfopen(hostname, _T("w"));
	if (invite)
	{
		if (invitation->get_ConnectionString(&inviteString) == S_OK)
		{
			fwprintf_s(invite, L"%ws", inviteString);
			//SysFreeString(inviteString);
		}
		fclose(invite);
	}

	if (session->get_Attendees(&attendeeManager) == S_OK)
	{
		// Create Thread
		HANDLE hThread;

		DWORD dwThreadId;

		//スレッド起動

		hThread = CreateThread(

			NULL, //セキュリティ属性

			0, //スタックサイズ

			ThreadInviteString, //スレッド関数

			NULL, //スレッド関数に渡す引数

			0, //作成オプション(0またはCREATE_SUSPENDED)

			&dwThreadId);//スレッドID

		//ThreadInviteString();
		printf("Start ok.\n");
		printf("Watting for attendees.\n");
	}
}
std::string ConvertWCSToMBS(const wchar_t* pstr, long wslen)
{
	int len = ::WideCharToMultiByte(CP_ACP, 0, pstr, wslen, NULL, 0, NULL, NULL);

	std::string dblstr(len, '\0');
	len = ::WideCharToMultiByte(CP_ACP, 0 /* no flags */,
		pstr, wslen /* not necessary NULL-terminated */,
		&dblstr[0], len,
		NULL, NULL /* no default char */);

	return dblstr;
}
DWORD WINAPI ThreadInviteString(LPVOID arg)
{
	printf("Thread Start ok.\n");

	//----------------------
	// Initialize Winsock.
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(1, 1), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %ld\n", iResult);
		return 1;
	}
	//----------------------
	// Create a SOCKET for listening for
	// incoming connection requests.
	SOCKET ListenSocket;
	ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ListenSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = INADDR_ANY;
	service.sin_port = htons(13389);

	if (bind(ListenSocket,
		(SOCKADDR *)& service, sizeof(service)) == SOCKET_ERROR) {
		wprintf(L"bind failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	//----------------------
	// Listen for incoming connection requests.
	// on the created socket
	if (listen(ListenSocket, 1) == SOCKET_ERROR) {
		wprintf(L"listen failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	do
	{
		//----------------------
		// Create a SOCKET for accepting incoming requests.
		SOCKET AcceptSocket;
		wprintf(L"Waiting for client to connect...\n");

		//----------------------
		// Accept the connection.
		AcceptSocket = accept(ListenSocket, NULL, NULL);
		if (AcceptSocket == INVALID_SOCKET) {
			wprintf(L"accept failed with error: %ld\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}
		else
			wprintf(L"Client connected.\n");

		// Write Invitate String
		std::string inv_str = ConvertWCSToMBS(inviteString, ::SysStringLen(inviteString));
		short size = strlen(inv_str.c_str());
		send(AcceptSocket, (char *)&size, 2, 0);
		send(AcceptSocket, inv_str.c_str(), size, 0);
		printf("Send inviteString %s\n", inv_str.c_str());
		// dummy read
		char buf[1];
		recv(AcceptSocket, buf, 1, 0);
		// No longer need server socket
		closesocket(AcceptSocket);

	} while (1);

	closesocket(ListenSocket);
	WSACleanup();
	return 0;
}

int _tmain(int argc, TCHAR* argv[])
{
	MSG Msg;

	StartServer();
	//ImpersonateActiveUserAndRun();

	while (GetMessage(&Msg, NULL, 0, 0))
	{
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}

	return 1;
}