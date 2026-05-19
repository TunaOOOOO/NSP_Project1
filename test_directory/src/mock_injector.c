#include <stdio.h>
#include <windows.h>

int main() {
    // 模擬惡意軟體嘗試分配記憶體並注入執行緒
    printf("Attempting process injection...\n");

    // 這些字串會觸發 Sentinel 的啟發式規則
    void* exec_mem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, exec_mem, payload, size, NULL);
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);

    return 0;
}