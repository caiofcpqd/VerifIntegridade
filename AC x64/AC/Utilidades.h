#pragma once

#include "WinSDK.h"

PVOID GetProcessPEB()
{
#if defined(_WIN64)
    return (PVOID)__readgsqword(0x60);
#else
    return (PVOID)__readfsdword(0x30);
#endif
}

BOOL HideInLoadOrderLinks(HMODULE dllBase)
{
    BOOL r = FALSE;
    PPEB peb = (PPEB)GetProcessPEB();

    PLIST_ENTRY OrderModuleHead, OrderModuleTail;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;

    OrderModuleHead = OrderModuleTail = peb->Ldr->InLoadOrderModuleList.Blink;

    do
    {
        pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(OrderModuleHead, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pLdrDataEntry->DllBase == NULL)
            break;

        if (pLdrDataEntry->DllBase == dllBase)
        {
            RemoveEntryList(OrderModuleHead);
            r = TRUE;
        }

        OrderModuleHead = OrderModuleHead->Blink;

    } while (OrderModuleHead != OrderModuleTail);

    return r;
}

BOOL HideInMemoryOrderLinks(HMODULE dllBase)
{
    BOOL r = FALSE;
    PPEB peb = (PPEB)GetProcessPEB();

    PLIST_ENTRY OrderModuleHead, OrderModuleTail;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;

    OrderModuleHead = OrderModuleTail = peb->Ldr->InMemoryOrderModuleList.Blink;

    do
    {
        pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(OrderModuleHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (pLdrDataEntry->DllBase == NULL)
            break;

        if (pLdrDataEntry->DllBase == dllBase)
        {
            RemoveEntryList(OrderModuleHead);
            r = TRUE;
        }

        OrderModuleHead = OrderModuleHead->Blink;

    } while (OrderModuleHead != OrderModuleTail);

    return r;
}

BOOL HideInInitializationOrderLinks(HMODULE dllBase)
{
    BOOL r = FALSE;
    PPEB peb = (PPEB)GetProcessPEB();

    PLIST_ENTRY OrderModuleHead, OrderModuleTail;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;

    OrderModuleHead = OrderModuleTail = peb->Ldr->InInitializationOrderModuleList.Blink;

    do
    {
        pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(OrderModuleHead, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

        if (pLdrDataEntry->DllBase == NULL)
            break;

        if (pLdrDataEntry->DllBase == dllBase)
        {
            RemoveEntryList(OrderModuleHead);
            r = TRUE;
        }

        OrderModuleHead = OrderModuleHead->Blink;

    } while (OrderModuleHead != OrderModuleTail);

    return r;
}

void EsconderModulo(HMODULE hModule)
{
    HideInLoadOrderLinks(hModule);
    HideInMemoryOrderLinks(hModule);
    HideInInitializationOrderLinks(hModule);
}