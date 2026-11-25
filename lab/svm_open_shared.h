#pragma once

typedef struct _SVM_OPEN_SHARED {
    volatile LONG Ready;
    DWORD SetupError;
    ULONGLONG OutHandlePointer;
    ULONGLONG ObjectAttributesPointer;
    ULONGLONG ReplacementObjectAttributesPointer;
    ULONGLONG IoStatusPointer;
    ULONGLONG ExpectedReturnRip;
    DWORD ExpectedService;
    LONG DirectBefore;
    LONG MonitoredStatus;
    LONG DirectAfter;
    ULONGLONG StartTick;
    ULONGLONG EndTick;
    DWORD ReadCount;
    CHAR Payload[128];
} SVM_OPEN_SHARED;
