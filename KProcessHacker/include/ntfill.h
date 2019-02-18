#ifndef NTFILL_H
#define NTFILL_H

extern ULONG KphDynNtVersion;
extern ULONG KphDynObDecodeShift;
extern ULONG KphDynObAttributesShift;

// EX

#if defined (_WIN64)
#define MAX_FAST_REFS 15
#else
#define MAX_FAST_REFS 7
#endif

typedef struct _EX_FAST_REF {
    union {
        PVOID Object;
#if defined (_WIN64)
        ULONG_PTR RefCnt : 4;
#else
        ULONG_PTR RefCnt : 3;
#endif
        ULONG_PTR Value;
    };
} EX_FAST_REF, *PEX_FAST_REF;

typedef struct _EX_CALLBACK {
    EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF        RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID                 Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _CM_NOTIFY_ENTRY
{
    LIST_ENTRY  ListEntryHead;	//+0
    ULONG   RefCount;			//+16
    ULONG   Altitude;
    LARGE_INTEGER   Cookie;		//+24
    PVOID	Context;			//+32
    PVOID	Function;			//+40
}CM_NOTIFY_ENTRY, *PCM_NOTIFY_ENTRY;

typedef struct _OB_CALLBACK
{
    LIST_ENTRY  ListEntry;
    OB_OPERATION Operations;
    ULONG Active;
    PVOID ObHandle;
    PVOID ObjectType;
    PVOID PreCall;
    PVOID PostCall;
    EX_RUNDOWN_REF RundownProtection;
} OB_CALLBACK, *POB_CALLBACK;

typedef VOID(*PDEBUG_PRINT_CALLBACK) (
    _In_ PSTRING Output,
    _In_ ULONG ComponentId,
    _In_ ULONG Level);

typedef struct _DBG_CALLBACK
{
    EX_RUNDOWN_REF RundownProtection;
    PDEBUG_PRINT_CALLBACK Callback;
    LIST_ENTRY ListEntry;
}DBG_CALLBACK, *PDBG_CALLBACK;

typedef struct _OBJECT_HEADER_CREATOR_INFO
{
    LIST_ENTRY TypeList;
    PVOID CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Reserved;
}OBJECT_HEADER_CREATOR_INFO, *POBJECT_HEADER_CREATOR_INFO;

typedef struct _OBJECT_TYPE_INITIALIZER_XP
{
    USHORT Length;
    CHAR UseDefaultObject;
    CHAR CaseInsensitive;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    CHAR SecurityRequired;
    CHAR MaintainHandleCount;
    CHAR MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER_XP, *POBJECT_TYPE_INITIALIZER_XP;

typedef struct _OBJECT_TYPE_INITIALIZER_WIN7
{
    USHORT Length;
    union
    {
        CHAR ObjectTypeFlags;
        struct
        {
            CHAR CaseInsensitive : 1;
            CHAR UnnamedObjectsOnly : 1;
            CHAR UseDefaultObject : 1;
            CHAR SecurityRequired : 1;
            CHAR MaintainHandleCount : 1;
            CHAR MaintainTypeList : 1;
            CHAR SupportsObjectCallbacks : 1;
        }s1;
    }u1;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER_WIN7, *POBJECT_TYPE_INITIALIZER_WIN7;

typedef OBJECT_TYPE_INITIALIZER_WIN7 OBJECT_TYPE_INITIALIZER_VISTA, *POBJECT_TYPE_INITIALIZER_VISTA;

typedef struct _OBJECT_TYPE_INITIALIZER_WIN8
{
    USHORT Length;
    USHORT ObjectTypeFlags;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
    ULONG WaitObjectFlagMask;
    USHORT WaitObjectFlagOffset;
    USHORT WaitObjectPointerOffset;
} OBJECT_TYPE_INITIALIZER_WIN8, *POBJECT_TYPE_INITIALIZER_WIN8;

typedef struct _OBJECT_TYPE_XP
{
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_XP TypeInfo;
    ULONG Key;
    ERESOURCE ObjectLocks[4];
}OBJECT_TYPE_XP, *POBJECT_TYPE_XP;

typedef struct _OBJECT_TYPE_VISTA
{
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
#ifdef _WIN64
    ULONG Padding;
#endif
    OBJECT_TYPE_INITIALIZER_VISTA TypeInfo;
    ERESOURCE Mutex;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    EX_PUSH_LOCK ObjectLocks[32];
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_VISTA, *POBJECT_TYPE_VISTA;

typedef struct _OBJECT_TYPE_WIN7
{
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    CHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
#ifdef _WIN64
    ULONG Padding;
#endif
    OBJECT_TYPE_INITIALIZER_WIN7 TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_WIN7, *POBJECT_TYPE_WIN7;

typedef struct _OBJECT_TYPE_WIN8
{
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    CHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
#ifdef _WIN64
    ULONG Padding;
#endif
    OBJECT_TYPE_INITIALIZER_WIN8 TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_WIN8, *POBJECT_TYPE_WIN8;

#define OBJECT_TO_OBJECT_HEADER_XP( o ) \
    CONTAINING_RECORD( (o), OBJECT_HEADER_XP, Body )

#define OBJECT_TO_OBJECT_HEADER_VISTA( o ) \
    CONTAINING_RECORD( (o), OBJECT_HEADER_VISTA, Body )

#define OBJECT_TO_OBJECT_HEADER_WIN7( o ) \
    CONTAINING_RECORD( (o), OBJECT_HEADER_WIN7, Body )

typedef struct _EX_PUSH_LOCK_WAIT_BLOCK *PEX_PUSH_LOCK_WAIT_BLOCK;

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    _Inout_ PEX_PUSH_LOCK PushLock,
    _Inout_opt_ PEX_PUSH_LOCK_WAIT_BLOCK WaitBlock
    );

typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        PVOID Object;
        ULONG ObAttributes;
        ULONG_PTR Value;
    };
    union
    {
        ACCESS_MASK GrantedAccess;
        LONG NextFreeTableEntry;
    };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE HANDLE_TABLE, *PHANDLE_TABLE;

typedef BOOLEAN (NTAPI *PEX_ENUM_HANDLE_CALLBACK_61)(
    _Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_ PVOID Context
    );

// since WIN8
typedef BOOLEAN (NTAPI *PEX_ENUM_HANDLE_CALLBACK)(
    _In_ PHANDLE_TABLE HandleTable,
    _Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_ PVOID Context
    );

NTKERNELAPI
BOOLEAN
NTAPI
ExEnumHandleTable(
    _In_ PHANDLE_TABLE HandleTable,
    _In_ PEX_ENUM_HANDLE_CALLBACK EnumHandleProcedure,
    _Inout_ PVOID Context,
    _Out_opt_ PHANDLE Handle
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

// IO

extern POBJECT_TYPE *IoDriverObjectType;

// KE

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
    );

typedef VOID KKERNEL_ROUTINE(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2
    );

typedef KKERNEL_ROUTINE (NTAPI *PKKERNEL_ROUTINE);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
    _In_ PRKAPC Apc
    );

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PRKTHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_opt_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext
    );

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
    );

// OB

// These definitions are no longer correct, but they produce correct results.

#define OBJ_PROTECT_CLOSE 0x00000001
#define OBJ_HANDLE_ATTRIBUTES (OBJ_PROTECT_CLOSE | OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE)

// This attribute is now stored in the GrantedAccess field.
#define ObpAccessProtectCloseBit 0x2000000

#define ObpDecodeGrantedAccess(Access) \
    ((Access) & ~ObpAccessProtectCloseBit)

FORCEINLINE PVOID ObpDecodeObject(PVOID Object)
{
#ifdef _M_X64
    if (KphDynNtVersion >= PHNT_WIN8)
    {
        if (KphDynObDecodeShift != -1)
            return (PVOID)(((LONG_PTR)Object >> KphDynObDecodeShift) & ~(ULONG_PTR)0xf);
        else
            return NULL;
    }
    else
    {
        return (PVOID)((ULONG_PTR)Object & ~OBJ_HANDLE_ATTRIBUTES);
    }
#else
    return (PVOID)((ULONG_PTR)Object & ~OBJ_HANDLE_ATTRIBUTES);
#endif
}

FORCEINLINE ULONG ObpGetHandleAttributes(PHANDLE_TABLE_ENTRY HandleTableEntry)
{
#ifdef _M_X64
    if (KphDynNtVersion >= PHNT_WIN8)
    {
        if (KphDynObAttributesShift != -1)
            return (ULONG)(HandleTableEntry->Value >> KphDynObAttributesShift) & 0x3;
        else
            return 0;
    }
    else
    {
        return (HandleTableEntry->ObAttributes & (OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE)) |
            ((HandleTableEntry->GrantedAccess & ObpAccessProtectCloseBit) ? OBJ_PROTECT_CLOSE : 0);
    }
#else
    return (HandleTableEntry->ObAttributes & (OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE)) |
        ((HandleTableEntry->GrantedAccess & ObpAccessProtectCloseBit) ? OBJ_PROTECT_CLOSE : 0);
#endif
}

typedef struct _OBJECT_CREATE_INFORMATION OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

// This structure is not correct on Windows 7, but the offsets we need are still correct.
typedef struct _OBJECT_HEADER
{
    LONG PointerCount;
    union
    {
        LONG HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    union
    {
        UCHAR TraceFlags;
        struct
        {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
            UCHAR Reserved : 6;
        };
    };
    UCHAR InfoMask;
    union
    {
        UCHAR Flags;
        struct
        {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    union
    {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

#ifdef _M_X64
C_ASSERT(FIELD_OFFSET(OBJECT_HEADER, Body) == 0x030);
C_ASSERT(sizeof(OBJECT_HEADER) == 0x038);
#else
C_ASSERT(FIELD_OFFSET(OBJECT_HEADER, Body) == 0x018);
C_ASSERT(sizeof(OBJECT_HEADER) == 0x020);
#endif

#define OBJECT_TO_OBJECT_HEADER(Object) CONTAINING_RECORD((Object), OBJECT_HEADER, Body)

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
    );

NTKERNELAPI
NTSTATUS
NTAPI
ObOpenObjectByName(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE PreviousMode,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ PVOID ParseContext,
    _Out_ PHANDLE Handle
    );

NTKERNELAPI
NTSTATUS
NTAPI
ObSetHandleAttributes(
    _In_ HANDLE Handle,
    _In_ POBJECT_HANDLE_FLAG_INFORMATION HandleFlags,
    _In_ KPROCESSOR_MODE PreviousMode
    );

// PS

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessThreadByCid(
    _In_ PCLIENT_ID ClientId,
    _Out_opt_ PEPROCESS *Process,
    _Out_ PETHREAD *Thread
    );

typedef struct _EJOB *PEJOB;

extern POBJECT_TYPE *PsJobType;

NTKERNELAPI
PEJOB
NTAPI
PsGetProcessJob(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
NTSTATUS
NTAPI
PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
VOID
NTAPI
PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS Process
    );

// RTL

// Sensible limit that may or may not correspond to the actual Windows value.
#define MAX_STACK_DEPTH 256

#define RTL_WALK_USER_MODE_STACK 0x00000001
#define RTL_WALK_VALID_FLAGS 0x00000001

#endif
