#ifndef CALLBACKTABP_H
#define CALLBACKTABP_H

BOOLEAN EtpCallbackPageCallback(
    _In_ struct _PH_MAIN_TAB_PAGE *Page,
    _In_ PH_MAIN_TAB_PAGE_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2
    );

VOID NTAPI EtpCallbackTabSelectionChangedCallback(
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3,
    _In_ PVOID Context
    );

VOID NTAPI EtpCallbackTabSaveContentCallback(
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3,
    _In_ PVOID Context
    );

VOID NTAPI EtpCallbackTabFontChangedCallback(
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3,
    _In_ PVOID Context
    );

BOOLEAN EtpCallbackNodeHashtableEqualFunction(
    _In_ PVOID Entry1,
    _In_ PVOID Entry2
    );

ULONG EtpCallbackNodeHashtableHashFunction(
    _In_ PVOID Entry
    );

VOID EtInitializeCallbackTreeList(
    _In_ HWND hwnd
    );

PET_CALLBACK_NODE EtAddCallbackNode(
    _In_ PET_CALLBACK_ITEM CallbackItem
    );

PET_CALLBACK_NODE EtFindCallbackNode(
    _In_ PET_CALLBACK_ITEM CallbackItem
    );

VOID EtRemoveCallbackNode(
    _In_ PET_CALLBACK_NODE CallbackNode
    );

VOID EtUpdateCallbackNode(
    _In_ PET_CALLBACK_NODE CallbackNode
    );

BOOLEAN NTAPI EtpCallbackTreeNewCallback(
    _In_ HWND hwnd,
    _In_ PH_TREENEW_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2,
    _In_opt_ PVOID Context
    );

PET_CALLBACK_ITEM EtGetSelectedCallbackItem(
    VOID
    );

VOID EtGetSelectedCallbackItems(
    _Out_ PET_CALLBACK_ITEM **CallbackItems,
    _Out_ PULONG NumberOfCallbackItems
    );

VOID EtDeselectAllCallbackNodes(
    VOID
    );

VOID EtSelectAndEnsureVisibleCallbackNode(
    _In_ PET_CALLBACK_NODE CallbackNode
    );

VOID EtCopyCallbackList(
    VOID
    );

VOID EtWriteCallbackList(
    _Inout_ PPH_FILE_STREAM FileStream,
    _In_ ULONG Mode
    );

VOID EtHandleCallbackCommand(
    _In_ ULONG Id
    );

VOID EtpInitializeCallbackMenu(
    _In_ PPH_EMENU Menu,
    _In_ PET_CALLBACK_ITEM *CallbackItems,
    _In_ ULONG NumberOfCallbackItems
    );

VOID EtShowCallbackContextMenu(
    _In_ HWND TreeWindowHandle,
    _In_ PPH_TREENEW_CONTEXT_MENU ContextMenuEvent
    );

VOID NTAPI EtpCallbackItemAddedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
    );

VOID NTAPI EtpCallbackItemModifiedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
    );

VOID NTAPI EtpCallbackItemRemovedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
    );

VOID NTAPI EtpCallbackItemsUpdatedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
    );

VOID NTAPI EtpOnCallbackItemAdded(
    _In_ PVOID Parameter
    );

VOID NTAPI EtpOnCallbackItemModified(
    _In_ PVOID Parameter
    );

VOID NTAPI EtpOnCallbackItemRemoved(
    _In_ PVOID Parameter
    );

VOID NTAPI EtpOnCallbackItemsUpdated(
    _In_ PVOID Parameter
    );

VOID NTAPI EtpCallbackSearchChangedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
    );

BOOLEAN NTAPI EtpSearchCallbackListFilterCallback(
    _In_ PPH_TREENEW_NODE Node,
    _In_opt_ PVOID Context
    );

VOID NTAPI EtpCallbackToolStatusActivateContent(
    _In_ BOOLEAN Select
    );

HWND NTAPI EtpCallbackToolStatusGetTreeNewHandle(
    VOID
    );

INT_PTR CALLBACK EtpCallbackTabErrorDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    );

VOID NTAPI RefreshProviderCallback(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
);

#endif
