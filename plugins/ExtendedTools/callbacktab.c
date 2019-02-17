/*
 * Process Hacker Extended Tools -
 *   kernel callbacks
 *
 * Copyright (C) 2011-2015 wj32
 *
 * This file is part of Process Hacker.
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "exttools.h"
#include "etwmon.h"
#include "kphuser.h"
#include <toolstatusintf.h>
#include "callbacktabp.h"

static PPH_MAIN_TAB_PAGE CallbackPage;
static BOOLEAN CallbackTreeNewCreated = FALSE;
static HWND CallbackTreeNewHandle;
static ULONG CallbackTreeNewSortColumn;
static PH_SORT_ORDER CallbackTreeNewSortOrder;

static PPH_HASHTABLE CallbackNodeHashtable; // hashtable of all nodes
static PPH_LIST CallbackNodeList; // list of all nodes

static PH_CALLBACK_REGISTRATION CallbackItemAddedRegistration;
static PH_CALLBACK_REGISTRATION CallbackItemModifiedRegistration;
static PH_CALLBACK_REGISTRATION CallbackItemRemovedRegistration;
static PH_CALLBACK_REGISTRATION CallbackItemsUpdatedRegistration;
static BOOLEAN CallbackNeedsRedraw = FALSE;

static PH_TN_FILTER_SUPPORT FilterSupport;
static PTOOLSTATUS_INTERFACE ToolStatusInterface;
static PH_CALLBACK_REGISTRATION SearchChangedRegistration;
static PH_CALLBACK_REGISTRATION RefreshProviderCallbackRegistration;

VOID EtInitializeCallbackTab(
    VOID
)
{
    PH_MAIN_TAB_PAGE page;
    PPH_PLUGIN toolStatusPlugin;

    if (toolStatusPlugin = PhFindPlugin(TOOLSTATUS_PLUGIN_NAME))
    {
        ToolStatusInterface = PhGetPluginInformation(toolStatusPlugin)->Interface;

        if (ToolStatusInterface->Version < TOOLSTATUS_INTERFACE_VERSION)
            ToolStatusInterface = NULL;
    }

    memset(&page, 0, sizeof(PH_MAIN_TAB_PAGE));
    PhInitializeStringRef(&page.Name, L"Kernel Callback");
    page.Callback = EtpCallbackPageCallback;
    CallbackPage = ProcessHacker_CreateTabPage(PhMainWndHandle, &page);

    if (ToolStatusInterface)
    {
        PTOOLSTATUS_TAB_INFO tabInfo;

        tabInfo = ToolStatusInterface->RegisterTabInfo(CallbackPage->Index);
        tabInfo->BannerText = L"Search Callback";
        tabInfo->ActivateContent = EtpCallbackToolStatusActivateContent;
        tabInfo->GetTreeNewHandle = EtpCallbackToolStatusGetTreeNewHandle;
    }

    PhRegisterCallback(
        PhGetGeneralCallback(GeneralCallbackRefreshProvider),
        RefreshProviderCallback,
        NULL,
        &RefreshProviderCallbackRegistration
    );
}

BOOLEAN EtpCallbackPageCallback(
    _In_ struct _PH_MAIN_TAB_PAGE *Page,
    _In_ PH_MAIN_TAB_PAGE_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2
)
{
    switch (Message)
    {
    case MainTabPageCreateWindow:
    {
        HWND hwnd;

        if (KphIsConnected())
        {
            ULONG thinRows;
            ULONG treelistBorder;

            thinRows = PhGetIntegerSetting(L"ThinRows") ? TN_STYLE_THIN_ROWS : 0;
            treelistBorder = PhGetIntegerSetting(L"TreeListBorderEnable") ? WS_BORDER : 0;
            hwnd = CreateWindow(
                PH_TREENEW_CLASSNAME,
                NULL,
                WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | TN_STYLE_ICONS | TN_STYLE_DOUBLE_BUFFERED | thinRows | treelistBorder,
                0,
                0,
                3,
                3,
                PhMainWndHandle,
                NULL,
                NULL,
                NULL
            );

            if (!hwnd)
                return FALSE;
        }
        else
        {
            *(HWND *)Parameter1 = CreateDialog(
                PluginInstance->DllBase,
                MAKEINTRESOURCE(IDD_CALLBACKTABERROR),
                PhMainWndHandle,
                EtpCallbackTabErrorDialogProc
            );
            return TRUE;
        }

        CallbackTreeNewCreated = TRUE;

        CallbackNodeHashtable = PhCreateHashtable(
            sizeof(PET_CALLBACK_NODE),
            EtpCallbackNodeHashtableEqualFunction,
            EtpCallbackNodeHashtableHashFunction,
            100
        );
        CallbackNodeList = PhCreateList(100);

        EtInitializeCallbackTreeList(hwnd);

        PhRegisterCallback(
            &EtCallbackItemAddedEvent,
            EtpCallbackItemAddedHandler,
            NULL,
            &CallbackItemAddedRegistration
        );
        PhRegisterCallback(
            &EtCallbackItemModifiedEvent,
            EtpCallbackItemModifiedHandler,
            NULL,
            &CallbackItemModifiedRegistration
        );
        PhRegisterCallback(
            &EtCallbackItemRemovedEvent,
            EtpCallbackItemRemovedHandler,
            NULL,
            &CallbackItemRemovedRegistration
        );
        PhRegisterCallback(
            &EtCallbackItemsUpdatedEvent,
            EtpCallbackItemsUpdatedHandler,
            NULL,
            &CallbackItemsUpdatedRegistration
        );

        EtInitializeCallbackInformation();

        *(HWND *)Parameter1 = hwnd;
    }
    return TRUE;
    case MainTabPageLoadSettings:
    {
        // Nothing
    }
    return TRUE;
    case MainTabPageSaveSettings:
    {
        // Nothing
    }
    return TRUE;
    case MainTabPageExportContent:
    {
        PPH_MAIN_TAB_PAGE_EXPORT_CONTENT exportContent = Parameter1;

        if (!EtEtwEnabled)
            return FALSE;

        //test
        //EtWriteCallbackList(exportContent->FileStream, exportContent->Mode);
    }
    return TRUE;
    case MainTabPageFontChanged:
    {
        HFONT font = (HFONT)Parameter1;

        if (CallbackTreeNewHandle)
            SendMessage(CallbackTreeNewHandle, WM_SETFONT, (WPARAM)Parameter1, TRUE);
    }
    break;
    }

    return FALSE;
}

BOOLEAN EtpCallbackNodeHashtableEqualFunction(
    _In_ PVOID Entry1,
    _In_ PVOID Entry2
)
{
    PET_CALLBACK_NODE callbackNode1 = *(PET_CALLBACK_NODE *)Entry1;
    PET_CALLBACK_NODE callbackNode2 = *(PET_CALLBACK_NODE *)Entry2;

    return callbackNode1->CallbackItem == callbackNode2->CallbackItem;
}

ULONG EtpCallbackNodeHashtableHashFunction(
    _In_ PVOID Entry
)
{
    return PhHashIntPtr((ULONG_PTR)(*(PET_CALLBACK_NODE *)Entry)->CallbackItem);
}

VOID EtInitializeCallbackTreeList(
    _In_ HWND hwnd
)
{
    CallbackTreeNewHandle = hwnd;
    PhSetControlTheme(CallbackTreeNewHandle, L"explorer");
    SendMessage(TreeNew_GetTooltips(CallbackTreeNewHandle), TTM_SETDELAYTIME, TTDT_AUTOPOP, 0x7fff);

    TreeNew_SetCallback(hwnd, EtpCallbackTreeNewCallback, NULL);

    TreeNew_SetRedraw(hwnd, FALSE);

    // Default columns
    PhAddTreeNewColumn(hwnd, ETCBTNC_CALLBACKADDRESS, TRUE, L"Callback Address", 300, PH_ALIGN_LEFT, 0, 0);
    PhAddTreeNewColumn(hwnd, ETCBTNC_TYPE, TRUE, L"Type", 100, PH_ALIGN_LEFT, 1, DT_PATH_ELLIPSIS);
    PhAddTreeNewColumnEx(hwnd, ETCBTNC_IMAGENAME, TRUE, L"Image", 400, PH_ALIGN_LEFT, 2, DT_LEFT | DT_PATH_ELLIPSIS, TRUE);

    TreeNew_SetRedraw(hwnd, TRUE);

    TreeNew_SetSort(hwnd, ETCBTNC_TYPE, DescendingSortOrder);

    EtLoadSettingsCallbackTreeList();

    PhInitializeTreeNewFilterSupport(&FilterSupport, hwnd, CallbackNodeList);

    if (ToolStatusInterface)
    {
        PhRegisterCallback(ToolStatusInterface->SearchChangedEvent, EtpCallbackSearchChangedHandler, NULL, &SearchChangedRegistration);
        PhAddTreeNewFilter(&FilterSupport, EtpSearchCallbackListFilterCallback, NULL);
    }
}

VOID EtLoadSettingsCallbackTreeList(
    VOID
)
{
    PH_INTEGER_PAIR sortSettings;

    PhCmLoadSettings(CallbackTreeNewHandle, &PhaGetStringSetting(SETTING_NAME_CALLBACK_TREE_LIST_COLUMNS)->sr);

    sortSettings = PhGetIntegerPairSetting(SETTING_NAME_CALLBACK_TREE_LIST_SORT);
    TreeNew_SetSort(CallbackTreeNewHandle, (ULONG)sortSettings.X, (PH_SORT_ORDER)sortSettings.Y);
}

VOID EtSaveSettingsCallbackTreeList(
    VOID
)
{
    PPH_STRING settings;
    PH_INTEGER_PAIR sortSettings;
    ULONG sortColumn;
    PH_SORT_ORDER sortOrder;

    if (!CallbackTreeNewCreated)
        return;

    settings = PH_AUTO(PhCmSaveSettings(CallbackTreeNewHandle));
    PhSetStringSetting2(SETTING_NAME_CALLBACK_TREE_LIST_COLUMNS, &settings->sr);

    TreeNew_GetSort(CallbackTreeNewHandle, &sortColumn, &sortOrder);
    sortSettings.X = sortColumn;
    sortSettings.Y = sortOrder;
    PhSetIntegerPairSetting(SETTING_NAME_CALLBACK_TREE_LIST_SORT, sortSettings);
}

PET_CALLBACK_NODE EtAddCallbackNode(
    _In_ PET_CALLBACK_ITEM CallbackItem
)
{
    PET_CALLBACK_NODE callbackNode;

    callbackNode = PhAllocate(sizeof(ET_CALLBACK_NODE));
    memset(callbackNode, 0, sizeof(ET_CALLBACK_NODE));
    PhInitializeTreeNewNode(&callbackNode->Node);

    PhSetReference(&callbackNode->CallbackItem, CallbackItem);

    memset(callbackNode->TextCache, 0, sizeof(PH_STRINGREF) * ETCBTNC_MAXIMUM);
    callbackNode->Node.TextCache = callbackNode->TextCache;
    callbackNode->Node.TextCacheSize = ETCBTNC_MAXIMUM;

    PhAddEntryHashtable(CallbackNodeHashtable, &callbackNode);
    PhAddItemList(CallbackNodeList, callbackNode);

    if (FilterSupport.NodeList)
        callbackNode->Node.Visible = PhApplyTreeNewFiltersToNode(&FilterSupport, &callbackNode->Node);

    TreeNew_NodesStructured(CallbackTreeNewHandle);

    return callbackNode;
}

PET_CALLBACK_NODE EtFindCallbackNode(
    _In_ PET_CALLBACK_ITEM CallbackItem
)
{
    ET_CALLBACK_NODE lookupCallbackNode;
    PET_CALLBACK_NODE lookupCallbackNodePtr = &lookupCallbackNode;
    PET_CALLBACK_NODE *callbackNode;

    lookupCallbackNode.CallbackItem = CallbackItem;

    callbackNode = (PET_CALLBACK_NODE *)PhFindEntryHashtable(
        CallbackNodeHashtable,
        &lookupCallbackNodePtr
    );

    if (callbackNode)
        return *callbackNode;
    else
        return NULL;
}

VOID EtRemoveCallbackNode(
    _In_ PET_CALLBACK_NODE CallbackNode
)
{
    ULONG index;

    // Remove from the hashtable/list and cleanup.

    PhRemoveEntryHashtable(CallbackNodeHashtable, &CallbackNode);

    if ((index = PhFindItemList(CallbackNodeList, CallbackNode)) != -1)
        PhRemoveItemList(CallbackNodeList, index);

    if (CallbackNode->TooltipText) PhDereferenceObject(CallbackNode->TooltipText);

    PhDereferenceObject(CallbackNode->CallbackItem);

    PhFree(CallbackNode);

    TreeNew_NodesStructured(CallbackTreeNewHandle);
}

VOID EtUpdateCallbackNode(
    _In_ PET_CALLBACK_NODE CallbackNode
)
{
    memset(CallbackNode->TextCache, 0, sizeof(PH_STRINGREF) * ETCBTNC_MAXIMUM);

    PhInvalidateTreeNewNode(&CallbackNode->Node, TN_CACHE_ICON);
    TreeNew_NodesStructured(CallbackTreeNewHandle);
}

#define SORT_FUNCTION(Column) EtpCallbackTreeNewCompare##Column

#define BEGIN_SORT_FUNCTION(Column) static int __cdecl EtpCallbackTreeNewCompare##Column( \
    _In_ const void *_elem1, \
    _In_ const void *_elem2 \
    ) \
{ \
    PET_CALLBACK_NODE node1 = *(PET_CALLBACK_NODE *)_elem1; \
    PET_CALLBACK_NODE node2 = *(PET_CALLBACK_NODE *)_elem2; \
    PET_CALLBACK_ITEM callbackItem1 = node1->CallbackItem; \
    PET_CALLBACK_ITEM callbackItem2 = node2->CallbackItem; \
    int sortResult = 0;

#define END_SORT_FUNCTION \
    if (sortResult == 0) \
        sortResult = PhCompareString(callbackItem1->ImageNameWin32, callbackItem2->ImageNameWin32, TRUE); \
    \
    return PhModifySort(sortResult, CallbackTreeNewSortOrder); \
}

BEGIN_SORT_FUNCTION(CallbackAddress)
{
    sortResult = uintptrcmp((ULONG_PTR)callbackItem1->CallbackAddress, (ULONG_PTR)callbackItem2->CallbackAddress);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(Type)
{
    sortResult = uint64cmp(callbackItem1->Type, callbackItem2->Type);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(ImageNameWin32)
{
    sortResult = PhCompareString(callbackItem1->ImageNameWin32, callbackItem2->ImageNameWin32, TRUE);
}
END_SORT_FUNCTION

BOOLEAN NTAPI EtpCallbackTreeNewCallback(
    _In_ HWND hwnd,
    _In_ PH_TREENEW_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2,
    _In_opt_ PVOID Context
)
{
    PET_CALLBACK_NODE node;

    switch (Message)
    {
    case TreeNewGetChildren:
    {
        PPH_TREENEW_GET_CHILDREN getChildren = Parameter1;

        if (!getChildren->Node)
        {
            static PVOID sortFunctions[] =
            {
                SORT_FUNCTION(CallbackAddress),
                SORT_FUNCTION(Type),
                SORT_FUNCTION(ImageNameWin32)
            };
            int(__cdecl *sortFunction)(const void *, const void *);

            if (CallbackTreeNewSortColumn < ETCBTNC_MAXIMUM)
                sortFunction = sortFunctions[CallbackTreeNewSortColumn];
            else
                sortFunction = NULL;

            if (sortFunction)
            {
                qsort(CallbackNodeList->Items, CallbackNodeList->Count, sizeof(PVOID), sortFunction);
            }

            getChildren->Children = (PPH_TREENEW_NODE *)CallbackNodeList->Items;
            getChildren->NumberOfChildren = CallbackNodeList->Count;
        }
    }
    return TRUE;
    case TreeNewIsLeaf:
    {
        PPH_TREENEW_IS_LEAF isLeaf = Parameter1;

        isLeaf->IsLeaf = TRUE;
    }
    return TRUE;
    case TreeNewGetCellText:
    {
        PPH_TREENEW_GET_CELL_TEXT getCellText = Parameter1;

        node = (PET_CALLBACK_NODE)getCellText->Node;
        PET_CALLBACK_ITEM callbackItem = node->CallbackItem;

        switch (getCellText->Id)
        {
        case ETCBTNC_CALLBACKADDRESS:
            getCellText->Text = PhGetStringRef(callbackItem->CallbackAddressString);
            break;
        case ETCBTNC_TYPE:
            switch (callbackItem->Type)
            {
            case KphCallbackPsCreateProcess:
                PhInitializeStringRef(&getCellText->Text, L"CreateProcess");
                break;
            case KphCallbackPsCreateThread:
                PhInitializeStringRef(&getCellText->Text, L"CreateThread");
                break;
            case KphCallbackPsLoadImage:
                PhInitializeStringRef(&getCellText->Text, L"LoadImage");
                break;
            default:
                PhInitializeStringRef(&getCellText->Text, L"Unknown");
                break;
            }
            break;
        case ETCBTNC_IMAGENAME:
            getCellText->Text = PhGetStringRef(callbackItem->ImageNameWin32);
            break;
        break;
        default:
            return FALSE;
        }

        getCellText->Flags = TN_CACHE;
    }
    return TRUE;
    case TreeNewGetNodeIcon:
    {
        return FALSE;
    }
    return TRUE;
    case TreeNewGetCellTooltip:
    {
        PPH_TREENEW_GET_CELL_TOOLTIP getCellTooltip = Parameter1;
       // PPH_PROCESS_NODE processNode;

        node = (PET_CALLBACK_NODE)getCellTooltip->Node;

        if (getCellTooltip->Column->Id != 0)
            return FALSE;

        /*if (!node->TooltipText)
        {
            if (processNode = PhFindProcessNode(node->CallbackItem->ProcessId))
            {
                PPH_TREENEW_CALLBACK callback;
                PVOID callbackContext;
                PPH_TREENEW_COLUMN fixedColumn;
                PH_TREENEW_GET_CELL_TOOLTIP fakeGetCellTooltip;

                // HACK: Get the tooltip text by using the treenew callback of the process tree.
                if (TreeNew_GetCallback(ProcessTreeNewHandle, &callback, &callbackContext) &&
                    (fixedColumn = TreeNew_GetFixedColumn(ProcessTreeNewHandle)))
                {
                    fakeGetCellTooltip.Flags = 0;
                    fakeGetCellTooltip.Node = &processNode->Node;
                    fakeGetCellTooltip.Column = fixedColumn;
                    fakeGetCellTooltip.Unfolding = FALSE;
                    PhInitializeEmptyStringRef(&fakeGetCellTooltip.Text);
                    fakeGetCellTooltip.Font = getCellTooltip->Font;
                    fakeGetCellTooltip.MaximumWidth = getCellTooltip->MaximumWidth;

                    if (callback(ProcessTreeNewHandle, TreeNewGetCellTooltip, &fakeGetCellTooltip, NULL, callbackContext))
                    {
                        node->TooltipText = PhCreateString2(&fakeGetCellTooltip.Text);
                    }
                }
            }
        }*/

        if (!PhIsNullOrEmptyString(node->TooltipText))
        {
            getCellTooltip->Text = node->TooltipText->sr;
            getCellTooltip->Unfolding = FALSE;
            getCellTooltip->MaximumWidth = -1;
        }
        else
        {
            return FALSE;
        }
    }
    return TRUE;
    case TreeNewSortChanged:
    {
        TreeNew_GetSort(hwnd, &CallbackTreeNewSortColumn, &CallbackTreeNewSortOrder);
        // Force a rebuild to sort the items.
        TreeNew_NodesStructured(hwnd);
    }
    return TRUE;
    case TreeNewKeyDown:
    {
        PPH_TREENEW_KEY_EVENT keyEvent = Parameter1;

        switch (keyEvent->VirtualKey)
        {
        case 'C':
            if (GetKeyState(VK_CONTROL) < 0)
                //EtHandleDiskCommand(ID_DISK_COPY);
            break;
        case 'A':
            if (GetKeyState(VK_CONTROL) < 0)
                TreeNew_SelectRange(CallbackTreeNewHandle, 0, -1);
            break;
        case VK_RETURN:
            //EtHandleDiskCommand(ID_DISK_OPENFILELOCATION);
            break;
        }
    }
    return TRUE;
    case TreeNewHeaderRightClick:
    {
        PH_TN_COLUMN_MENU_DATA data;

        data.TreeNewHandle = hwnd;
        data.MouseEvent = Parameter1;
        data.DefaultSortColumn = 0;
        data.DefaultSortOrder = AscendingSortOrder;
        PhInitializeTreeNewColumnMenu(&data);

        data.Selection = PhShowEMenu(data.Menu, hwnd, PH_EMENU_SHOW_LEFTRIGHT,
            PH_ALIGN_LEFT | PH_ALIGN_TOP, data.MouseEvent->ScreenLocation.x, data.MouseEvent->ScreenLocation.y);
        PhHandleTreeNewColumnMenu(&data);
        PhDeleteTreeNewColumnMenu(&data);
    }
    return TRUE;
    case TreeNewLeftDoubleClick:
    {
        //EtHandleDiskCommand(ID_DISK_OPENFILELOCATION);
    }
    return TRUE;
    case TreeNewContextMenu:
    {
        PPH_TREENEW_CONTEXT_MENU contextMenuEvent = Parameter1;

       // EtShowDiskContextMenu(hwnd, contextMenuEvent);
    }
    return TRUE;
    case TreeNewDestroying:
    {
        EtSaveSettingsCallbackTreeList();
    }
    return TRUE;
    }

    return FALSE;
}

PET_CALLBACK_ITEM EtGetSelectedCallbackItem(
    VOID
)
{
    PET_CALLBACK_ITEM callbackItem = NULL;
    ULONG i;

    for (i = 0; i < CallbackNodeList->Count; i++)
    {
        PET_CALLBACK_NODE node = CallbackNodeList->Items[i];

        if (node->Node.Selected)
        {
            callbackItem = node->CallbackItem;
            break;
        }
    }

    return callbackItem;
}

VOID EtGetSelectedCallbackItems(
    _Out_ PET_CALLBACK_ITEM **CallbackItems,
    _Out_ PULONG NumberOfCallbackItems
)
{
    PPH_LIST list;
    ULONG i;

    list = PhCreateList(2);

    for (i = 0; i < CallbackNodeList->Count; i++)
    {
        PET_CALLBACK_NODE node = CallbackNodeList->Items[i];

        if (node->Node.Selected)
        {
            PhAddItemList(list, node->CallbackItem);
        }
    }

    *CallbackItems = PhAllocateCopy(list->Items, sizeof(PVOID) * list->Count);
    *NumberOfCallbackItems = list->Count;

    PhDereferenceObject(list);
}

VOID EtDeselectAllCallbackNodes(
    VOID
)
{
    TreeNew_DeselectRange(CallbackTreeNewHandle, 0, -1);
}

VOID EtSelectAndEnsureVisibleCallbackNode(
    _In_ PET_CALLBACK_NODE CallbackNode
)
{
    EtDeselectAllCallbackNodes();

    if (!CallbackNode->Node.Visible)
        return;

    TreeNew_SetFocusNode(CallbackTreeNewHandle, &CallbackNode->Node);
    TreeNew_SetMarkNode(CallbackTreeNewHandle, &CallbackNode->Node);
    TreeNew_SelectRange(CallbackTreeNewHandle, CallbackNode->Node.Index, CallbackNode->Node.Index);
    TreeNew_EnsureVisible(CallbackTreeNewHandle, &CallbackNode->Node);
}

VOID EtCopyCallbackList(
    VOID
)
{
    PPH_STRING text;

    text = PhGetTreeNewText(CallbackTreeNewHandle, 0);
    PhSetClipboardString(CallbackTreeNewHandle, &text->sr);
    PhDereferenceObject(text);
}

VOID EtWriteCallbackList(
    _Inout_ PPH_FILE_STREAM FileStream,
    _In_ ULONG Mode
)
{
    PPH_LIST lines;
    ULONG i;

    lines = PhGetGenericTreeNewLines(CallbackTreeNewHandle, Mode);

    for (i = 0; i < lines->Count; i++)
    {
        PPH_STRING line;

        line = lines->Items[i];
        PhWriteStringAsUtf8FileStream(FileStream, &line->sr);
        PhDereferenceObject(line);
        PhWriteStringAsUtf8FileStream2(FileStream, L"\r\n");
    }

    PhDereferenceObject(lines);
}

VOID EtHandleCallbackCommand(
    _In_ ULONG Id
)
{
    /*switch (Id)
    {
    case ID_CALLBACK_GOTOPROCESS:
    {
        PET_CALLBACK_ITEM callbackItem = EtGetSelectedCallbackItem();
        PPH_PROCESS_NODE processNode;

        if (callbackItem)
        {
            PhReferenceObject(callbackItem);

            if (callbackItem->ProcessRecord)
            {
                // Check if this is really the process that we want, or if it's just a case of PID re-use.
                if ((processNode = PhFindProcessNode(callbackItem->ProcessId)) &&
                    processNode->ProcessItem->CreateTime.QuadPart == callbackItem->ProcessRecord->CreateTime.QuadPart)
                {
                    ProcessHacker_SelectTabPage(PhMainWndHandle, 0);
                    PhSelectAndEnsureVisibleProcessNode(processNode);
                }
                else
                {
                    PhShowProcessRecordDialog(PhMainWndHandle, callbackItem->ProcessRecord);
                }
            }
            else
            {
                PhShowError(PhMainWndHandle, L"The process does not exist.");
            }

            PhDereferenceObject(callbackItem);
        }
    }
    break;
    case ID_CALLBACK_OPENFILELOCATION:
    {
        PET_CALLBACK_ITEM callbackItem = EtGetSelectedCallbackItem();

        if (callbackItem)
        {
            PhShellExploreFile(PhMainWndHandle, callbackItem->FileNameWin32->Buffer);
        }
    }
    break;
    case ID_CALLBACK_COPY:
    {
        EtCopyDiskList();
    }
    break;
    case ID_CALLBACK_PROPERTIES:
    {
        PET_CALLBACK_ITEM callbackItem = EtGetSelectedCallbackItem();

        if (callbackItem)
        {
            PhShellProperties(PhMainWndHandle, callbackItem->FileNameWin32->Buffer);
        }
    }
    break;
    }*/
}

VOID EtpInitializeCallbackMenu(
    _In_ PPH_EMENU Menu,
    _In_ PET_CALLBACK_ITEM *CallbackItems,
    _In_ ULONG NumberOfCallbackItems
)
{
    /*PPH_EMENU_ITEM item;

    if (NumberOfCallbackItems == 0)
    {
        PhSetFlagsAllEMenuItems(Menu, PH_EMENU_DISABLED, PH_EMENU_DISABLED);
    }
    else if (NumberOfCallbackItems == 1)
    {
        PPH_PROCESS_ITEM processItem;

        // If we have a process record and the process has terminated, we can only show
        // process properties.
        if (CallbackItems[0]->ProcessRecord)
        {
            if (processItem = PhReferenceProcessItemForRecord(CallbackItems[0]->ProcessRecord))
            {
                PhDereferenceObject(processItem);
            }
            else
            {
                if (item = PhFindEMenuItem(Menu, 0, NULL, ID_CALLBACK_GOTOPROCESS))
                {
                    item->Text = L"Process Properties";
                    item->Flags &= ~PH_EMENU_TEXT_OWNED;
                }
            }
        }
    }
    else
    {
        PhSetFlagsAllEMenuItems(Menu, PH_EMENU_DISABLED, PH_EMENU_DISABLED);
        PhEnableEMenuItem(Menu, ID_CALLBACK_COPY, TRUE);
    }*/
}

VOID EtShowCallbackContextMenu(
    _In_ HWND TreeWindowHandle,
    _In_ PPH_TREENEW_CONTEXT_MENU ContextMenuEvent
)
{
    /*PET_CALLBACK_ITEM *callbackItems;
    ULONG numberOfCallbackItems;

    EtGetSelectedCallbackItems(&callbackItems, &numberOfCallbackItems);

    if (numberOfCallbackItems != 0)
    {
        PPH_EMENU menu;
        PPH_EMENU_ITEM item;

        menu = PhCreateEMenu();
        PhLoadResourceEMenuItem(menu, PluginInstance->DllBase, MAKEINTRESOURCE(IDR_CALLBACK), 0);
        PhInsertCopyCellEMenuItem(menu, ID_CALLBACK_COPY, TreeWindowHandle, ContextMenuEvent->Column);
        PhSetFlagsEMenuItem(menu, ID_CALLBACK_OPENFILELOCATION, PH_EMENU_DEFAULT, PH_EMENU_DEFAULT);

        EtpInitializeDiskMenu(menu, callbackItems, numberOfCallbackItems);

        item = PhShowEMenu(
            menu,
            PhMainWndHandle,
            PH_EMENU_SHOW_LEFTRIGHT,
            PH_ALIGN_LEFT | PH_ALIGN_TOP,
            ContextMenuEvent->Location.x,
            ContextMenuEvent->Location.y
        );

        if (item)
        {
            BOOLEAN handled = FALSE;

            handled = PhHandleCopyCellEMenuItem(item);

            if (!handled)
                EtHandleDiskCommand(item->Id);
        }

        PhDestroyEMenu(menu);
    }

    PhFree(callbackItems);*/
}

VOID NTAPI EtpCallbackItemAddedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    PET_CALLBACK_ITEM callbackItem = (PET_CALLBACK_ITEM)Parameter;

    PhReferenceObject(callbackItem);
    ProcessHacker_Invoke(PhMainWndHandle, EtpOnCallbackItemAdded, callbackItem);
}

VOID NTAPI EtpCallbackItemModifiedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    ProcessHacker_Invoke(PhMainWndHandle, EtpOnCallbackItemModified, (PET_CALLBACK_ITEM)Parameter);
}

VOID NTAPI EtpCallbackItemRemovedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    ProcessHacker_Invoke(PhMainWndHandle, EtpOnCallbackItemRemoved, (PET_CALLBACK_ITEM)Parameter);
}

VOID NTAPI EtpCallbackItemsUpdatedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    ProcessHacker_Invoke(PhMainWndHandle, EtpOnCallbackItemsUpdated, NULL);
}

VOID NTAPI EtpOnCallbackItemAdded(
    _In_ PVOID Parameter
)
{
    PET_CALLBACK_ITEM callbackItem = Parameter;
    PET_CALLBACK_NODE callbackNode;

    if (!CallbackNeedsRedraw)
    {
        TreeNew_SetRedraw(CallbackTreeNewHandle, FALSE);
        CallbackNeedsRedraw = TRUE;
    }

    callbackNode = EtAddCallbackNode(callbackItem);
    PhDereferenceObject(callbackItem);
}

VOID NTAPI EtpOnCallbackItemModified(
    _In_ PVOID Parameter
)
{
    PET_CALLBACK_ITEM callbackItem = Parameter;

    EtUpdateCallbackNode(EtFindCallbackNode(callbackItem));
}

VOID NTAPI EtpOnCallbackItemRemoved(
    _In_ PVOID Parameter
)
{
    PET_CALLBACK_ITEM callbackItem = Parameter;

    if (!CallbackNeedsRedraw)
    {
        TreeNew_SetRedraw(CallbackTreeNewHandle, FALSE);
        CallbackNeedsRedraw = TRUE;
    }

    EtRemoveCallbackNode(EtFindCallbackNode(callbackItem));
}

VOID NTAPI EtpOnCallbackItemsUpdated(
    _In_ PVOID Parameter
)
{
    ULONG i;

    if (CallbackNeedsRedraw)
    {
        TreeNew_SetRedraw(CallbackTreeNewHandle, TRUE);
        CallbackNeedsRedraw = FALSE;
    }

    // Text invalidation

    for (i = 0; i < CallbackNodeList->Count; i++)
    {
        PET_CALLBACK_NODE node = CallbackNodeList->Items[i];

        // The name and file name never change, so we don't invalidate that.
        memset(&node->TextCache[2], 0, sizeof(PH_STRINGREF) * (ETCBTNC_MAXIMUM - 2));
        // Always get the newest tooltip text from the process tree.
        PhClearReference(&node->TooltipText);
    }

    InvalidateRect(CallbackTreeNewHandle, NULL, FALSE);
}

VOID NTAPI EtpCallbackSearchChangedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    if (!EtEtwEnabled)
        return;

    PhApplyTreeNewFilters(&FilterSupport);
}

BOOLEAN NTAPI EtpSearchCallbackListFilterCallback(
    _In_ PPH_TREENEW_NODE Node,
    _In_opt_ PVOID Context
)
{
    PET_CALLBACK_NODE callbackNode = (PET_CALLBACK_NODE)Node;
    PTOOLSTATUS_WORD_MATCH wordMatch = ToolStatusInterface->WordMatch;

    if (PhIsNullOrEmptyString(ToolStatusInterface->GetSearchboxText()))
        return TRUE;

    if (wordMatch(&callbackNode->CallbackItem->ImageNameWin32->sr))
        return TRUE;

    return FALSE;
}

VOID NTAPI EtpCallbackToolStatusActivateContent(
    _In_ BOOLEAN Select
)
{
    SetFocus(CallbackTreeNewHandle);

    if (Select)
    {
        if (TreeNew_GetFlatNodeCount(CallbackTreeNewHandle) > 0)
            EtSelectAndEnsureVisibleCallbackNode((PET_CALLBACK_NODE)TreeNew_GetFlatNode(CallbackTreeNewHandle, 0));
    }
}

HWND NTAPI EtpCallbackToolStatusGetTreeNewHandle(
    VOID
)
{
    return CallbackTreeNewHandle;
}

INT_PTR CALLBACK EtpCallbackTabErrorDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        if (!PhGetOwnTokenAttributes().Elevated)
        {
            Button_SetElevationRequiredState(GetDlgItem(hwndDlg, IDC_RESTART), TRUE);
        }
        else
        {
            PhSetDialogItemText(hwndDlg, IDC_ERROR, L"Unable to get callback information from KProcessHacker.");
            ShowWindow(GetDlgItem(hwndDlg, IDC_RESTART), SW_HIDE);
        }

        PhInitializeWindowTheme(hwndDlg, !!PhGetIntegerSetting(L"EnableThemeSupport"));
    }
    break;
    case WM_COMMAND:
    {
        switch (GET_WM_COMMAND_ID(wParam, lParam))
        {
        case IDC_RESTART:
            ProcessHacker_PrepareForEarlyShutdown(PhMainWndHandle);

            if (PhShellProcessHacker(
                PhMainWndHandle,
                L"-v -selecttab Callback",
                SW_SHOW,
                PH_SHELL_EXECUTE_ADMIN,
                PH_SHELL_APP_PROPAGATE_PARAMETERS | PH_SHELL_APP_PROPAGATE_PARAMETERS_IGNORE_VISIBILITY,
                0,
                NULL
            ))
            {
                ProcessHacker_Destroy(PhMainWndHandle);
            }
            else
            {
                ProcessHacker_CancelEarlyShutdown(PhMainWndHandle);
            }

            break;
        }
    }
    break;
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORSTATIC:
    {
        SetBkMode((HDC)wParam, TRANSPARENT);
        return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);
    }
    break;
    }

    return FALSE;
}

VOID NTAPI RefreshProviderCallback(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    EtGetCallbackInformation();
}
