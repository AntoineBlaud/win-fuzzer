
var sys_data = {"ntdll.dll": {"ZwDeviceIoControlFile": {"args": ["_In_ HANDLE FileHandle", "_In_opt_ HANDLE Event", "_In_opt_ PIO_APC_ROUTINE ApcRoutine", "_In_opt_ PVOID ApcContext", "_Out_ PIO_STATUS_BLOCK IoStatusBlock", "_In_ ULONG IoControlCode", "_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer", "_In_ ULONG InputBufferLength", "_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer", "_In_ ULONG OutputBufferLength"], "addr": 652352}, "ZwReplyWaitReceivePort": {"args": ["_In_ HANDLE PortHandle", "_Out_opt_ PVOID *PortContext", "_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage", "_Out_ PPORT_MESSAGE ReceiveMessage"], "addr": 652480}, "ZwQueryObject": {"args": ["_In_opt_ HANDLE Handle", "_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass", "_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation", "_In_ ULONG ObjectInformationLength", "_Out_opt_ PULONG ReturnLength"], "addr": 652640}, "ZwQueryDefaultLocale": {"args": ["_In_ BOOLEAN UserProfile", "_Out_ PLCID DefaultLocaleId"], "addr": 652800}, "ZwQueryKey": {"args": ["_In_ HANDLE KeyHandle", "_In_ __drv_strictTypeMatch(__drv_typeConst)\nKEY_INFORMATION_CLASS KeyInformationClass", "_Out_writes_bytes_opt_(Length) PVOID KeyInformation", "_In_ ULONG Length", "_Out_ PULONG ResultLength"], "addr": 652832}, "ZwWaitForMultipleObjects32": {"args": ["_In_ ULONG Count", "_In_reads_(Count) LONG Handles[]", "_In_ WAIT_TYPE WaitType", "_In_ BOOLEAN Alertable", "_In_opt_ PLARGE_INTEGER Timeout"], "addr": 652960}, "ZwSetInformationProcess": {"args": ["_In_ HANDLE ProcessHandle", "_In_ PROCESSINFOCLASS ProcessInformationClass", "_In_reads_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation", "_In_ ULONG ProcessInformationLength"], "addr": 653024}, "ZwCreateKey": {"args": ["_Out_ PHANDLE KeyedEventHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes", "_In_ ULONG Flags"], "addr": 653056}, "ZwReleaseMutant": {"args": ["_In_ HANDLE MutantHandle", "_Out_opt_ PLONG PreviousCount"], "addr": 653152}, "ZwQueryInformationThread": {"args": ["_In_ HANDLE ThreadHandle", "_In_ THREADINFOCLASS ThreadInformationClass", "_Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation", "_In_ ULONG ThreadInformationLength", "_Out_opt_ PULONG ReturnLength"], "addr": 653312}, "ZwReadFileScatter": {"args": ["_In_ HANDLE FileHandle", "_In_opt_ HANDLE Event", "_In_opt_ PIO_APC_ROUTINE ApcRoutine", "_In_opt_ PVOID ApcContext", "_Out_ PIO_STATUS_BLOCK IoStatusBlock", "_In_ PFILE_SEGMENT_ELEMENT SegmentArray", "_In_ ULONG Length", "_In_opt_ PLARGE_INTEGER ByteOffset", "_In_opt_ PULONG Key"], "addr": 653600}, "ZwQueryAttributesFile": {"args": ["_In_ POBJECT_ATTRIBUTES ObjectAttributes", "_Out_ PFILE_BASIC_INFORMATION FileInformation"], "addr": 654080}, "ZwOpenEvent": {"args": ["_Out_ PHANDLE EventHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_ POBJECT_ATTRIBUTES ObjectAttributes"], "addr": 654176}, "ZwApphelpCacheControl": {"args": [], "addr": 654560}, "ZwCreateProcessEx": {"args": ["_Out_ PHANDLE ProcessHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes", "_In_ HANDLE ParentProcess", "_In_ ULONG Flags", "_In_opt_ HANDLE SectionHandle", "_In_opt_ HANDLE DebugPort", "_In_opt_ HANDLE TokenHandle", "_In_ ULONG JobMemberLevel"], "addr": 654592}, "ZwSetInformationObject": {"args": ["_In_ HANDLE Handle", "_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass", "_In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation", "_In_ ULONG ObjectInformationLength"], "addr": 655056}, "ZwTraceEvent": {"args": ["_In_opt_ HANDLE TraceHandle", "_In_ ULONG Flags", "_In_ ULONG FieldSize", "_In_ PVOID Fields"], "addr": 655120}, "ZwAccessCheckByTypeResultListAndAuditAlarmByHandle": {"args": ["_In_ PUNICODE_STRING SubsystemName", "_In_opt_ PVOID HandleId", "_In_ HANDLE ClientToken", "_In_ PUNICODE_STRING ObjectTypeName", "_In_ PUNICODE_STRING ObjectName", "_In_ PSECURITY_DESCRIPTOR SecurityDescriptor", "_In_opt_ PSID PrincipalSelfSid", "_In_ ACCESS_MASK DesiredAccess", "_In_ AUDIT_EVENT_TYPE AuditType", "_In_ ULONG Flags", "_In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList", "_In_ ULONG ObjectTypeListLength", "_In_ PGENERIC_MAPPING GenericMapping", "_In_ BOOLEAN ObjectCreation", "_Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccess", "_Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatus", "_Out_ PBOOLEAN GenerateOnClose"], "addr": 655376}, "ZwAcquireCrossVmMutant": {"args": [], "addr": 655408}, "ZwAddDriverEntry": {"args": ["_In_ PEFI_DRIVER_ENTRY DriverEntry", "_Out_opt_ PULONG Id"], "addr": 655536}, "ZwAlertResumeThread": {"args": ["_In_ HANDLE ThreadHandle", "_Out_opt_ PULONG PreviousSuspendCount"], "addr": 655632}, "ZwAlpcCreateResourceReserve": {"args": ["_In_ HANDLE PortHandle", "_Reserved_ ULONG Flags", "_In_ SIZE_T MessageSize", "_Out_ PULONG ResourceId"], "addr": 656112}, "ZwAlpcDeletePortSection": {"args": ["_In_ HANDLE PortHandle", "_Reserved_ ULONG Flags", "_In_ ALPC_HANDLE SectionHandle"], "addr": 656208}, "ZwAlpcImpersonateClientOfPort": {"args": ["_In_ HANDLE PortHandle", "_In_ PPORT_MESSAGE Message", "_In_ PVOID Flags"], "addr": 656400}, "ZwAlpcQueryInformation": {"args": ["_In_opt_ HANDLE PortHandle", "_In_ __drv_strictTypeMatch(__drv_typeConst) ALPC_PORT_INFORMATION_CLASS PortInformationClass", "_Inout_updates_bytes_to_(Length,*ReturnLength) PVOID PortInformation", "_In_ ULONG Length", "_Out_opt_ PULONG ReturnLength"], "addr": 656496}, "ZwAreMappedFilesTheSame": {"args": ["_In_ PVOID File1MappedAsAnImage", "_In_ PVOID File2MappedAsFile"], "addr": 656656}, "ZwAssignProcessToJobObject": {"args": ["_In_ HANDLE JobHandle", "_In_ HANDLE ProcessHandle"], "addr": 656688}, "ZwCancelIoFileEx": {"args": ["_In_ HANDLE FileHandle", "_In_opt_ PIO_STATUS_BLOCK IoRequestToCancel", "_Out_ PIO_STATUS_BLOCK IoStatusBlock"], "addr": 656784}, "ZwCancelSynchronousIoFile": {"args": ["_In_ HANDLE ThreadHandle", "_In_opt_ PIO_STATUS_BLOCK IoRequestToCancel", "_Out_ PIO_STATUS_BLOCK IoStatusBlock"], "addr": 656816}, "ZwChangeProcessState": {"args": [], "addr": 656912}, "ZwChangeThreadState": {"args": [], "addr": 656944}, "ZwCompactKeys": {"args": ["_In_ ULONG Count", "_In_reads_(Count) HANDLE KeyArray[]"], "addr": 657104}, "ZwCompareSigningLevels": {"args": [], "addr": 657168}, "ZwCompleteConnectPort": {"args": ["_In_ HANDLE PortHandle"], "addr": 657232}, "ZwConnectPort": {"args": ["_Out_ PHANDLE PortHandle", "_In_ PUNICODE_STRING PortName", "_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos", "_Inout_opt_ PPORT_VIEW ClientView", "_Inout_opt_ PREMOTE_PORT_VIEW ServerView", "_Out_opt_ PULONG MaxMessageLength", "_Inout_updates_bytes_to_opt_(*ConnectionInformationLength,*ConnectionInformationLength)", "PVOID ConnectionInformation", "_Inout_opt_ PULONG ConnectionInformationLength"], "addr": 657296}, "ZwContinueEx": {"args": [], "addr": 657328}, "ZwCreateEventPair": {"args": ["_Out_ PHANDLE EventPairHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes"], "addr": 657680}, "ZwCreateMailslotFile": {"args": ["_Out_ PHANDLE FileHandle", "_In_ ULONG DesiredAccess", "_In_ POBJECT_ATTRIBUTES ObjectAttributes", "_Out_ PIO_STATUS_BLOCK IoStatusBlock", "_In_ ULONG CreateOptions", "_In_ ULONG MailslotQuota", "_In_ ULONG MaximumMessageSize", "_In_ PLARGE_INTEGER ReadTimeout"], "addr": 657968}, "ZwCreatePartition": {"args": ["_In_opt_ HANDLE ParentPartitionHandle", "_Out_ PHANDLE PartitionHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes", "_In_ ULONG PreferredNode"], "addr": 658096}, "ZwCreatePort": {"args": ["_Out_ PHANDLE PortHandle", "_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes", "_In_ ULONG MaxConnectionInfoLength", "_In_ ULONG MaxMessageLength", "_In_opt_ ULONG MaxPoolUsage"], "addr": 658128}, "ZwCreateTimer2": {"args": ["_Out_ PHANDLE TimerHandle", "_In_opt_ PVOID Reserved1", "_In_opt_ PVOID Reserved2", "_In_ ULONG Attributes", "_In_ ACCESS_MASK DesiredAccess"], "addr": 658576}, "ZwCreateWnfStateName": {"args": ["_Out_ PWNF_STATE_NAME StateName", "_In_ WNF_STATE_NAME_LIFETIME NameLifetime", "_In_ WNF_DATA_SCOPE DataScope", "_In_ BOOLEAN PersistData", "_In_opt_ PCWNF_TYPE_ID TypeId", "_In_ ULONG MaximumStateSize", "_In_ PSECURITY_DESCRIPTOR SecurityDescriptor"], "addr": 658832}, "ZwDeleteDriverEntry": {"args": ["_In_ ULONG Id"], "addr": 659024}, "ZwDeletePrivateNamespace": {"args": ["_In_ HANDLE NamespaceHandle"], "addr": 659152}, "ZwDeleteValueKey": {"args": ["_In_ HANDLE KeyHandle", "_In_ PUNICODE_STRING ValueName"], "addr": 659184}, "ZwDisplayString": {"args": ["_In_ PUNICODE_STRING String"], "addr": 659344}, "ZwEnumerateDriverEntries": {"args": ["_Out_writes_bytes_opt_(*BufferLength) PVOID Buffer", "_Inout_ PULONG BufferLength"], "addr": 659472}, "ZwExtendSection": {"args": ["_In_ HANDLE SectionHandle", "_Inout_ PLARGE_INTEGER NewSectionSize"], "addr": 659568}, "ZwFlushKey": {"args": ["_In_ HANDLE KeyHandle"], "addr": 659792}, "ZwGetCompleteWnfStateSubscription": {"args": ["_In_opt_ PWNF_STATE_NAME OldDescriptorStateName", "_In_opt_ ULONG64 *OldSubscriptionId", "_In_opt_ ULONG OldDescriptorEventMask", "_In_opt_ ULONG OldDescriptorStatus", "_Out_writes_bytes_(DescriptorSize) PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor", "_In_ ULONG DescriptorSize"], "addr": 660048}, "ZwGetCurrentProcessorNumber": {"args": ["_Out_ PPROCESSOR_NUMBER ProcNumber"], "addr": 660112}, "ZwGetCurrentProcessorNumberEx": {"args": ["_Out_ PPROCESSOR_NUMBER ProcNumber"], "addr": 660144}, "ZwGetMUIRegistryInfo": {"args": ["_In_ ULONG Flags", "_Inout_opt_ ULONG *DataSize", "_Inout_updates_bytes_opt_(*DataSize) PVOID Data"], "addr": 660208}, "ZwInitializeNlsFiles": {"args": ["_Outptr_result_bytebuffer_(sizeof(NLS_MAIN_TABLE_OFFSET)) PVOID *BaseAddress", "_Out_ PLCID DefaultLocaleId", "_Out_ PLARGE_INTEGER DefaultCasingTableSize"], "addr": 660496}, "ZwIsSystemResumeAutomatic": {"args": [], "addr": 660592}, "ZwLoadKeyEx": {"args": ["_In_ POBJECT_ATTRIBUTES   TargetKey", "_In_ POBJECT_ATTRIBUTES   SourceFile", "_In_ ULONG         Flags", "_In_opt_ HANDLE       TrustClassKey", "_In_opt_ HANDLE       Event", "_In_opt_ ACCESS_MASK    DesiredAccess", "_Out_opt_ PHANDLE      RootHandle", "_Out_opt_ PIO_STATUS_BLOCK IoStatus"], "addr": 660848}, "ZwLockRegistryKey": {"args": ["_In_ HANDLE      KeyHandle"], "addr": 660944}, "ZwManageHotPatch": {"args": [], "addr": 661072}, "ZwManagePartition": {"args": ["_In_ HANDLE TargetHandle", "_In_opt_ HANDLE SourceHandle", "_In_ MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass", "_In_ PVOID PartitionInformation", "_In_ ULONG PartitionInformationLength"], "addr": 661104}, "ZwMapCMFModule": {"args": ["_In_ ULONG What", "_In_ ULONG Index", "_Out_opt_ ULONG *CacheIndexOut", "_Out_opt_ ULONG *CacheFlagsOut", "_Out_opt_ ULONG *ViewSizeOut", "_Out_opt_ PVOID *BaseAddress"], "addr": 661136}, "ZwMapViewOfSectionEx": {"args": [], "addr": 661200}, "ZwModifyBootEntry": {"args": ["_In_ PBOOT_ENTRY BootEntry"], "addr": 661232}, "ZwNotifyChangeSession": {"args": ["_In_ HANDLE SessionHandle", "_In_ ULONG ChangeSequenceNumber", "_In_ PLARGE_INTEGER ChangeTimeStamp", "_In_ IO_SESSION_EVENT Event", "_In_ IO_SESSION_STATE NewState", "_In_ IO_SESSION_STATE PreviousState", "_In_reads_bytes_opt_(PayloadSize) PVOID Payload", "_In_ ULONG PayloadSize"], "addr": 661424}, "ZwOpenCpuPartition": {"args": [], "addr": 661456}, "ZwOpenEventPair": {"args": ["_Out_ PHANDLE EventPairHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_ POBJECT_ATTRIBUTES ObjectAttributes"], "addr": 661520}, "ZwOpenMutant": {"args": ["_Out_ PHANDLE MutantHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_ POBJECT_ATTRIBUTES ObjectAttributes"], "addr": 661744}, "ZwOpenObjectAuditAlarm": {"args": ["_In_ PUNICODE_STRING SubsystemName", "_In_opt_ PVOID HandleId", "_In_ PUNICODE_STRING ObjectTypeName", "_In_ PUNICODE_STRING ObjectName", "_In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor", "_In_ HANDLE ClientToken", "_In_ ACCESS_MASK DesiredAccess", "_In_ ACCESS_MASK GrantedAccess", "_In_opt_ PPRIVILEGE_SET Privileges", "_In_ BOOLEAN ObjectCreation", "_In_ BOOLEAN AccessGranted", "_Out_ PBOOLEAN GenerateOnClose"], "addr": 661776}, "ZwOpenThread": {"args": ["_Out_ PHANDLE ThreadHandle", "_In_ ACCESS_MASK DesiredAccess", "_In_ POBJECT_ATTRIBUTES ObjectAttributes", "_In_opt_ PCLIENT_ID ClientId"], "addr": 662064}, "ZwPrivilegedServiceAuditAlarm": {"args": ["_In_ PUNICODE_STRING SubsystemName", "_In_ PUNICODE_STRING ServiceName", "_In_ HANDLE ClientToken", "_In_ PPRIVILEGE_SET Privileges", "_In_ BOOLEAN AccessGranted"], "addr": 662416}, "ZwQueryDirectoryObject": {"args": ["_In_ HANDLE DirectoryHandle", "_Out_writes_bytes_opt_(Length) PVOID Buffer", "_In_ ULONG Length", "_In_ BOOLEAN ReturnSingleEntry", "_In_ BOOLEAN RestartScan", "_Inout_ PULONG Context", "_Out_opt_ PULONG ReturnLength"], "addr": 662736}, "ZwQueryFullAttributesFile": {"args": ["_In_ POBJECT_ATTRIBUTES ObjectAttributes", "_Out_ PFILE_NETWORK_OPEN_INFORMATION FileInformation"], "addr": 662832}, "ZwQuerySystemEnvironmentValue": {"args": ["_In_ PUNICODE_STRING VariableName", "_Out_writes_bytes_(ValueLength) PWSTR VariableValue", "_In_ USHORT ValueLength", "_Out_opt_ PUSHORT ReturnLength"], "addr": 663696}, "ZwQueryWnfStateNameInformation": {"args": ["_In_ PCWNF_STATE_NAME StateName", "_In_ WNF_STATE_NAME_INFORMATION NameInfoClass", "_In_opt_ const PVOID ExplicitScope", "_Out_writes_bytes_(InfoBufferSize) PVOID InfoBuffer", "_In_ ULONG InfoBufferSize"], "addr": 663856}, "ZwRecoverEnlistment": {"args": ["_In_ HANDLE EnlistmentHandle", "_In_opt_ PVOID EnlistmentKey"], "addr": 664080}, "ZwReleaseWorkerFactoryWorker": {"args": [], "addr": 664272}, "ZwRenameKey": {"args": ["_In_ HANDLE      KeyHandle", "_In_ PUNICODE_STRING NewName"], "addr": 664368}, "ZwRenameTransactionManager": {"args": ["_In_ PUNICODE_STRING LogFileName", "_In_ LPGUID ExistingTransactionManagerGuid"], "addr": 664400}, "ZwRestoreKey": {"args": ["_In_ HANDLE KeyHandle", "_In_opt_ HANDLE FileHandle", "_In_ ULONG Flags"], "addr": 664624}, "ZwRollbackEnlistment": {"args": ["_In_ HANDLE EnlistmentHandle", "_In_opt_ PLARGE_INTEGER TmVirtualClock"], "addr": 664752}, "ZwSaveMergedKeys": {"args": ["_In_ HANDLE HighPrecedenceKeyHandle", "_In_ HANDLE LowPrecedenceKeyHandle", "_In_ HANDLE FileHandle"], "addr": 664944}, "ZwSetDefaultHardErrorPort": {"args": ["_In_ HANDLE DefaultHardErrorPort"], "addr": 665232}, "ZwSetEaFile": {"args": ["_In_ HANDLE FileHandle", "_Out_ PIO_STATUS_BLOCK IoStatusBlock", "_In_reads_bytes_(Length) PVOID Buffer", "_In_ ULONG Length"], "addr": 665360}, "ZwSetInformationIoRing": {"args": [], "addr": 665584}, "ZwSetInformationJobObject": {"args": ["_In_ HANDLE JobHandle", "_In_ JOBOBJECTINFOCLASS JobObjectInformationClass", "_In_reads_bytes_(JobObjectInformationLength) PVOID JobObjectInformation", "_In_ ULONG JobObjectInformationLength"], "addr": 665616}, "ZwSetInformationTransaction": {"args": ["_In_opt_ HANDLE TmHandle", "_In_ TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass", "_In_reads_bytes_(TransactionManagerInformationLength) PVOID TransactionManagerInformation", "_In_ ULONG TransactionManagerInformationLength"], "addr": 665776}, "ZwSetIoCompletion": {"args": ["_In_ HANDLE IoCompletionHandle", "_In_opt_ PVOID KeyContext", "_In_opt_ PVOID ApcContext", "_In_ NTSTATUS IoStatus", "_In_ ULONG_PTR IoStatusInformation"], "addr": 665936}, "ZwStartProfile": {"args": ["_In_ HANDLE ProfileHandle"], "addr": 666672}, "ZwSubmitIoRing": {"args": [], "addr": 666736}, "ZwSuspendProcess": {"args": ["_In_ HANDLE ProcessHandle"], "addr": 666800}, "ZwUnloadKey": {"args": ["_In_ POBJECT_ATTRIBUTES TargetKey"], "addr": 667184}, "ZwUnmapViewOfSectionEx": {"args": ["_In_ HANDLE ProcessHandle", "_In_opt_ PVOID BaseAddress", "_In_ ULONG Flags"], "addr": 667344}, "ZwWaitLowEventPair": {"args": ["_In_ HANDLE EventPairHandle"], "addr": 667632}}, "win32u.dll": {"NtUserQueryWindow": {"args": [], "addr": 5728}, "NtGdiGetRandomRgn": {"args": ["_In_ HDC hdc", "_In_ HRGN hrgn", "_In_ int iRgn"], "addr": 6496}, "NtUserGetSystemMenu": {"args": [], "addr": 8192}, "NtUserSetParent": {"args": [], "addr": 8864}, "NtGdiCreatePaletteInternal": {"args": ["_In_reads_bytes_(cEntries * 4 + 4) LPLOGPALETTE pLogPal", "_In_ UINT cEntries"], "addr": 10336}, "NtUserBuildNameList": {"args": [], "addr": 10400}, "NtGdiSetPixel": {"args": ["_In_ HDC hdc", "_In_ int ipfd"], "addr": 10432}, "NtUserGetAncestor": {"args": [], "addr": 10528}, "NtUserScrollWindowEx": {"args": [], "addr": 10912}, "NtUserSetClipboardData": {"args": [], "addr": 11360}, "NtGdiBeginPath": {"args": ["_In_ HDC hdc"], "addr": 13152}, "NtUserPaintDesktop": {"args": [], "addr": 13504}, "NtBindCompositionSurface": {"args": [], "addr": 13824}, "NtDCompositionCreateChannel": {"args": [], "addr": 14368}, "NtDCompositionCreateSynchronizationObject": {"args": [], "addr": 14496}, "NtDCompositionGetChannels": {"args": [], "addr": 14720}, "NtDCompositionGetTargetStatistics": {"args": [], "addr": 15040}, "NtDCompositionSetMaterialProperty": {"args": [], "addr": 15456}, "NtDCompositionUpdatePointerCapture": {"args": [], "addr": 15616}, "NtDxgkDisplayPortOperation": {"args": [], "addr": 16064}, "NtDxgkGetProperties": {"args": [], "addr": 16256}, "NtFlipObjectEnablePresentStatisticsType": {"args": [], "addr": 17120}, "NtFlipObjectSetContent": {"args": [], "addr": 17440}, "NtGdiClearBitmapAttributes": {"args": ["_In_ HBITMAP hbm", "_In_ DWORD dwFlags"], "addr": 18176}, "NtGdiConfigureOPMProtectedOutput": {"args": [], "addr": 18272}, "NtGdiCreateOPMProtectedOutputs": {"args": [], "addr": 18560}, "NtGdiCreateServerMetaFile": {"args": ["_In_ DWORD iType", "_In_ ULONG cjData", "_In_reads_bytes_(cjData) LPBYTE pjData", "_In_ DWORD mm", "_In_ DWORD xExt", "_In_ DWORD yExt"], "addr": 18624}, "NtGdiDdDDICreateHwQueue": {"args": [], "addr": 19712}, "NtGdiDdDDIGetSwapChainSurfacePhysicalAddress": {"args": [], "addr": 21568}, "NtGdiDdDDIInvalidateActiveVidPn": {"args": [], "addr": 21632}, "NtGdiDdDDIInvalidateCache": {"args": [], "addr": 21664}, "NtGdiDdDDILock2": {"args": [], "addr": 21728}, "NtGdiDdDDINetDispGetNextChunkInfo": {"args": [], "addr": 21856}, "NtGdiDdDDINetDispQueryMiracastDisplayDeviceSupport": {"args": [], "addr": 21920}, "NtGdiDdDDIReleaseProcessVidPnSourceOwners": {"args": [], "addr": 23456}, "NtGdiDdDDISignalSynchronizationObjectFromGpu": {"args": [], "addr": 24416}, "NtGdiDdDDITrimProcessCommitment": {"args": [], "addr": 24608}, "NtGdiDdNotifyFullscreenSpriteUpdate": {"args": ["_In_ HDC hdc", "_In_ HANDLE hSprite"], "addr": 25056}, "NtGdiEnableEudc": {"args": ["_In_ BOOL"], "addr": 25376}, "NtGdiEngCreateDeviceSurface": {"args": ["_In_ DHSURF dhsurf", "_In_ SIZEL sizl", "_In_ ULONG iFormatCompat"], "addr": 25792}, "NtGdiEngUnlockSurface": {"args": ["_In_ SURFOBJ *"], "addr": 26432}, "NtGdiGetColorAdjustment": {"args": ["_In_ HDC hdc", "_Out_ PCOLORADJUSTMENT pcaOut"], "addr": 27328}, "NtGdiGetFontFileData": {"args": ["_In_         UINT      uFileCollectionID", "_In_         UINT      uFileIndex", "_In_         ULONGLONG *  pullFileOffset", "_Out_writes_bytes_(cbSize) void *     pBuffer", "_In_         SIZE_T     cbSize"], "addr": 27744}, "NtGdiGetGlyphIndicesW": {"args": ["_In_ HDC hdc", "_In_reads_opt_(cwc) LPWSTR pwc", "_In_ int cwc", "_Out_writes_opt_(cwc) LPWORD pgi", "_In_ DWORD iMode"], "addr": 27872}, "NtGdiGetMonitorID": {"args": ["_In_ HDC hdc", "_In_ DWORD dwSize", "_Out_writes_bytes_(dwSize) LPWSTR pszMonitorID"], "addr": 28064}, "NtGdiGetUFIPathname": {"args": ["_In_ PUNIVERSAL_FONT_ID pufi", "_Deref_out_range_(0,MAX_PATH * 3) ULONG* pcwc", "_Out_writes_to_opt_(MAX_PATH * 3,*pcwc) LPWSTR pwszPathname", "_Out_opt_ ULONG* pcNumFiles", "_In_ FLONG fl", "_Out_opt_ BOOL *pbMemFont", "_Out_opt_ ULONG *pcjView", "_Out_opt_ PVOID pvView", "_Out_opt_ BOOL *pbTTC", "_Out_opt_ ULONG *piTTC"], "addr": 28672}, "NtGdiResetDC": {"args": [], "addr": 29664}, "NtGdiScaleViewportExtEx": {"args": ["_In_ HDC hdc", "_In_ int xNum", "_In_ int xDenom", "_In_ int yNum", "_In_ int yDenom", "_Out_opt_ LPSIZE pszOut"], "addr": 29984}, "NtGdiScaleWindowExtEx": {"args": ["_In_ HDC hdc", "_In_ int xNum", "_In_ int xDenom", "_In_ int yNum", "_In_ int yDenom", "_Out_opt_ LPSIZE pszOut"], "addr": 30016}, "NtGdiUnloadPrinterDriver": {"args": ["_In_reads_bytes_(cbDriverName) LPWSTR pDriverName", "_In_ ULONG cbDriverName"], "addr": 30880}, "NtMinQPeekForInput": {"args": [], "addr": 32448}, "NtMinQUpdateWakeMask": {"args": [], "addr": 32512}, "NtRIMAreSiblingDevices": {"args": [], "addr": 33536}, "NtSetCursorInputSpace": {"args": [], "addr": 34432}, "NtUserAcquireIAMKey": {"args": [], "addr": 34848}, "NtUserCreateDCompositionHwndTarget": {"args": [], "addr": 36128}, "NtUserCreatePopupMenu": {"args": [], "addr": 36320}, "NtUserDestroyActivationObject": {"args": [], "addr": 36704}, "NtUserDestroyCaret": {"args": [], "addr": 36736}, "NtUserDisableThreadIme": {"args": [], "addr": 36960}, "NtUserDiscardPointerFrameMessages": {"args": [], "addr": 36992}, "NtUserDoSoundDisconnect": {"args": [], "addr": 37152}, "NtUserDragObject": {"args": [], "addr": 37280}, "NtUserDrawMenuBar": {"args": [], "addr": 37440}, "NtUserEnableMouseInPointerForThread": {"args": [], "addr": 37824}, "NtUserEnableMouseInPointerForWindow": {"args": [], "addr": 37856}, "NtUserEnableShellWindowManagementBehavior": {"args": [], "addr": 38016}, "NtUserGetClipboardViewer": {"args": [], "addr": 38816}, "NtUserGetModernAppWindow": {"args": [], "addr": 40256}, "NtUserGetPointerInputTransform": {"args": [], "addr": 40704}, "NtUserGetWindowMinimizeRect": {"args": [], "addr": 41920}, "NtUserGetWindowRgnEx": {"args": [], "addr": 41984}, "NtUserGetWindowThreadProcessId": {"args": [], "addr": 42016}, "NtUserHardErrorControl": {"args": [], "addr": 42176}, "NtUserInitThreadCoreMessagingIocp": {"args": [], "addr": 42528}, "NtUserIsTouchWindow": {"args": [], "addr": 43296}, "NtUserOpenInputDesktop": {"args": [], "addr": 44416}, "NtUserRegisterManipulationThread": {"args": [], "addr": 45568}, "NtUserRegisterPointerInputTarget": {"args": [], "addr": 45632}, "NtUserRemoteConsoleShadowStop": {"args": [], "addr": 46208}, "NtUserRemoteShadowSetup": {"args": [], "addr": 46496}, "NtUserRemoteStopScreenUpdates": {"args": [], "addr": 46592}, "NtUserScaleSystemMetricForDPIWithoutCache": {"args": [], "addr": 46944}, "NtUserSetChildWindowNoActivate": {"args": [], "addr": 47424}, "NtUserSetDialogPointer": {"args": [], "addr": 47712}, "NtUserSetProcessDpiAwarenessContext": {"args": [], "addr": 48864}, "NtUserSetThreadInputBlocked": {"args": [], "addr": 49440}, "NtUserSetVisible": {"args": [], "addr": 49536}, "NtUserSetWindowBand": {"args": [], "addr": 49632}, "NtUserSetWindowFeedbackSetting": {"args": [], "addr": 49792}, "NtUserShellHandwritingDelegateInput": {"args": [], "addr": 49952}, "NtUserUpdatePerUserSystemParameters": {"args": [], "addr": 51232}, "NtUserUserHandleGrantAccess": {"args": [], "addr": 51392}}};
var funcs_map = {};
var register_args = ["rcx", "rdx", "r8", "r9"];

function lib_includes(libname, liblist) {
  for (var i = 0; i < liblist.length; i++) {
    if (libname.toLowerCase() == liblist[i].toLowerCase()) {
      return true
    }
  }
  return false
}

function func_includes(funcname, funclist) {
  for (var i = 0; i < funclist.length; i++) {
    if (funcname.toLowerCase() == funclist[i].toLowerCase()) {
      return true
    }
  }
  return false
}

function mutate_n(n, ratio){
  return n + Math.floor(Math.random() * ratio) - ratio/2;
}

function mutate_buf(ptr, size, arg_i) {
  let buf = Memory.readByteArray(ptr, size);
  let buf_view = new Uint8Array(buf);
  // deep copy buf
  let new_buf = new ArrayBuffer(size);
  let new_buf_view = new Uint8Array(new_buf);
  for (let i = 0; i < size; i++) {
      if (Math.random() < 0.7) {
        new_buf_view[i] = buf_view[i];
      }else{
        new_buf_view[i] = mutate_n(buf_view[i], 10)
        }
    }
  Memory.writeByteArray(ptr, new_buf_view);
  console.log("Mutating buffer arg " + arg_i);
  console.log("From:");
  console.log(buf);
  console.log("To:");
  console.log(new_buf);
}

function mutate_args(context, args, f_args_infos) {
  let syscall_args = ["rcx", "rdx", "r8", "r9"];
  for (let i = 0; i < args.length; i++) {
    if (Math.random() < 0.02) {
        try{
          Memory.readPointer(args[i]) 
          mutate_buf(Memory.readPointer(args[i]), 0x100, i);
        }catch(e){
          continue;
        }
    }
    else if (i < syscall_args.length && Math.random() < 0.01 ) {
        let reg_name = syscall_args[i];
        // convert to int
        let reg_val = parseInt(args[i]);
        let new_val = mutate_n(reg_val, 10000);
        context[reg_name] = new_val;
        let hex_val = "0x" + new_val.toString(16);
        console.log("Mutating " + reg_name + " from " + args[i] + " to " + hex_val);
    }
  }
}


setTimeout(function() {
  Process.enumerateModules({
    onMatch: function(module) {
      //console.log("Found " + module.name + " at " + module.base);
      if (lib_includes(module.name, Object.keys(sys_data))) {
        let exports = module.enumerateExports();
        let module_name = module.name.toLowerCase();
        for (let f_name in sys_data[module_name]) {
          // call random function
          
          let infos = sys_data[module_name][f_name];
          let ea = infos["addr"]
          ea = module.base.add(ptr(ea));
          funcs_map[ea] = [f_name, module.name]
          try {
            //console.log("Hooking " + f_name + " at " + ea);
            Interceptor.attach(ea, {
              onEnter: function(args) {
                let f_name = funcs_map[this.context.pc][0];
                let module_name = funcs_map[this.context.pc][1];
                console.log(f_name); 
                let rcx = this.context.rcx;
                let rdx = this.context.rdx;
                let r8 = this.context.r8;
                let r9 = this.context.r9;
                let syscall_args = [rcx, rdx, r8, r9];
                let arg_index = 0;
                let stack_arg = Memory.readPointer(this.context.rsp.add(arg_index * Process.pointerSize));
                while (stack_arg != 0 && arg_index < 4) {
                  stack_arg = Memory.readPointer(this.context.rsp.add(arg_index * Process.pointerSize));
                  syscall_args.push(stack_arg);
                  arg_index++;
                }
                let f_args_infos = sys_data[module_name][f_name]["args"];
                for (let i = 0; i < syscall_args.length; i++) {
                  let arg_info = "";
                  if (i < f_args_infos.length) {
                    arg_info = f_args_infos[i];
                  }
                  console.log("Arg " + i + ": " + " " + arg_info + " " + syscall_args[i]);
                }
                mutate_args(this.context, syscall_args, f_args_infos);
                
              }
            });
          } catch (e) {
            console.log("Error: " + e);
          }
        }
      }
    },
    onComplete: function() {
    }
  });
}, 500);
