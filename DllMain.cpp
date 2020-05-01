
/* Xbox SDK Calls */
#include <xtl.h>
#include <xboxmath.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <fstream>

/* Xbox SDK Local Headers */
#include "Kernel.h"
#include "utilites.h"
#include "Detours.h"

#include "Dvar.h"

Detour<void>R_EndFrameDetour;

typedef void(*SV_SendServerCommand_t)(int r3, int r4, char* r5, ...);
SV_SendServerCommand_t SV_SendServerCommand = SV_SendServerCommand_t(0x82433E78);
typedef char*(*va_t)(const char* fmt, ...);
va_t va = va_t(0x8249E440);
typedef dvar_s*(*Dvar_FindVar_t)(const char* dvar);
Dvar_FindVar_t Dvar_FindVar = Dvar_FindVar_t(0x82496430);


bool Dvar_GetBool(const char* dvarName)
{
	dvar_s* dvar_t = Dvar_FindVar(dvarName);
	if (!dvar_t)
		return false;
	return dvar_t->current.enabled;
}

void SendDataRME(int address, int value) {
	auto data = address - *(int*)0x82BBAE68;
	data /= 4;
	data += 0x5DDD;
	data -= 0x20000;
	SV_SendServerCommand(0, 1, "i %i %i", data, value);
}

#define GSC_Pointer 0x00000 //GSC pointer you want to override ex: 0x831EBE78 - _clientids.gsc
#define fileSize 0x1111 //Size of the GSC file you want to write

bool done, unload;
int shift;

void R_EndFrame()
{
	if (!Dvar_GetBool("cl_ingame")) 
		return;
	if (GSC_Pointer < 1)
		return;

	if (!done)
	{
		SendDataRME(0x40300000 + shift, *(int*)(0x40300000 + shift));
	}
	if (shift > fileSize) {
		shift = fileSize;
		done = true;
		if (done) {
			SV_SendServerCommand(0, 1, va("O \"^1--- ^5DONE ^1---"));
			SendDataRME(GSC_Pointer, 0x40300000);
			unload = true;
			if (unload)
				R_EndFrameDetour.TakeDownDetour();
		}
	}
	else
		shift += 4;
	R_EndFrameDetour.CallOriginal();
}

bool WINAPI DllMain(HANDLE hInstDll, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:


		*(int*)0x828B9F64 = 0x60000000;
		*(int*)0x828B9F68 = 0x60000000;

		R_EndFrameDetour.SetupDetour(0x828B9F58, R_EndFrame);
	
		break;
	case DLL_PROCESS_DETACH:

		R_EndFrameDetour.TakeDownDetour();
		break;
	}
	return true;
}