// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch ( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
			MessageBoxW( 0, L"Loaded", L"Info", 0 );
			FreeLibrary( GetModuleHandle( NULL ) );
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_DETACH:
			MessageBoxW( 0, L"Unload", L"Info", 0 );
			break;
		default:
			MessageBoxW( 0, L"unknown :D", L"Info", 0 );
	}

	return TRUE;
}

