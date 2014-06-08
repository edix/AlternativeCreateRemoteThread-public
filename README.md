What is Alternative Create Remote Thread?
============
This project is a example of of creating a remote thread into a process without using WriteProcessMemory like others techniques. We will drop a DLL named "API32.DLL" to "C:\WINDOWS\" and create a new thread to the process where we want to load the DLL. In the remote process we will execute LoadLibraryA with a pointer to the string API32.DLL as the first parameter, by using CreateRemoteThread..

If you want to know exactly how it works just check the code out.

