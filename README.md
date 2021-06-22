# CodeInjection

## SectionInjection
### This code works on my machine @ 22-06-2021
Injects shellcode using NtCreateSection, NtMapViewOfSection and RtlCreateUserThread.  
#### Explanation
Create `notepad.exe` as host process to run our shellcode in.  
Create a new memory section with RWX protection using `NtCreateSection`.  
Map a view of the created section to the local process with RW protection using `NtMapViewOfSection`.
Map a view of the created section to a remote target process with RX protection using `NtMapViewOfSection`.  
Fill the view mapped in the local process with shellcode. This gets reflected in the mapped section in the remote process.  
Run the mapped shellcode by creating a remote thread and pointing it to the mapped shellcode using `RtlCreateUserThread`.
#### References
https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection

## APCQueueInjection
### This code works on my machine @ 22-06-2021
#### Explanation
Find the PID of `explorer.exe`.  
Allocate memory in explorer.exe process memory space.  
Write shellcode to that memory location.  
Find an alertable thread.  
Queue an APC at alertable thread. APC points to the shellcode
#### References
https://modexp.wordpress.com/2019/08/27/process-injection-apc/  
https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection
