# -*- coding: utf-8 -*-

import copy
from ctypes import *
from defines import *
from ctypes import wintypes
import sys

kernel32 = windll.kernel32

class Debugger():
    def __init__(self):
        self.h_process = None
        self.h_thread = None
        self.pid = None
        self.tid = None
        self.debugger_active = False
        self.context = None
        self.exception = None
        self.exception_address = None
        #self.first_chance = False   #  第一次处理某调试异常
        self.breakpoints = {}
        self.first_breakpoint = True
        self.last_hit_bp = None     # last hit user breakpoint address
        self.breakpoint_single_step = False  # trap single step mode to reset breakpoint
        self.load_dlls = []         # record loaded dll handle value = (hFile, lpBaseOfDll)
        self.cmd_go = False         # 断点后继续

    def read_process_memory(self, address, length):
        """ Return read data """
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        if kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
            data += read_buf.raw
            return data
        else:
            return False

    def write_process_memory(self, address, data):
        """ Return the number of bytes written """
        count = c_ulong(0)
        length = len(data)
        c_data = c_char_p(data[count.value:])
        if kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            return count
        else:
            return False

    def read_remote_string(self, address, length, unicode):
        if unicode:
            return self.read_process_memory(address, length * sizeof(c_wchar))
        else:
            return self.read_process_memory(address, length)
    
    #def report_error(self, msg=None):
    #    error = GetLastError()
    #    if msg != None:
    #        print "[*] ERROR: %s - %s" % (msg, FormatError(error))
    #    else:
    #        print "[*] ERROR: %s" % FormatError(error)
    #    exit(1)

    #def APIFail(self, descr=None, code=None):
    #    if code is None:
    #        code = GetLastError()
    #    if descr is None:
    #        descr = FormatError(code).strip()
    #    else:
    #        descr = FormatError(code).strip() + descr
    #    return WindowsError(code, descr)

    def resolve_function(self, dll, name):
        handle = kernel32.GetModuleHandleA(dll)
        if not handle:
            raise WinError()
        func = kernel32.GetProcAddress(handle, name)
        kernel32.CloseHandle(handle)
        return func
    
    def set_breakpoint(self, address):
        if not self.breakpoints.has_key(address):
            try:
                original_byte = self.read_process_memory(address, 1)
                # write the opcode 0xCC (INT3)
                self.write_process_memory(address, "\xCC")
                # save the original byte
                self.breakpoints[address] = original_byte
            except:
                print "Failed to set breakpoint at 0x%08x" % address
                return False
        return True

    def load(self, path_to_exe):
        """ Load a program for debugging """
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
        # instantiate the structs
        startupinfo         = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startupinfo.dwFlags     = 0x1
        startupinfo.wShowWindow = 0x0
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):

            print "[*] Launched the process: %s!" % path_to_exe
            print "[*] PID: %d" % process_information.dwProcessId
            kernel32.CloseHandle(process_information.hProcess)
            kernel32.CloseHandle(process_information.hThread)
            self.pid = process_information.dwProcessId
            self.h_process = self.open_process(process_information.dwProcessId)
            self.debugger_active = True
        else:    
            raise WinError()
            
    def open_process(self, pid):
        # NOTE: 32bit process only
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return hProcess
    
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False  
     
    def enumerate_modules(self, pid):
        module_entry = MODULEENTRY32()
        module_entry.dwSize = sizeof(module_entry)
        module_list = []

        while True:
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)
            if snapshot == ERROR_BAD_LENGTH:
                continue
            elif snapshot == INVALID_HANDLE_VALUE:
                raise WinError()
            break

        success = kernel32.Module32First(snapshot, byref(module_entry))
        while success:
            module_list.append(module_entry)
            module_entry = MODULEENTRY32()
            module_entry.dwSize = sizeof(module_entry)
            success = kernel32.Module32Next(snapshot, byref(module_entry))
        kernel32.CloseHandle(snapshot)
        return module_list

    def enumerate_threads(self):
        """ Return a list of thread in the debuggee process """
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        
        if snapshot is not None:
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
                
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
    
    def get_thread_context(self, h_thread):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if kernel32.GetThreadContext(h_thread, byref(context)):
            return context
        else:
            return False
                         
    def attach(self, pid):
        self.h_process = self.open_process(pid)
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            self.start_debug()                      
        else:
            print "[*] Unable to attach to the process."
            #print "[*] Error occurred: 0x%08x." % kernel32.GetLastError() 
            raise WinError()
            
    def start_debug(self):
        """ Debugger main loop """
        while self.debugger_active:
            self.get_debug_event()
    
    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        # 等待调试事件
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.tid = debug_event.dwThreadId
            self.context = self.get_thread_context(self.h_thread)
            #print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if self.exception == EXCEPTION_SINGLE_STEP:
                    self.exception_handler_single_step()
                elif self.exception == EXCEPTION_BREAKPOINT:
                    self.Debug_Event_Log("Breakpoint Exception", self.exception, self.exception_address)
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_ACCESS_VIOLATION:
                    self.Debug_Event_Log("Access Violation Detected", self.exception, self.exception_address)
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    self.Debug_Event_Log("Guard Page Access Detected", self.exception, self.exception_address)
                   
            elif debug_event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT:
                output_debug = debug_event.u.DebugString
                msg = self.read_remote_string(output_debug.lpDebugStringData, output_debug.nDebugStringLength, output_debug.fUnicode)
                print "Debug Output: %s" % msg

            elif debug_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                dllinfo = debug_event.u.LoadDll
                if dllinfo.hFile != None:
                    # 由于系统还未将dll完全载入目标进程，此时只记录dll基址
                    # 当第一个断点事件发生时，才能枚举调试进程中的模块，把这两个基址进行对比
                    # 可以得到载入的模块路径
                    # 否则调用API时会产生无效句柄的错误
                    self.load_dlls.append(dllinfo.lpBaseOfDll)
                    kernel32.CloseHandle(dllinfo.hFile)
            else:
                print "Unhandled Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)
            # 继续执行目标进程
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

    def exception_handler_single_step(self):
        if self.breakpoint_single_step:
            # Reset the last breakpoint
            self.write_process_memory(self.last_hit_bp, "\xCC")
            self.breakpoint_single_step = False
            if self.cmd_go:
                return
        #else:
        #    self.Debug_Event_Log("Single Step Exception", self.exception, self.exception_address)
        self.show_registers()
        self.run_cmd_interpreter()
    
    def exception_handler_breakpoint(self):
        if not self.breakpoints.has_key(self.exception_address):
            if self.first_breakpoint == True:
                self.first_breakpoint = False
                print "[*] Hit the first breakpoint."
                # Print the loaded modules
                mods = self.enumerate_modules(self.pid)
                for m in mods:
                    #print m.modBaseAddr
                    base_addr = cast(m.modBaseAddr, LPVOID).value
                    #print base_addr
                    if base_addr in self.load_dlls:
                        print "[*] Loaded '%s' <0x%08x>" % (m.szExePath, base_addr)
                # Set breakpoint
                func_addr = self.resolve_function("msvcrt.dll", "printf")
                #func_addr = self.resolve_func("kernel32.dll", "Sleep")
                self.set_breakpoint(func_addr)
                print "[*] Set breakpoint at: 0x%08x" % func_addr
            else:
                print "[*] Hit unknown breakpoint at 0x%08x" % self.exception_address
            continue_status = DBG_CONTINUE
            self.run_cmd_interpreter()
        else:
            print "[*] Hit user breakpoint at 0x%08x" % self.exception_address
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])
            self.context = self.get_thread_context(self.h_thread)
            self.context.Eip -= 1
            self.context.EFlags |= 0x00000100  # set TF bit
            self.breakpoint_single_step = True
            self.last_hit_bp = self.exception_address
            kernel32.SetThreadContext(self.h_thread, byref(self.context))
            continue_status = DBG_CONTINUE
            self.run_cmd_interpreter()

        return continue_status

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting..."
            return True
        else:
            print "There was an error"
            return False

    def show_registers(self):
        if self.context:
            #print "[*] Registers for thread ID: 0x%x(%d)" % (self.tid, self.tid)
            print "EAX:%08x EBX:%08x ECX:%08x EDX:%08x" \
                % (self.context.Eax, self.context.Ebx, self.context.Ecx, self.context.Edx)
            print "ESP:%08x EBP:%08x" % (self.context.Esp, self.context.Ebp)
            print "EIP:%08x" % self.context.Eip

    def run_cmd_interpreter(self, set_tf=True):
        # reset interpreter states
        self.cmd_go = False
        while True:
            cmd = raw_input("*> ")
            if cmd == "":
                continue
            if cmd == ":?" or cmd == ":h" or cmd == ":help":
                print "g: go\nt: single stepping\nr: display registers\nsb: show all breakpoints\n~: the number of threads\n"
            elif cmd == "g" or cmd == "go":
                self.cmd_go = True
                #kernel32.RaiseException(0x600033C0, EXCEPTION_NONCONTINUABLE, 0, None)
                break
            elif cmd == 't':
                self.context = self.get_thread_context(self.h_thread)
                self.context.EFlags |= 0x00000100  # set TF bit
                kernel32.SetThreadContext(self.h_thread,byref(self.context))
                break
            elif cmd == 'r':
                self.show_registers()
            elif cmd == 'sb':
                for i, addr in enumerate(self.breakpoints.iterkeys()):
                    print "Num\tAddress"
                    print "%d\t0x%08x" % (i, addr)
            elif cmd == '~':
                tlist = self.enumerate_threads()
                print "[*] PID: 0x%x(%d), the number of threads: %d" % (self.pid, self.pid, len(tlist))
            elif cmd == ":q":
                sys.exit(0)
            else:
                print "unknown command '%s'" % cmd
                print "use :? for help."
      
    def Debug_Event_Log(self, text, code, addr, first_chance=False):
        if first_chance:
            print "[*] %s - code 0x%08x (first chance) at 0x%08x" % (text, code, addr)
        else:
            print "[*] %s - code 0x%08x at 0x%08x" % (text, code, addr)