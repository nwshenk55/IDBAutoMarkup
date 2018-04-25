# IDB Markup Script
# Purpose: markup an IDB with some helpful comments to speed up RE time.
# To run, open a malware in IDA Pro, then select 'File' -> 'ScriptFile' -> <this script>.

from collections import OrderedDict
from itertools import islice
import idaapi


class FunctionCommenter(object):

    def __init__(self):
        self.master_commenting_dict = {}

    def add_function_comment_to_queue(self, function_address, comment_string):

        if function_address in self.master_commenting_dict.keys():
            existing_comment = self.master_commenting_dict[function_address]
            new_comment = str(existing_comment) + '\n' + str(comment_string)
            self.master_commenting_dict[function_address] = new_comment
        else:
            self.master_commenting_dict[function_address] = comment_string

        return

    def commit_all_comments_to_idb(self):

        for address, comment in self.master_commenting_dict.items():

            function_flags = GetFunctionFlags(address)
            if function_flags & FUNC_LIB:
                continue
            else:
                SetFunctionCmt(address, comment, 1)

        return


def count_and_sum_xrefs_to_functions(ea):
    total_number_of_functions = 0
    function_dict = {}
    user_code_functions = []

    for function_address in Functions(SegStart(ea), SegEnd(ea)):
        function_flags = GetFunctionFlags(function_address)
        if function_flags & FUNC_LIB or function_flags & FUNC_STATIC:
            continue
        else:
            user_code_functions.append(function_address)

    for user_code_function in user_code_functions:
        xref_generator = XrefsTo(user_code_function)
        count_of_xrefs = sum(1 for function_generated in xref_generator)
        commenter.add_function_comment_to_queue(user_code_function, 'Fx Xrefs: %s' % count_of_xrefs)
        function_dict[user_code_function] = count_of_xrefs
        total_number_of_functions += 1

    print('\n\nTotal number of user-code functions identified: %s (approx) ' % total_number_of_functions)

    sorted_function_xrefs = OrderedDict(sorted(function_dict.items(), key=lambda t: t[1], reverse=True))

    print('\n\nTop ten most xref\'d user-code functions:\n')
    sorted_function_xrefs_tuples = sorted_function_xrefs.items()
    count = 0
    score = 1

    while count <= len(sorted_function_xrefs_tuples):
        function_flags = GetFunctionFlags(sorted_function_xrefs_tuples[count][0])
        if not function_flags & FUNC_THUNK:
            print("%s -> %s" % (str(hex(int(sorted_function_xrefs_tuples[count][0]))).strip("L"), str(int(sorted_function_xrefs_tuples[count][1]))))
            commenter.add_function_comment_to_queue(sorted_function_xrefs_tuples[count][0], 'This is the #%s most-referenced user-code function' % score)
            score += 1
        count += 1
        if score == 10:
            break

    return

def highlight_instructions_of_interest(mnem_to_highlight, color):
    # TODO: add more, such as pusha, etc

    for segment in Segments():
        for head in Heads(segment, SegEnd(segment)):
            if GetMnem(head) == mnem_to_highlight:
                if mnem_to_highlight == 'call':
                    SetColor(head, CIC_ITEM, color)
                elif mnem_to_highlight == 'xor':
                    if GetOpnd(head, 0) != GetOpnd(head, 1):
                        SetColor(head, CIC_ITEM, color)
                        print('Non-zero XOR @ %s: %s %s' % (str(hex(int(head))).strip("L"), GetOpnd(head, 0), GetOpnd(head, 1)))

    return


class ImportMarkup(object):

    def __init__(self):
        self.dict_of_imports = {}
        self.mapping_of_functions_to_noteworthy_apis = {}
        self.noteworthy_imports = ['accept', 'bind', 'CompareString', 'connect', 'CreateFile', 'CreateMutex', 'CreatePipe', 'CreateProcess', 'CreateRemoteThread', 'CreateService', 'CreateToolhelp32Snapshot', 'CryptAcquireContext', 'DeviceIoControl', 'EnumProcesses', 'EnumProcessModules', 'FindResource', 'GeAsyncKeyState', 'GetAdaptersInfo', 'GetFileSize', 'gethostbyname', 'gethostname', 'GetProcAddress', 'GetTempPath', 'GetTickCount', 'inet_addr', 'InternetOpenUrl', 'InternetReadFile', 'InternetWriteFile', 'IsDebuggerPresent', 'LoadLibrary', 'NetShareEnum', 'NtQueryInformationProcess', 'OleInitialize', 'PeekNamedPipe', 'QueryPerformanceCounter', 'QueueUserAPC', 'ReadFile', 'ReadProcessMemory', 'recv', 'ResumeThread', 'RtlCreateRegistryKey', 'RtlWriteRegistryValue', 'send', 'SetFilePointer', 'SetFileTime', 'SetWindowsHookEx', 'ShellExecute', 'sleep', 'URLDownloadToFile', 'WinExec', 'WriteFile', 'WriteProcessMemory', 'WSAStartup']

    def imports_callback(self, ea, name, ord):
        # Note: this fx is courtesy of hexrays
        if not name:
            self.dict_of_imports[ea] = 'UNK_NAME?'
        else:
            self.dict_of_imports[ea] = name

        return True

    def get_all_imports(self):
        # Note: this fx is courtesy of hexrays
        number_of_imports = idaapi.get_import_module_qty()
        for i in xrange(0, number_of_imports):
            name = idaapi.get_import_module_name(i)
            if not name:
                print("Failed to get import module name for #%d" % i)
                continue

            idaapi.enum_import_names(i, self.imports_callback)

        return

    def trace_direct_or_indirect_references_to_noteworthy_imports(self):
        noteworthy_fxs_in_file = {}
        for imported_function_address, imported_function_name in self.dict_of_imports.items():
            for noteworthy_import in self.noteworthy_imports:
                if noteworthy_import.lower() in imported_function_name.lower():
                    noteworthy_fxs_in_file[imported_function_address] = imported_function_name

        # End goal, a dict with entries which look like this: {4201616:['Sleep','CreateMutex']}

        print('\n\nResults of attempting to trace usage of noteworthy imported APIs by user-code functions:\n')

        for noteworthy_function_address, noteworthy_function_name in noteworthy_fxs_in_file.items():
            list_of_traced_xrefs_to_noteworthy_fx = self.trace_all_xrefs_to_function(noteworthy_function_address)
            if list_of_traced_xrefs_to_noteworthy_fx:
                print('\n%s - Traced %s user-code xref\'s: %s' % (noteworthy_function_name, len(list_of_traced_xrefs_to_noteworthy_fx), (", ".join([str(hex(int(z))).strip("L") for z in list_of_traced_xrefs_to_noteworthy_fx]))))
                for traced_xref in list_of_traced_xrefs_to_noteworthy_fx:
                    if traced_xref not in self.mapping_of_functions_to_noteworthy_apis.keys():
                        self.mapping_of_functions_to_noteworthy_apis[traced_xref] = [noteworthy_function_name]
                    elif traced_xref in self.mapping_of_functions_to_noteworthy_apis.keys():
                        if noteworthy_function_name not in self.mapping_of_functions_to_noteworthy_apis[traced_xref]:
                            self.mapping_of_functions_to_noteworthy_apis[traced_xref].append(noteworthy_function_name)
            else:
                print('\nTraced 0 user-code Xref\'s to imported fx %s. Malware is possibly obfu-ing its API usage?' % noteworthy_function_name)

        return

    def trace_all_xrefs_to_function(self, address_to_trace):
        trace_of_xrefs_to_fx = []

        queue_of_traced_fxs_with_xrefs_to_imported_fx = self.user_code_functions_containing_xrefs_to_address(address_to_trace)
        while queue_of_traced_fxs_with_xrefs_to_imported_fx:
            xrefed_fx = queue_of_traced_fxs_with_xrefs_to_imported_fx.pop()
            if xrefed_fx not in trace_of_xrefs_to_fx:
                trace_of_xrefs_to_fx.append(xrefed_fx)
                queue_of_traced_fxs_with_xrefs_to_imported_fx.extend(self.user_code_functions_containing_xrefs_to_address(xrefed_fx))

        return trace_of_xrefs_to_fx

    @staticmethod
    def user_code_functions_containing_xrefs_to_address(address):
        list_of_fxs_containing_xrefs_to_address = []

        for xref in XrefsTo(address, XREF_USER):
            fx_flags = GetFunctionFlags(xref.frm)
            if fx_flags & FUNC_LIB or fx_flags & FUNC_STATIC:
                continue
            else:
                fx_containing_xref = GetFunctionAttr(xref.frm, FUNCATTR_START)
                list_of_fxs_containing_xrefs_to_address.append(fx_containing_xref)

        return list_of_fxs_containing_xrefs_to_address

    @staticmethod
    def chunkster(list_to_break_into_chunks, length_of_chunks):
        # Yield successive n-sized chunks from a list (courtesy of the internet)
        for i in range(0, len(list_to_break_into_chunks), length_of_chunks):
            yield list_to_break_into_chunks[i:i + length_of_chunks]

        return

    def comment_functions_with_noteworthy_referenced_imports(self):
        for address, api_list in self.mapping_of_functions_to_noteworthy_apis.items():
            if len(api_list) > 7:
                commenter.add_function_comment_to_queue(address, 'Noteworthy referenced APIs:')
                chunked_list_of_apis = list(self.chunkster(api_list, length_of_chunks=7))
                for chunk in chunked_list_of_apis:
                    commenter.add_function_comment_to_queue(address, chunk)
            else:
                commenter.add_function_comment_to_queue(address, 'Noteworthy referenced APIs:\n%s' % api_list)

        return

# Get started
print('\n\n**** Starting IDB Markup! ****\n\n')

# Highlight instructions I care about
highlight_instructions_of_interest('call', 0xffffd0)
highlight_instructions_of_interest('xor', 0xc7c7ff)

# Instantiate the commenter class
commenter = FunctionCommenter()

# Count and Sum Xrefs to all user-code functions
count_and_sum_xrefs_to_functions(ScreenEA())

# Add comments to user-code functions regarding the noteworthy imported functions it calls directly or via sub-functions
importProcessor = ImportMarkup()
importProcessor.get_all_imports()
importProcessor.trace_direct_or_indirect_references_to_noteworthy_imports()
importProcessor.comment_functions_with_noteworthy_referenced_imports()

# Markup the functions
commenter.commit_all_comments_to_idb()

# The end!
print('\n\n**** IDB Markup Complete! ****\n\n')
