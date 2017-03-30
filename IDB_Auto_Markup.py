'''

IDB Auto Markup

- Purpose: This script marks up an IDA Pro IDB with comments that are helpful for malware reverse engineers

- To run, open a malware in IDA Pro, then select 'File' -> 'ScriptFile' -> <this script>.

- Current features:
[1] Highlight noteworthy operations, such as calls and non-zeroing XOR operations.
[2] Auto identify the top-ten most referenced user code functions
 and comment them accordingly. This is a helpful way to (sometimes) quickly find obfuscation functions.
[3] Auto identify all noteworthy imported functions and trace their usage throughout the
malware. This is a helpful way to (sometimes) quickly quickly identify key execution paths. 

TODO:
- Support 64-bit malware (currently untested)
- Verify that I'm identifying user-code functions correctly
- Auto-identify non-zero XOR operations occurring in the context of
a loop (e.g. possibly obfuscation)
- Auto-identify PDB strings
- Auto-identify stack strings (use an existing tool for this?)
- Auto-identify compile time
- Auto-identify calls to registers such as 'call eax'
- Auto-identify the top-10 longest user code functions

'''

from collections import OrderedDict
from itertools import islice
import idaapi


class functionCommenting(object):
    '''
	Add comments to functions. 
	It is much easier to do all commenting at one time, rather than ad-hoc. Hence, this class handles that.
	'''

    def __init__(self):
        self.masterCmtDict = {}

    def addCmt(self, fxAddy, cmntString):

        if fxAddy in self.masterCmtDict.keys():
			self.masterCmtDict.()
            existingCmt = self.masterCmtDict[fxAddy]
            # print 'existingCmt is %s' % existingCmt
            newCmt = str(existingCmt) + '\n' + str(cmntString)
            self.masterCmtDict[fxAddy] = newCmt
        else:
            self.masterCmtDict[fxAddy] = cmntString  # Might want to do this as a list

        return

    def commitAllCmts(self):

        for addy, cmt in self.masterCmtDict.items():

            fxFlags = GetFunctionFlags(addy)
            if fxFlags & FUNC_LIB:
                continue
            else:
                SetFunctionCmt(addy, cmt, 1)

        return


def countAndSumXrefsToFunctions(ea):
    '''
	This function calculates the number of xrefs for each function and the most-xref'd functions
	in the entire program and comments the IDB accordingly.
	'''
    totalNumOfFx = 0
    fxDict = {}

    ## Get list of user-code functions
    userCodeFunctions = []
    for functionAddy in Functions(SegStart(ea), SegEnd(ea)):
        # print 'Checking fx %s' % hex(int(functionAddy))
        fxFlags = GetFunctionFlags(functionAddy)
        if fxFlags & FUNC_LIB or fxFlags & FUNC_STATIC:
            # print 'Fx %s is not user code, skipping' % hex(int(functionAddy))
            continue
        else:
            userCodeFunctions.append(functionAddy)

    ## Create xref count comments for user-code functions
    for usercodeFx in userCodeFunctions:
        xrefGenerator = XrefsTo(usercodeFx)
        totalCrossReferences = sum(1 for fx in xrefGenerator)
        commentor.addCmt(usercodeFx, 'Fx Xrefs: %s' % totalCrossReferences)
        fxDict[usercodeFx] = totalCrossReferences
        totalNumOfFx += 1
    print '\n\nTotal number of user-code functions identified: %s (approx) ' % totalNumOfFx

    ## Create top-ten xref'd functions comments
    fxXrefsSorted = OrderedDict(sorted(fxDict.items(), key=lambda t: t[1], reverse=True))

    print '\n\nTop ten most xref\'d user-code functions:\n'
    xList = fxXrefsSorted.items()
    control = 0
    score = 1
    while control <= len(xList):
        fFlags = GetFunctionFlags(xList[control][0])
        if not fFlags & FUNC_THUNK:
            print hex(int(xList[control][0])), '->', int(xList[control][1])
            commentor.addCmt(xList[control][0], 'This is the #%s most-referenced user-code function' % score)
            score += 1
        control += 1
        if score == 10:
            break


def highlightInstructions(MnemToHighlight, Color):
    '''
	Highlight specific noteworthy instructions.
	TODO: add more, such as pusha, etc
	'''

    for seg in Segments():
        for head in Heads(seg, SegEnd(seg)):
            if GetMnem(head) == MnemToHighlight:
                if MnemToHighlight == 'call':
                    SetColor(head, CIC_ITEM, Color)
                elif MnemToHighlight == 'xor':
                    if GetOpnd(head, 0) != GetOpnd(head, 1):
                        SetColor(head, CIC_ITEM, Color)
                        print 'Non-zero XOR @ %s: %s %s' % (hex(int(head)), GetOpnd(head, 0), GetOpnd(head, 1))


class ImportMarkup(object):
    noteworthyImports = list((x.lower() for x in
                              ['accept', 'bind', 'CompareString', 'connect', 'CreateFile', 'CreateMutex', 'CreatePipe',
                               'CreateProcess', 'CreateRemoteThread', 'CreateService', 'CreateToolhelp32Snapshot',
                               'CryptAcquireContext', 'DeviceIoControl', 'EnumProcesses', 'EnumProcessModules',
                               'FindResource', 'GeAsyncKeyState', 'GetAdaptersInfo', 'GetFileSize', 'gethostbyname',
                               'gethostname', 'GetProcAddress', 'GetTempPath', 'GetTickCount', 'inet_addr',
                               'InternetOpenUrl', 'InternetReadFile', 'InternetWriteFile', 'IsDebuggerPresent',
                               'LoadLibrary', 'NetShareEnum', 'NtQueryInformationProcess', 'OleInitialize',
                               'PeekNamedPipe', 'QueryPerformanceCounter', 'QueueUserAPC', 'ReadFile',
                               'ReadProcessMemory', 'recv', 'ResumeThread', 'RtlCreateRegistryKey',
                               'RtlWriteRegistryValue', 'send', 'SetFilePointer', 'SetFileTime', 'SetWindowsHookEx',
                               'ShellExecute', 'sleep', 'URLDownloadToFile', 'WinExec', 'WriteFile',
                               'WriteProcessMemory', 'WSAStartup']))

    def __init__(self):
        self.importDict = {}

    def importsCallback(self, ea, name, ord):
        '''
		Note: this fx is courtesy of hexrays
		'''
        if not name:
            # print "%08x: ord#%d" % (ea, ord)
            self.importDict[ea] = 'UNK_NAME?'
        else:
            # print "%08x: %s (ord#%d)" % (ea, name, ord)
            self.importDict[ea] = name
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True

    def getImports(self):
        '''
		Get all imports
		Note: this fx is courtesy of hexrays
		'''

        nimps = idaapi.get_import_module_qty()

        # print "Found %d import(s)..." % nimps

        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                print "Failed to get import module name for #%d" % i
                continue

            # print "Walking-> %s" % name
            idaapi.enum_import_names(i, self.importsCallback)

    def traceNoteworthyImports(self):
        '''
		Identify all functions in the program which reference noteworthy imported functions either directly, or via sub-functions. 
		'''
        noteworthyFxsInFile = {}
        self.functionToNoteworthyAPIMappingDict = {}

        ## Get dict of noteworthy functions in the file
        for importedFx in self.importDict.items():
            for fx in self.noteworthyImports:
                if fx in importedFx[1].lower():
                    noteworthyFxsInFile[importedFx[0]] = importedFx[1]

        ## For each noteworthy function, trace its xrefs and build a new dict accordingly.
        ## End goal, a dict like this: {4201616:['Sleep','CreateMutex'],etc}

        print '\n\nResults of attempting to trace usage of noteworthy imported APIs by user-code functions.\n'
        for noteworthyFx in noteworthyFxsInFile.items():
            listOfTracedXrefsToNoteworthyFx = self.xrefGraphTraversal(noteworthyFx[0])
            if listOfTracedXrefsToNoteworthyFx:
                print '\n%s - Traced %s user-code xref\'s: %s' % (noteworthyFx[1], len(listOfTracedXrefsToNoteworthyFx),
                                                                  (", ".join([hex(int(z)) for z in
                                                                              listOfTracedXrefsToNoteworthyFx])))
                # print 'Traced %s user-code Xref\'s to imported fx @ %s: %s' % (len(listOfTracedXrefsToNoteworthyFx),noteworthyFx[1],(", ".join([hex(int(z)) for z in listOfTracedXrefsToNoteworthyFx])))
                for tracedXref in listOfTracedXrefsToNoteworthyFx:
                    if tracedXref not in self.functionToNoteworthyAPIMappingDict.keys():
                        self.functionToNoteworthyAPIMappingDict[tracedXref] = [noteworthyFx[1]]
                    elif tracedXref in self.functionToNoteworthyAPIMappingDict.keys():
                        if noteworthyFx[1] not in self.functionToNoteworthyAPIMappingDict[tracedXref]:
                            self.functionToNoteworthyAPIMappingDict[tracedXref].append(noteworthyFx[1])
                        # elif noteworthyFx[1] in self.functionToNoteworthyAPIMappingDict[tracedXref]:
                        #	print 'No action, its already there'
            else:
                print 'Traced 0 user-code Xref\'s to imported fx @ %s. Possibly using non-standard wrapper?' % \
                      noteworthyFx[1]

            # print 'Final: %s' % self.functionToNoteworthyAPIMappingDict

    def xrefGraphTraversal(self, importAddy):
        '''
		Given a function, trace all xref's to it.
		Return a list of traced xref's
		'''
        traceOfXrefsToFx = []

        queueOfTracedFxsWithXrefsToImportedFx = self.xrefMe(importAddy)
        while queueOfTracedFxsWithXrefsToImportedFx:
            xrefedFx = queueOfTracedFxsWithXrefsToImportedFx.pop()
            ## Check if we've seen it before
            if xrefedFx not in traceOfXrefsToFx:
                ## If we haven't seen it before, add it to the final list and enumerate its xrefs
                traceOfXrefsToFx.append(xrefedFx)
                queueOfTracedFxsWithXrefsToImportedFx.extend(self.xrefMe(xrefedFx))

        return traceOfXrefsToFx

    def xrefMe(self, addressToXref):
        '''
		Return a list of user-code functions containing xrefs to any given address
		'''
        listOfFxsContainingXrefsToAddress = []

        for xref in XrefsTo(addressToXref, XREF_USER):
            fxFlags = GetFunctionFlags(xref.frm)
            if fxFlags & FUNC_LIB or fxFlags & FUNC_STATIC:
                continue
            else:
                fxContainingXref = GetFunctionAttr(xref.frm, FUNCATTR_START)
                listOfFxsContainingXrefsToAddress.append(fxContainingXref)

        return listOfFxsContainingXrefsToAddress

    def chunkster(self, l, n):
        """Yield successive n-sized chunks from l, courtesy of the internet"""
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def commentNoteworthyImports(self):
        '''
		Add a comment to every function stating which noteworthy functions it references directly or via sub-functions
		'''
        for address, APIList in self.functionToNoteworthyAPIMappingDict.items():
            if len(APIList) > 7:
                commentor.addCmt(address, 'Noteworthy referenced APIs:')
                chunkedListOfAPIs = list(self.chunkster(APIList, 7))
                for chunk in chunkedListOfAPIs:
                    commentor.addCmt(address, chunk)
            else:
                commentor.addCmt(address, 'Noteworthy referenced APIs:\n%s' % APIList)


## Get started
print '\n\n**** Starting IDB Markup! ****\n\n'

## Highlight instructions I care about
highlightInstructions('call', 0xffffd0)
highlightInstructions('xor', 0xc7c7ff)

## Instantiate the commentor class
commentor = functionCommenting()

## Count and Sum Xrefs to all user-code functions
countAndSumXrefsToFunctions(ScreenEA())

## Add comments to every user-code function regarding which noteworthy imported function it calls directly or via sub-functions
importProcessor = ImportMarkup()
importProcessor.getImports()
importProcessor.traceNoteworthyImports()
importProcessor.commentNoteworthyImports()

## Markup the function's
commentor.commitAllCmts()

## The end!
print '\n\n**** IDB Markup Complete! ****\n\n'
