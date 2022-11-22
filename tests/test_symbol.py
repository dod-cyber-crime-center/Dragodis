
import pytest


EXPECTED_IMPORTS_X86 = [
    (0x40a000, None, "GetCommandLineA", "KERNEL32"),
    (0x40a004, None, "EnterCriticalSection", "KERNEL32"),
    (0x40a008, None, "LeaveCriticalSection", "KERNEL32"),
    (0x40a00c, None, "TerminateProcess", "KERNEL32"),
    (0x40a010, None, "GetCurrentProcess", "KERNEL32"),
    (0x40a014, None, "UnhandledExceptionFilter", "KERNEL32"),
    (0x40a018, None, "SetUnhandledExceptionFilter", "KERNEL32"),
    (0x40a01c, None, "IsDebuggerPresent", "KERNEL32"),
    (0x40a020, None, "GetModuleHandleW", "KERNEL32"),
    (0x40a024, None, "Sleep", "KERNEL32"),
    (0x40a028, None, "GetProcAddress", "KERNEL32"),
    (0x40a02c, None, "ExitProcess", "KERNEL32"),
    (0x40a030, None, "WriteFile", "KERNEL32"),
    (0x40a034, None, "GetStdHandle", "KERNEL32"),
    (0x40a038, None, "GetModuleFileNameA", "KERNEL32"),
    (0x40a03c, None, "FreeEnvironmentStringsA", "KERNEL32"),
    (0x40a040, None, "GetEnvironmentStrings", "KERNEL32"),
    (0x40a044, None, "FreeEnvironmentStringsW", "KERNEL32"),
    (0x40a048, None, "WideCharToMultiByte", "KERNEL32"),
    (0x40a04c, None, "GetLastError", "KERNEL32"),
    (0x40a050, None, "GetEnvironmentStringsW", "KERNEL32"),
    (0x40a054, None, "SetHandleCount", "KERNEL32"),
    (0x40a058, None, "GetFileType", "KERNEL32"),
    (0x40a05c, None, "GetStartupInfoA", "KERNEL32"),
    (0x40a060, None, "DeleteCriticalSection", "KERNEL32"),
    (0x40a064, None, "TlsGetValue", "KERNEL32"),
    (0x40a068, None, "TlsAlloc", "KERNEL32"),
    (0x40a06c, None, "TlsSetValue", "KERNEL32"),
    (0x40a070, None, "TlsFree", "KERNEL32"),
    (0x40a074, None, "InterlockedIncrement", "KERNEL32"),
    (0x40a078, None, "SetLastError", "KERNEL32"),
    (0x40a07c, None, "GetCurrentThreadId", "KERNEL32"),
    (0x40a080, None, "InterlockedDecrement", "KERNEL32"),
    (0x40a084, None, "HeapCreate", "KERNEL32"),
    (0x40a088, None, "VirtualFree", "KERNEL32"),
    (0x40a08c, None, "HeapFree", "KERNEL32"),
    (0x40a090, None, "QueryPerformanceCounter", "KERNEL32"),
    (0x40a094, None, "GetTickCount", "KERNEL32"),
    (0x40a098, None, "GetCurrentProcessId", "KERNEL32"),
    (0x40a09c, None, "GetSystemTimeAsFileTime", "KERNEL32"),
    (0x40a0a0, None, "GetCPInfo", "KERNEL32"),
    (0x40a0a4, None, "GetACP", "KERNEL32"),
    (0x40a0a8, None, "GetOEMCP", "KERNEL32"),
    (0x40a0ac, None, "IsValidCodePage", "KERNEL32"),
    (0x40a0b0, 0x409b0e, "RtlUnwind", "KERNEL32"),
    (0x40a0b4, None, "LoadLibraryA", "KERNEL32"),
    (0x40a0b8, None, "InitializeCriticalSectionAndSpinCount", "KERNEL32"),
    (0x40a0bc, None, "HeapAlloc", "KERNEL32"),
    (0x40a0c0, None, "VirtualAlloc", "KERNEL32"),
    (0x40a0c4, None, "HeapReAlloc", "KERNEL32"),
    (0x40a0c8, None, "GetConsoleCP", "KERNEL32"),
    (0x40a0cc, None, "GetConsoleMode", "KERNEL32"),
    (0x40a0d0, None, "FlushFileBuffers", "KERNEL32"),
    (0x40a0d4, None, "LCMapStringA", "KERNEL32"),
    (0x40a0d8, None, "MultiByteToWideChar", "KERNEL32"),
    (0x40a0dc, None, "LCMapStringW", "KERNEL32"),
    (0x40a0e0, None, "GetStringTypeA", "KERNEL32"),
    (0x40a0e4, None, "GetStringTypeW", "KERNEL32"),
    (0x40a0e8, None, "GetLocaleInfoA", "KERNEL32"),
    (0x40a0ec, None, "SetFilePointer", "KERNEL32"),
    (0x40a0f0, None, "HeapSize", "KERNEL32"),
    (0x40a0f4, None, "CloseHandle", "KERNEL32"),
    (0x40a0f8, None, "WriteConsoleA", "KERNEL32"),
    (0x40a0fc, None, "GetConsoleOutputCP", "KERNEL32"),
    (0x40a100, None, "WriteConsoleW", "KERNEL32"),
    (0x40a104, None, "SetStdHandle", "KERNEL32"),
    (0x40a108, None, "CreateFileA", "KERNEL32"),
]


def test_imports_x86_ida(disassembler):
    actual = [
        (import_.address, import_.thunk_address, import_.name, import_.namespace)
        for import_ in disassembler.imports
    ]
    assert actual == EXPECTED_IMPORTS_X86


def test_imports_x86_ghidra(disassembler):
    # Ghidra includes the ".DLL" for the module.
    expected = [
        (address, thunk_address, name, namespace + ".DLL")
        for address, thunk_address, name, namespace in EXPECTED_IMPORTS_X86
    ]
    actual = [
        (import_.address, import_.thunk_address, import_.name, import_.namespace)
        for import_ in disassembler.imports
    ]
    assert actual == expected


def test_imports_references(disassembler):
    imp = disassembler.get_import("LoadLibraryA")
    assert set(ref.from_address for ref in imp.references_to) == {0x405873}


def test_imports_arm_ida(disassembler):
    imports = list(disassembler.imports)
    assert len(imports) == 4
    # Newer versions of IDA includes the namespace or library name.
    assert set(import_.namespace for import_ in imports) in ({".dynsym"}, {None})

    imports = [(import_.address, import_.thunk_address, import_.name) for import_ in imports]
    assert imports == [
        (0x21270, 0x102DC, "puts"),
        (0x21274, 0x10300, "abort"),
        (0x21278, 0x102E8, "__libc_start_main"),
        (0x2127C, 0x102F4, "__gmon_start__"),
    ]


def test_imports_arm_ghidra(disassembler):
    imports = [
        (import_.address, import_.thunk_address, import_.name)
        for import_ in disassembler.imports
    ]
    assert imports == [
        # Ghidra's import address is None, because it doesn't map an "extern" segment.
        (0x22004, 0x102DC, "puts"),
        (0x22008, 0x10300, "abort"),
        (0x2200c, 0x102E8, "__libc_start_main"),
        (0x22000, None, "__gmon_start__")
    ]


def test_exports_x86_ida(disassembler):
    exports = [(export.address, export.name) for export in disassembler.exports]
    assert exports == [(0x4014E0, "start")]


def test_exports_x86_ghidra(disassembler):
    exports = [(export.address, export.name) for export in disassembler.exports]
    assert exports == [(0x4014E0, "entry")]


def test_exports_arm(disassembler):
    # NOTE: Only testing main user code symbols, since the other entry points
    # can vary based on disassembler.
    expected = [
        # (0x102bc, ".init_proc"),
        # (0x1030c, "_start"),
        (0x103fc, "encrypt"),
        (0x1045c, "decrypt"),
        (0x1058c, "main"),
        # (0x1067c, "__libc_csu_init"),
        # (0x106dc, "__libc_csu_fini"),
        # (0x106e0, ".term_proc"),
        # (0x106e8, "_IO_stdin_used"),
        # (0x21020, "__data_start"),
        # (0x21024, "__dso_handle"),
        (0x21028, "string01"),
        (0x21038, "string02"),
        (0x21054, "string03"),
        (0x21084, "string04"),
        (0x210a8, "string05"),
        (0x210c8, "string06"),
        (0x210ec, "string13"),
        (0x21118, "string17"),
        (0x2113c, "string1a"),
        (0x21148, "string23"),
        (0x21158, "string27"),
        (0x21160, "string40"),
        (0x21168, "string46"),
        (0x21184, "string73"),
        (0x2119c, "string75"),
        (0x211c4, "string77"),
        (0x211ec, "string7a"),
        (0x2121c, "string7f"),
        # (0x2126a, "__bss_start"),

    ]
    actual = sorted([
        (export.address, export.name)
        for export in disassembler.exports
        if export.name in ("encrypt", "decrypt", "main") or export.name.startswith("string")
    ])
    assert actual == expected
