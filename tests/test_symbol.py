
import pytest


EXPECTED_IMPORTS_X86 = [
    (0x40a000, "GetCommandLineA", "KERNEL32"),
    (0x40a004, "EnterCriticalSection", "KERNEL32"),
    (0x40a008, "LeaveCriticalSection", "KERNEL32"),
    (0x40a00c, "TerminateProcess", "KERNEL32"),
    (0x40a010, "GetCurrentProcess", "KERNEL32"),
    (0x40a014, "UnhandledExceptionFilter", "KERNEL32"),
    (0x40a018, "SetUnhandledExceptionFilter", "KERNEL32"),
    (0x40a01c, "IsDebuggerPresent", "KERNEL32"),
    (0x40a020, "GetModuleHandleW", "KERNEL32"),
    (0x40a024, "Sleep", "KERNEL32"),
    (0x40a028, "GetProcAddress", "KERNEL32"),
    (0x40a02c, "ExitProcess", "KERNEL32"),
    (0x40a030, "WriteFile", "KERNEL32"),
    (0x40a034, "GetStdHandle", "KERNEL32"),
    (0x40a038, "GetModuleFileNameA", "KERNEL32"),
    (0x40a03c, "FreeEnvironmentStringsA", "KERNEL32"),
    (0x40a040, "GetEnvironmentStrings", "KERNEL32"),
    (0x40a044, "FreeEnvironmentStringsW", "KERNEL32"),
    (0x40a048, "WideCharToMultiByte", "KERNEL32"),
    (0x40a04c, "GetLastError", "KERNEL32"),
    (0x40a050, "GetEnvironmentStringsW", "KERNEL32"),
    (0x40a054, "SetHandleCount", "KERNEL32"),
    (0x40a058, "GetFileType", "KERNEL32"),
    (0x40a05c, "GetStartupInfoA", "KERNEL32"),
    (0x40a060, "DeleteCriticalSection", "KERNEL32"),
    (0x40a064, "TlsGetValue", "KERNEL32"),
    (0x40a068, "TlsAlloc", "KERNEL32"),
    (0x40a06c, "TlsSetValue", "KERNEL32"),
    (0x40a070, "TlsFree", "KERNEL32"),
    (0x40a074, "InterlockedIncrement", "KERNEL32"),
    (0x40a078, "SetLastError", "KERNEL32"),
    (0x40a07c, "GetCurrentThreadId", "KERNEL32"),
    (0x40a080, "InterlockedDecrement", "KERNEL32"),
    (0x40a084, "HeapCreate", "KERNEL32"),
    (0x40a088, "VirtualFree", "KERNEL32"),
    (0x40a08c, "HeapFree", "KERNEL32"),
    (0x40a090, "QueryPerformanceCounter", "KERNEL32"),
    (0x40a094, "GetTickCount", "KERNEL32"),
    (0x40a098, "GetCurrentProcessId", "KERNEL32"),
    (0x40a09c, "GetSystemTimeAsFileTime", "KERNEL32"),
    (0x40a0a0, "GetCPInfo", "KERNEL32"),
    (0x40a0a4, "GetACP", "KERNEL32"),
    (0x40a0a8, "GetOEMCP", "KERNEL32"),
    (0x40a0ac, "IsValidCodePage", "KERNEL32"),
    (0x409b0e, "RtlUnwind", "KERNEL32"),
    (0x40a0b4, "LoadLibraryA", "KERNEL32"),
    (0x40a0b8, "InitializeCriticalSectionAndSpinCount", "KERNEL32"),
    (0x40a0bc, "HeapAlloc", "KERNEL32"),
    (0x40a0c0, "VirtualAlloc", "KERNEL32"),
    (0x40a0c4, "HeapReAlloc", "KERNEL32"),
    (0x40a0c8, "GetConsoleCP", "KERNEL32"),
    (0x40a0cc, "GetConsoleMode", "KERNEL32"),
    (0x40a0d0, "FlushFileBuffers", "KERNEL32"),
    (0x40a0d4, "LCMapStringA", "KERNEL32"),
    (0x40a0d8, "MultiByteToWideChar", "KERNEL32"),
    (0x40a0dc, "LCMapStringW", "KERNEL32"),
    (0x40a0e0, "GetStringTypeA", "KERNEL32"),
    (0x40a0e4, "GetStringTypeW", "KERNEL32"),
    (0x40a0e8, "GetLocaleInfoA", "KERNEL32"),
    (0x40a0ec, "SetFilePointer", "KERNEL32"),
    (0x40a0f0, "HeapSize", "KERNEL32"),
    (0x40a0f4, "CloseHandle", "KERNEL32"),
    (0x40a0f8, "WriteConsoleA", "KERNEL32"),
    (0x40a0fc, "GetConsoleOutputCP", "KERNEL32"),
    (0x40a100, "WriteConsoleW", "KERNEL32"),
    (0x40a104, "SetStdHandle", "KERNEL32"),
    (0x40a108, "CreateFileA", "KERNEL32"),
]


def test_imports_x86_ida(disassembler):
    actual = [
        (import_.address, import_.name, import_.namespace)
        for import_ in disassembler.imports
    ]
    assert actual == EXPECTED_IMPORTS_X86


def test_imports_x86_ghidra(disassembler):
    # Ghidra includes the ".DLL" for the module.
    expected = [
        (address, name, namespace + ".DLL")
        for address, name, namespace in EXPECTED_IMPORTS_X86
    ]
    actual = [
        (import_.address, import_.name, import_.namespace)
        for import_ in disassembler.imports
    ]
    assert actual == expected


def test_imports_arm_ida(disassembler):
    imports = list(disassembler.imports)
    assert len(imports) == 4
    # Newer versions of IDA includes the namespace or library name.
    assert set(import_.namespace for import_ in imports) in ({".dynsym"}, {None})

    imports = [(import_.address, import_.name) for import_ in imports]
    assert imports == [
        (0x102DC, "puts"),
        (0x10300, "abort"),
        (0x102E8, "__libc_start_main"),
        (0x102F4, "__gmon_start__"),
    ]


def test_imports_arm_ghidra(disassembler):
    imports = [
        (import_.address, import_.name, import_.namespace)
        for import_ in disassembler.imports
    ]
    assert imports == [
        (0x22004, "puts", None),
        (0x22008, "abort", None),
        (0x2200c, "__libc_start_main", None),
        (0x22000, "__gmon_start__", None)
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
