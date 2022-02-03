import pathlib
import shutil

import pytest

import dragodis


def _get_strings_path(arch, tmp_path_factory) -> pathlib.Path:
    filename = f"strings_{arch}"
    tmp_dir = tmp_path_factory.mktemp(filename)
    strings_path = pathlib.Path(__file__).parent / "data" / filename
    new_strings_path = tmp_dir / filename
    shutil.copy(strings_path, new_strings_path)
    return new_strings_path


@pytest.fixture(scope="function")
def disassembler(request, tmp_path_factory) -> dragodis.Disassembler:
    """
    This fixture gets indirectly called by pytest_generate_tests.
    """
    if not hasattr(request, "param"):
        # If we don't have a param, we are making a disassembler for the doctests.
        # Set those to IDA with x86.
        backend = "ida"
        arch = "x86"
    else:
        backend, arch = request.param
    strings_path = _get_strings_path(arch, tmp_path_factory)
    try:
        with dragodis.open_program(str(strings_path), disassembler=backend) as dis:
            yield dis
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))


BACKENDS = ["ida", "ghidra"]
ARCHES = ["x86", "arm"]


_param_cache = {}


def pytest_generate_tests(metafunc):
    """
    Generate parametrization for the "disassembler" fixture using the test function name
    to determine which combination of backends and architectures to use.
    """
    if "disassembler" in metafunc.fixturenames:
        # Filter specific backends and arches based on test function name.
        func_name = metafunc.function.__name__.casefold()
        keywords = func_name.split("_")

        backends = [backend for backend in BACKENDS if backend in keywords]
        arches = [arch for arch in ARCHES if arch in keywords]

        # Since we default arch to only be x86, "all" can be used to signal all architectures.
        if not arches and "all" in keywords:
            arches = list(ARCHES)

        # Set defaults to be all backends and just the x86 sample.
        if not backends:
            backends = list(BACKENDS)
        if not arches:
            arches = ["x86"]

        # Parametrize the disassembler fixture based on filters.
        params = []
        for backend in backends:
            for arch in arches:
                # NOTE: We have to cache our parameters so we can reuse them in order to
                # ensure scoping is correct.
                # https://github.com/pytest-dev/pytest/issues/896
                key = (backend, arch)
                try:
                    param = _param_cache[key]
                except KeyError:
                    param = pytest.param(key, id=f"{backend}-{arch}")
                    _param_cache[key] = param
                params.append(param)
        metafunc.parametrize("disassembler", params, indirect=True)


def pytest_make_parametrize_id(config, val, argname):
    """
    Hook id creation to convert addresses into hex.
    """
    if "address" in argname:
        return hex(val)
