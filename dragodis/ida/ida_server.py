"""
Custom script to run rpyc server.
This was done so we can properly control the shutdown of IDA after the server exits.
"""
import os
import site
import sys


def activate_virtualenv():
    """
    Activates the virtualenv found in the inherited VIRTUAL_ENV environment variable.
    """
    base_path = os.environ.get("VIRTUAL_ENV")
    if not base_path:
        return

    # Add to PATH
    bin_dir = os.path.join(base_path, "Scripts" if sys.platform == "win32" else "bin")
    os.environ["PATH"] = os.pathsep.join([bin_dir] + os.environ.get("PATH", "").split(os.pathsep))

    # Add site-packages dir
    if sys.platform == "win32":
        site_packages = os.path.join(base_path, "Lib", "site-packages")
    else:
        site_packages = os.path.join(base_path, "lib", "python{}.{}".format(*sys.version_info), "site-packages")

    site.addsitedir(site_packages)
    sys.real_prefix = sys.prefix
    sys.prefix = base_path


def main():
    """
    Initialize rpyc connection.
    """
    # Activate virtualenv if user was in one.
    activate_virtualenv()

    # Start RPyC server.
    # Importing idc here so we can still import the server externally.
    import idc

    if not idc.ARGV[1:]:
        raise RuntimeError(f"No connection parameter provided.")

    import rpyc
    from rpyc import SlaveService, OneShotServer
    from rpyc.core.stream import NamedPipeStream

    # Don't compress to improve speed.
    rpyc.core.channel.Channel.COMPRESSION_LEVEL = 0

    if sys.platform == "win32":
        pipe_name = idc.ARGV[1]
        stream = NamedPipeStream.create_server(pipe_name)
        with rpyc.classic.connect_stream(stream) as srv:
            srv.serve_all()
    else:
        socket_path = idc.ARGV[1]
        server = OneShotServer(SlaveService, socket_path=socket_path, auto_register=False)
        server.start()

    idc.qexit(0)


if __name__ == "__main__":
    main()
