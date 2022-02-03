"""
Custom script to run rpyc server.
This was done so we can properly control the shutdown of IDA after the server exits.
"""
import sys

import rpyc
from rpyc.core.stream import NamedPipeStream, SocketStream


def main():
    """
    Initialize rpyc connection.
    """
    # Don't compress to improve speed.
    rpyc.core.channel.Channel.COMPRESSION_LEVEL = 0

    # Importing idc here so we can still import the server externally.
    import idc

    if not idc.ARGV[1:]:
        raise RuntimeError(f"No connection parameter provided.")

    if sys.platform == "win32":
        pipe_name = idc.ARGV[1]
        stream = NamedPipeStream.create_server(pipe_name)
    else:
        socket_path = idc.ARGV[1]
        stream = SocketStream.unix_connect(socket_path)

    with stream:
        with rpyc.classic.connect_stream(stream) as srv:
            srv.serve_all()

    idc.qexit(0)


if __name__ == "__main__":
    main()
