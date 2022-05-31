
def test_teleport_ida(disassembler):
    # Test basic
    @disassembler.teleport
    def teleported(addr):
        import idc
        return idc.get_strlit_contents(addr)
    assert teleported(0x40C000) == b"Idmmn!Vnsme "

    # Test disassembler gets converted to local version.
    @disassembler.teleport
    def teleported(dis):
        from dragodis.ida.disassembler import IDALocalDisassembler
        return isinstance(dis, IDALocalDisassembler)
    assert teleported(disassembler)
