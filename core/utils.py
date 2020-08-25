def mem_view_guid_to_str(mem_view):
    return ('{:08x}-{:04x}-{:04x}-' + '{:02x}' * 8).format(mem_view.Data1.concrete,
                                                           mem_view.Data2.concrete,
                                                           mem_view.Data3.concrete,
                                                           *[int.from_bytes(mem_view.Data4[i].concrete,
                                                                            byteorder='little') for i in range(8)])
