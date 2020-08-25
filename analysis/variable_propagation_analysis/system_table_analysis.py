import angr
from angr.calling_conventions import SimCCMicrosoftAMD64

from core.interface_loader import InterfaceLoaderPlugin
from core.loader import load_types, register_basic_types, write_system_table, load_guid_db
from hooks import interfaces_hooks


class SystemTableAnalysis(angr.Analysis):
    def __init__(self, header_file=None):
        add_options = {angr.options.MEMORY_SYMBOLIC_BYTES_MAP, angr.options.REVERSE_MEMORY_NAME_MAP}
        cc = SimCCMicrosoftAMD64(self.project.arch)
        state = self.project.factory.entry_state(add_options=add_options, cc=cc)

        user_header = ''
        if header_file is not None:
            with open(header_file) as f:
                user_header = f.read()
        types = load_types(user_header)

        register_basic_types(types, state)
        guid_to_name, name_to_guid = load_guid_db()
        state.register_plugin('interface_loader', InterfaceLoaderPlugin(guid_to_name, interfaces_hooks, types))

        hook_addr = state.heap.allocate(0x1000)
        struct_addr = state.heap.allocate(0x2000)
        system_table = write_system_table(types, state, hook_addr, struct_addr)

        cc.setup_callsite(state, args=[0x1337, system_table],
                          ret_addr=self.project.simos.return_deadend)

        simgr = self.project.factory.simgr(state)

        simgr.run()
