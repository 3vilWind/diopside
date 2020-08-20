import angr

from core.loader import load_behemoth, register_basic_types, write_system_table, load_guid_db
from core.interface_loader import InterfaceLoaderPlugin
from hooks import interfaces_hooks


class SystemTableAnalysis(angr.Analysis):
    def __init__(self):
        add_options = {angr.options.MEMORY_SYMBOLIC_BYTES_MAP, angr.options.REVERSE_MEMORY_NAME_MAP}
        state = self.project.factory.full_init_state(add_options=add_options)

        defns, types = load_behemoth()
        register_basic_types(types, state)
        guid_to_name, name_to_guid = load_guid_db()
        state.register_plugin('interface_loader', InterfaceLoaderPlugin(guid_to_name, interfaces_hooks, types))

        hook_addr = state.heap.allocate(0x1000)
        struct_addr = state.heap.allocate(0x2000)
        system_table = write_system_table(types, state, hook_addr, struct_addr)

        state.regs.rdx = system_table
        state.regs.rcx = 0x1337

        simgr = self.project.factory.simgr(state)

        simgr.run()
