import angr
import claripy
from angr.calling_conventions import SimCCMicrosoftAMD64

from core.env_setup import setup_environment_by_file
from core.loader import load_types, register_basic_types


class SmiVulnerabilitiesAnalysis(angr.Analysis):
    def __init__(self, smi_addr, env_file=None, header_file=None):
        add_options = {angr.options.MEMORY_SYMBOLIC_BYTES_MAP, angr.options.REVERSE_MEMORY_NAME_MAP}
        cc = SimCCMicrosoftAMD64(self.project.arch)

        state = self.project.factory.call_state(addr=smi_addr, cc=cc,
                                                add_options=add_options)
        user_header = ''
        if header_file is not None:
            with open(header_file) as f:
                user_header = f.read()

        types = load_types(user_header)
        register_basic_types(types, state)

        if env_file is not None:
            setup_environment_by_file(state, types, env_file)

        context_addr = state.heap.allocate(0x1000)
        comm_buffer = state.heap.allocate(0x1000)
        comm_buffer_size = state.heap.allocate(0x8)

        comm_buffer_var = claripy.BVS('UNTRUSTED_comm_buffer', 0x1000 * 8)
        state.memory.store(comm_buffer, comm_buffer_var)

        cc.setup_callsite(state, args=[0x1337, context_addr, comm_buffer, comm_buffer_size],
                          ret_addr=self.project.simos.return_deadend)

        def track_writes(st):
            names = st.inspect.mem_write_expr.variables
            for name in names:
                if name.startswith('UNTRUSTED'):
                    print('Write', st.inspect.mem_write_expr, 'to', st.inspect.mem_write_address)

        state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_writes)

        simgr = self.project.factory.simgr(state)
        simgr.run()
