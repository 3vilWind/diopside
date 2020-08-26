import angr

from hooks import interfaces_hooks
from .structure import write_struct_type_with_hooks


class InterfaceLoaderPlugin(angr.SimStatePlugin):
    def __init__(self, guid_to_name, interfaces_hooks, types, maps=None):
        super().__init__()
        self._guid_to_name = guid_to_name
        self._interfaces_hooks = interfaces_hooks
        self._types = types
        self.maps = maps if maps is not None else dict()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return InterfaceLoaderPlugin(self._guid_to_name, self._interfaces_hooks, self._types, dict(self.maps))

    def merge(self, _others, _merge_conditions, _common_ancestor=None):
        raise NotImplementedError()

    def widen(self, _others):
        raise NotImplementedError()

    def locate_interface(self, guid):
        if guid in self.maps:
            return self.maps[guid]

        name = self._guid_to_name[guid]
        # TODO: dummy struct if struct doesn't exists

        struct = self._types[name].with_arch(self.state.arch)
        addr = self.state.heap.allocate(struct.size)
        write_struct_type_with_hooks(self.state, struct, addr, hook_addr=self.state.heap.allocate(0x100),
                                     hooks=interfaces_hooks.get(name, dict()), hook_types=self._types)
        return addr
