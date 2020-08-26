import claripy
import yaml

from core.structure import write_struct_hooks, write_struct, resolve_hook_types
from hooks import interfaces_hooks


def setup_environment_by_file(state, types, filepath):
    with open(filepath) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
    return setup_environment(state, types, data)


def setup_environment(state, types, data):
    interfaces = dict()

    for name, _ in data['heap'].items():
        interface_type = types[name].with_arch(state.arch)

        hooks = resolve_hook_types(state.project, interfaces_hooks.get(name, dict()), types)

        hooks_addr = state.heap.allocate(0x100)
        struct_addr = state.heap.allocate(interface_type.size)

        _, hooks = write_struct_hooks(state, hooks_addr, interface_type, hooks)
        write_struct(state, struct_addr, interface_type, hooks)
        interfaces[name] = struct_addr

    for addr, item in data['memory'].items():
        if item['type'] == 'pointer':
            points_to = item['points_to']
            state.memory.store(addr, interfaces[points_to].to_bytes(8, byteorder='little', signed=False))

        elif item['type'] == 'interface':
            interface = item['interface']
            interface_type = types[interface].with_arch(state.arch)

            hooks = interfaces_hooks.get(interface, dict())
            hooks_addr = state.heap.allocate(0x100)
            _, hooks = write_struct_hooks(state, hooks_addr, interface_type, hooks)

            for field_name, field_data in item.get('fields', dict()).items():
                if field_data['type'] == 'pointer':
                    points_to = field_data['points_to']
                    hooks[field_name] = interfaces[points_to]

            write_struct(state, addr, interface_type, hooks)
        elif item['type'] == 'untrusted':
            var = claripy.BVS('UNTRUSTED', item['size'] * 8)
            state.memory.store(addr, var)
