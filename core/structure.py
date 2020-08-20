from typing import Dict

from angr import SimState
from angr.sim_type import SimStruct, SimTypePointer, SimTypeFunction, SimType

HOOK_SHELLCODE = b'\xc3'  # ret


def dummy(state):
    pass


def write_struct_hooks(state: SimState, base_addr: int, struct: SimStruct, hooks: Dict):
    results = dict()
    current_addr = base_addr

    for name, ty in struct.fields.items():
        if isinstance(ty, SimTypePointer) and isinstance(ty.pts_to, SimTypeFunction):
            state.memory.store(current_addr, HOOK_SHELLCODE)
            state.project.hook(current_addr, hooks[name] if name in hooks else dummy)

            results[name] = current_addr
            current_addr += len(HOOK_SHELLCODE)
        elif isinstance(ty, SimStruct):
            current_addr, nested_result = write_struct_hooks(state, current_addr, ty,
                                                             hooks[name] if name in hooks else {})
            results[name] = nested_result

    return current_addr, results


def _prepare_values(state: SimState, struct: SimStruct, values: Dict, var_prefix=''):
    result = dict()

    for name, ty in struct.fields.items():
        field_fullname = '.'.join([var_prefix, name])
        if isinstance(ty, SimStruct):
            result[name] = _prepare_values(state, ty, values[name], field_fullname)
        elif isinstance(ty, SimTypePointer) and isinstance(ty, SimTypeFunction) and name not in values:
            raise RuntimeError('Unfilled function pointer!')
        elif isinstance(ty, SimType):
            if name in values:
                result[name] = values[name]
            else:
                result[name] = state.solver.BVS(field_fullname, ty.size)
        else:
            raise RuntimeError('Unknown type!')

    return result


def write_struct(state: SimState, base_addr: int, struct: SimStruct, values: Dict, var_prefix=''):
    final_values = _prepare_values(state, struct, values, var_prefix)
    struct.store(state, base_addr, final_values)

    return base_addr + struct.size
