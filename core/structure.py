from typing import Dict

from angr import SimState
from angr.sim_type import SimStruct, SimTypePointer, SimTypeFunction, SimType

from .uefi_function import UefiFunction

HOOK_SIZE = 1


class DummyFunction(UefiFunction):
    def __init__(self, proj, func_ty=None):
        super().__init__(proj, func_ty, symbolic_return=True)

    def perform(self, *args, **kwargs):
        print('dummy called at {:x}'.format(self.state.solver.eval(self.state.ip)))


def resolve_hook_types(proj, hooks, types):
    result = dict()
    for name, hook in hooks.items():
        func_type = types.get(hook.FUNCTION_TYPE_NAME, None)
        if isinstance(func_type, SimTypePointer):
            func_type = func_type.pts_to
        if not isinstance(func_type, SimTypeFunction) and func_type is not None:
            raise RuntimeError('Type of hook is not a function!')

        result[name] = hook(proj=proj, func_ty=func_type)
    return result


def write_func_hook(state: SimState, addr: int, hook):
    state.project.hook(addr, hook)
    return addr + HOOK_SIZE


def write_struct_hooks(state: SimState, base_addr: int, struct: SimStruct, hooks: Dict):
    results = dict()
    current_addr = base_addr

    for name, ty in struct.fields.items():
        if isinstance(ty, SimTypePointer) and isinstance(ty.pts_to, SimTypeFunction):
            state.project.hook(current_addr, hooks.get(name, DummyFunction(state.project)))
            results[name] = current_addr
            current_addr += HOOK_SIZE
        elif isinstance(ty, SimStruct):
            current_addr, nested_result = write_struct_hooks(state, current_addr, ty,
                                                             hooks.get(name, dict()))
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
                var = state.solver.BVS(field_fullname, ty.size)
                state.solver.add(var == values[name])
                result[name] = var
            else:
                result[name] = state.solver.BVS(field_fullname, ty.size)
        else:
            raise RuntimeError('Unknown type!')

    return result


def write_struct(state: SimState, base_addr: int, struct: SimStruct, values: Dict, var_prefix=''):
    final_values = _prepare_values(state, struct, values, var_prefix)
    struct.store(state, base_addr, final_values)

    return base_addr + struct.size // state.arch.byte_width


def write_struct_type_with_hooks(state, struct_type, struct_addr, hook_addr=None, hooks=None, fields=None,
                                 hook_types=None, var_prefix=''):
    if fields is None:
        fields = dict()
    if hooks is None:
        hooks = dict()
    if hook_types is None:
        hook_types = dict()
    struct_type = struct_type.with_arch(state.arch)

    next_hook_addr, hooks = write_struct_hooks(state, hook_addr, struct_type,
                                               resolve_hook_types(state.project, hooks, hook_types))
    hooks.update(fields)
    next_struct_addr = write_struct(state, struct_addr, struct_type, hooks, var_prefix)

    return next_struct_addr, next_hook_addr
