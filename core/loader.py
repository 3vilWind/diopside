import configparser
from importlib import resources

import angr
from angr.sim_type import parse_file

from hooks import efi_boot_services
from .structure import write_struct_hooks, write_struct, resolve_hook_types


def load_types(user_data=''):
    defns, types = parse_file(resources.read_text('data', 'behemoth.h') + '\n' + user_data)
    defns.update(types)
    return defns


def load_guid_db():
    guid_to_name, name_to_guid = dict(), dict()
    config = configparser.ConfigParser()
    config.read_string(resources.read_text('data', 'guids-db.ini'))
    for section in config:
        for item in config[section]:
            name = item.rstrip('_guid').upper()
            guid = config[section][item].strip('{}')
            guid_to_name[guid] = name
            name_to_guid[name] = guid

    return guid_to_name, name_to_guid


def write_system_table(types, state, hook_addr, struct_addr):
    rs = types['EFI_RUNTIME_SERVICES'].with_arch(state.arch)
    bs = types['EFI_BOOT_SERVICES'].with_arch(state.arch)
    st = types['EFI_SYSTEM_TABLE'].with_arch(state.arch)

    hook_addr, bs_hooks = write_struct_hooks(state, hook_addr, bs,
                                             resolve_hook_types(state.project, efi_boot_services.hooks, types))
    hook_addr, rs_hooks = write_struct_hooks(state, hook_addr, rs, dict())
    hook_addr, st_hooks = write_struct_hooks(state, hook_addr, st, dict())

    bs_addr = struct_addr
    struct_addr = write_struct(state, struct_addr, bs, bs_hooks, 'BootServices')
    rs_addr = struct_addr
    struct_addr = write_struct(state, struct_addr, rs, rs_hooks, 'RuntimeServices')
    st_addr = struct_addr
    st_hooks.update({'RuntimeServices': rs_addr, 'BootServices': bs_addr})
    struct_addr = write_struct(state, struct_addr, st, st_hooks, 'SystemTable')

    return st_addr


def register_basic_types(types, state):
    guid = types['EFI_GUID'].with_arch(state.arch)
    guid.name = 'EFI_GUID'
    angr.sim_type.register_types(guid)
