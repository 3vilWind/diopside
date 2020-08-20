import angr

from core.constants import EFI_SUCCESS
from core.utils import uefi_function, mem_view_guid_to_str


@uefi_function
def locate_protocol(state: angr.SimState, protocol, registration, addr):
    guid = state.mem[protocol].struct.EFI_GUID
    str_guid = mem_view_guid_to_str(guid)
    print('LocateProtocol[{}]'.format(str_guid))
    interface_addr = state.interface_loader.locate_interface(str_guid)
    state.memory.store(addr, interface_addr.to_bytes(8, byteorder='little'))

    return EFI_SUCCESS


hooks = {
    'LocateProtocol': locate_protocol
}
