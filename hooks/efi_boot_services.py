from core.constants import EFI_SUCCESS
from core.uefi_function import UefiFunction
from core.utils import mem_view_guid_to_str


class LocateProtocolFunction(UefiFunction):
    FUNCTION_TYPE_NAME = 'EFI_LOCATE_PROTOCOL'

    def perform(self, protocol, registration, addr):
        guid = self.state.mem[protocol].struct.EFI_GUID
        str_guid = mem_view_guid_to_str(guid)

        interface_addr = self.state.interface_loader.locate_interface(str_guid)
        self.state.memory.store(addr, interface_addr.to_bytes(8, byteorder='little'))

        return EFI_SUCCESS


hooks = {
    'LocateProtocol': LocateProtocolFunction
}
