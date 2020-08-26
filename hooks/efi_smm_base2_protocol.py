from core.constants import EFI_SUCCESS
from core.structure import write_struct_type_with_hooks
from core.uefi_function import UefiFunction


class GetSmstLocationFunction(UefiFunction):
    FUNCTION_TYPE_NAME = 'EFI_SMM_GET_SMST_LOCATION2'

    def perform(self, this, smst):
        smst_addr = self.state.globals.get('smst', None)
        if smst_addr is None:
            smst_type = self.state.interface_loader._types['EFI_SMM_SYSTEM_TABLE2'].with_arch(self.state.arch)
            smst_addr = self.state.heap.allocate(smst_type.size)
            smst_hooks_addr = self.state.heap.allocate(0x100)
            write_struct_type_with_hooks(self.state, smst_type, smst_addr, smst_hooks_addr, hooks=dict(),
                                         hook_types=self.state.interface_loader._types,
                                         var_prefix='EFI_SMM_SYSTEM_TABLE2')
            self.state.globals['smst'] = smst_addr

        self.state.memory.store(smst,
                                smst_addr.to_bytes(8, byteorder='little', signed=False))

        return EFI_SUCCESS


hooks = {
    'GetSmstLocation': GetSmstLocationFunction
}
