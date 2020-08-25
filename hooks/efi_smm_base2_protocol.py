from core.constants import EFI_SUCCESS
from core.uefi_function import UefiFunction


class GetSmstLocationFunction(UefiFunction):
    FUNCTION_TYPE_NAME = 'EFI_SMM_GET_SMST_LOCATION2'

    def perform(self, this, smst):
        return EFI_SUCCESS


hooks = {
    'GetSmstLocation': GetSmstLocationFunction
}
