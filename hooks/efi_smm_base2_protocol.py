import angr

from core.constants import EFI_SUCCESS
from core.utils import uefi_function


@uefi_function
def get_smst_location(state: angr.SimState, this, smst):
    return EFI_SUCCESS


hooks = {
    'GetSmstLocation': get_smst_location
}
