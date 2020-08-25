from angr.calling_conventions import SimCCMicrosoftAMD64
from angr.sim_procedure import SimProcedure


class UefiFunction(SimProcedure):
    FUNCTION_TYPE_NAME = ''

    def __init__(self, proj, func_ty=None, *args, **kwargs):
        super().__init__(
            project=proj,
            cc=SimCCMicrosoftAMD64(proj.arch, func_ty=func_ty),
            *args, **kwargs
        )

    def run(self, *args, **kwargs):
        if self.cc.func_ty is not None:
            arguments = self.cc.get_args(self.state)
        else:
            arguments = [self.arg(i) for i in range(self.num_args)]

        return self.perform(*arguments)

    def perform(self, *args, **kwargs):
        pass
