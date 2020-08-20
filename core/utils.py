import inspect


def get_arguments(state, n):
    native_args = []

    if n >= 1:
        native_args.append(state.regs.rcx)
    if n >= 2:
        native_args.append(state.regs.rdx)
    if n >= 3:
        native_args.append(state.regs.r8)
    if n >= 4:
        native_args.append(state.regs.r9)
    if n >= 5:
        raise NotImplementedError()

    return native_args


def uefi_function(func):
    def wrapper(state):
        args = inspect.getfullargspec(func).args
        args_count = len(args) - 1

        native_args = get_arguments(state, args_count)

        result = func(state, *native_args)

        if result is not None:
            state.regs.rax = result

    return wrapper


def mem_view_guid_to_str(mem_view):
    return ('{:08x}-{:04x}-{:04x}-' + '{:02x}' * 8).format(mem_view.Data1.concrete, mem_view.Data2.concrete,
                                                           mem_view.Data3.concrete,
                                                           *[int.from_bytes(mem_view.Data4[i].concrete,
                                                                            byteorder='little') for i in
                                                             range(8)])
