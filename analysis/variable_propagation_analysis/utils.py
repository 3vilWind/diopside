def get_prefix_memory_objects(state, prefix):
    result = set()

    for name in state.memory.mem._name_mapping:
        if name.startswith(prefix):
            result.update(state.memory.memory_objects_for_name(name))

    return {i.base for i in result}
