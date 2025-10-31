# Applies local variable names and types extracted from the decompiled xzre
# sources onto the active program.
# @category xzre

import json
import os

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import Undefined
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException, InvalidInputException

try:
    from java.lang import Throwable  # type: ignore
except ImportError:  # pragma: no cover - non-Jython environments
    class Throwable(Exception):
        pass


def _find_function_by_name(fm, target_name):
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.getName() == target_name:
            return func
    return None


class TypeResolver(object):
    """
    Lightweight helper that feeds individual type strings through Ghidra's C
    parser and returns resolved DataType instances while avoiding persistent
    typedef clutter in the data type manager.
    """

    def __init__(self, dtm, monitor):
        self._dtm = dtm
        self._parser = CParser(dtm)
        self._monitor = monitor
        self._counter = 0

    def parse(self, type_str):
        name = "__xzre_tmp_type_{}".format(self._counter)
        self._counter += 1
        typedef = None
        snippet = None
        stripped = type_str.strip()
        array_suffix = None
        if "[" in stripped and stripped.endswith("]"):
            idx = stripped.find("[")
            array_suffix = stripped[idx:]
            base = stripped[:idx].rstrip()
            snippet = "typedef {} {}{};\n".format(base, name, array_suffix)
        else:
            snippet = "typedef {} {};\n".format(stripped, name)
        try:
            parsed = self._parser.parse(snippet)
            if parsed is None:
                printerr("Type parse produced None for '{}'".format(type_str))
                return None
            data_type = parsed
            if hasattr(parsed, "getDataType"):
                try:
                    inner = parsed.getDataType()
                    if inner is not None:
                        data_type = inner
                except Exception:
                    pass
            return data_type
        except (Exception, Throwable) as exc:
            printerr("Type parse failed for '{}': {}".format(type_str, exc))
            return None


def _load_mapping(default_path, args):
    mapping_path = default_path
    for arg in args:
        if arg.startswith("map="):
            mapping_path = arg.split("=", 1)[1]
    mapping_path = os.path.abspath(mapping_path)
    if not os.path.exists(mapping_path):
        raise RuntimeError("locals mapping not found at {}".format(mapping_path))
    with open(mapping_path, "r") as infile:
        return mapping_path, json.load(infile)


def _variable_score(var, target_dt):
    score = 0
    target_len = -1
    if target_dt is not None and hasattr(target_dt, "getLength"):
        try:
            target_len = target_dt.getLength()
        except Exception:
            target_len = -1

    try:
        var_len = var.getLength()
    except Exception:
        var_len = -1

    if target_len >= 0 and var_len >= 0:
        score += abs(target_len - var_len)

    if var.getSource() == SourceType.USER_DEFINED:
        score += 5

    name = var.getName() or ""
    if name and not (name.startswith("local_") or name.startswith("stack") or name.startswith("param")):
        score += 2

    storage = var.getVariableStorage()
    if storage is not None and storage.isRegisterStorage():
        score += 1  # Slightly prefer stack storage by keeping register vars later.
    return score


def _choose_variable(candidates, target_dt):
    if not candidates:
        return None
    best = None
    best_score = None
    for var in candidates:
        score = _variable_score(var, target_dt)
        if best is None or score < best_score:
            best = var
            best_score = score
    if best is None:
        return None
    if best_score is None:
        return best
    if best_score > 8:
        return None
    return best


def _data_type_length(dt):
    if dt is None:
        return None
    if hasattr(dt, "getLength"):
        try:
            return dt.getLength()
        except Exception:
            return None
    return None


def _align_value(value, alignment, grows_negative):
    if alignment <= 0:
        return value
    if grows_negative:
        remainder = (-value) % alignment
        if remainder != 0:
            value -= alignment - remainder
    else:
        remainder = value % alignment
        if remainder != 0:
            value += alignment - remainder
    return value


def _next_stack_offset(offsets, grows_negative, size, alignment):
    size = max(size, 1)
    if offsets:
        base = min(offsets) if grows_negative else max(offsets)
        offset = base - size if grows_negative else base + size
    else:
        offset = -size if grows_negative else size
    offset = _align_value(offset, alignment, grows_negative)
    offsets.add(offset)
    return offset


def _ensure_data_type(dt, size):
    if dt is not None:
        return dt
    size = max(size, 1)
    try:
        return Undefined.getUndefinedDataType(size)
    except Exception:
        return Undefined.getUndefinedDataType(1)


def _stack_interval(offset, size, grows_negative):
    size = max(size, 1)
    if grows_negative:
        start = offset
        end = offset + size
    else:
        start = offset - size
        end = offset
    if start > end:
        start, end = end, start
    return start, end


def _clear_stack_conflicts(stack_frame, offset, size, grows_negative, offsets_set, keep_var=None):
    if size <= 0:
        return
    target_start, target_end = _stack_interval(offset, size, grows_negative)
    to_clear = []
    keep_offset = None
    if keep_var is not None:
        try:
            keep_storage = keep_var.getVariableStorage()
            if keep_storage is not None and keep_storage.hasStackStorage():
                keep_offset = keep_storage.getStackOffset()
        except Exception:
            keep_offset = None
    for var in stack_frame.getStackVariables():
        if keep_var is not None and var == keep_var:
            continue
        storage = var.getVariableStorage()
        if storage is None or not storage.hasStackStorage():
            continue
        try:
            var_offset = storage.getStackOffset()
        except Exception:
            continue
        if keep_offset is not None and var_offset == keep_offset:
            continue
        if grows_negative and var_offset >= 0:
            continue
        if var_offset == offset and var == keep_var:
            continue
        var_len = max(var.getLength(), 1)
        var_start, var_end = _stack_interval(var_offset, var_len, grows_negative)
        if target_start < var_end and var_start < target_end:
            to_clear.append(var_offset)
    for off in to_clear:
        try:
            stack_frame.clearVariable(off)
            if offsets_set is not None:
                offsets_set.discard(off)
        except Exception as exc:
            printerr("Failed to clear stack var at {}: {}".format(off, exc))


def _refresh_stack_variable(stack_frame, offset, fallback):
    if offset is None:
        return fallback
    try:
        for var in stack_frame.getStackVariables():
            storage = var.getVariableStorage()
            if storage is None or not storage.hasStackStorage():
                continue
            try:
                var_offset = storage.getStackOffset()
            except Exception:
                continue
            if var_offset == offset:
                return var
    except Exception:
        pass
    return fallback


def _ensure_frame_capacity(stack_frame, offset, size, grows_negative):
    if offset is None or size is None:
        return
    size = max(size, 1)
    try:
        current_size = stack_frame.getFrameSize()
    except Exception:
        return
    try:
        low, high = _stack_interval(offset, size, grows_negative)
    except Exception:
        low, high = (offset, offset)
    needed = current_size
    if grows_negative:
        needed = max(current_size, abs(low))
    else:
        needed = max(current_size, high)
    if needed > current_size:
        try:
            stack_frame.setLocalSize(needed)
        except (Exception, Throwable) as exc:
            printerr(
                "Failed to expand stack frame to {} bytes: {}".format(
                    needed, exc
                )
            )


def _apply_locals_to_function(func, locals_data, type_resolver):
    stack_frame = func.getStackFrame()
    if stack_frame is None:
        printerr("Function {} has no stack frame".format(func.getName()))
        return 0, len(locals_data)

    temp_name_counter = [0]

    def _iter_all_locals():
        try:
            for var in func.getLocalVariables():
                yield var
        except Exception:
            pass
        try:
            for var in stack_frame.getLocals():
                yield var
        except Exception:
            pass

    def _name_in_use(name):
        for var in _iter_all_locals():
            try:
                if var.getName() == name:
                    return True
            except Exception:
                continue
        return False

    def _make_temp_name():
        while True:
            name = "__xzre_tmp_{}".format(temp_name_counter[0])
            temp_name_counter[0] += 1
            if not _name_in_use(name):
                return name

    def _ensure_unique_local_name(desired_name, target_var):
        for var in _iter_all_locals():
            if var == target_var:
                continue
            try:
                existing_name = var.getName()
            except Exception:
                continue
            if existing_name != desired_name:
                continue
            temp_name = _make_temp_name()
            try:
                var.setName(temp_name, SourceType.USER_DEFINED)
            except (Exception, Throwable):
                try:
                    var.setName(temp_name, SourceType.ANALYSIS)
                except (Exception, Throwable) as exc:
                    printerr(
                        "Failed to displace '{}' when renaming in {}: {}".format(
                            desired_name, func.getName(), exc
                        )
                    )
                    continue
            if var not in candidates:
                candidates.append(var)

    stack_offsets = set()

    stack_vars = list(stack_frame.getStackVariables() or [])
    other_locals = list(func.getLocalVariables() or [])
    candidates = []
    for var in stack_vars:
        storage = var.getVariableStorage()
        if storage is not None and storage.hasStackStorage():
            try:
                stack_offsets.add(storage.getStackOffset())
            except Exception:
                continue
            candidates.append(var)
            continue
        candidates.append(var)
    for var in other_locals:
        if var in candidates:
            continue
        storage = var.getVariableStorage()
        if storage is not None and storage.hasStackStorage():
            try:
                stack_offsets.add(storage.getStackOffset())
            except Exception:
                continue
            candidates.append(var)
            continue
        candidates.append(var)

    updated = 0
    skipped = 0
    seen_names = set()

    grows_negative = True
    try:
        grows_negative = stack_frame.growsNegative()
    except Exception:
        grows_negative = True

    for entry in locals_data:
        monitor.checkCanceled()
        name = entry.get("name")
        type_str = entry.get("type")
        if not name:
            skipped += 1
            continue
        if name in seen_names:
            continue

        dt = None
        if type_str:
            dt = type_resolver.parse(type_str)

        target_var = _choose_variable(candidates, dt)
        debug_func = func.getName()
        if target_var is None:
            size = _data_type_length(dt)
            if size is None or size <= 0:
                size = 8
            if size >= 8:
                alignment = 8
            elif size >= 4:
                alignment = 4
            elif size >= 2:
                alignment = 2
            else:
                alignment = 1
            try:
                offset = _next_stack_offset(stack_offsets, grows_negative, size, alignment)
                storage_dt = _ensure_data_type(dt, size)
                _clear_stack_conflicts(stack_frame, offset, size, grows_negative, stack_offsets)
                new_var = stack_frame.createVariable(
                    name or "local_{:x}".format(abs(offset)),
                    offset,
                    storage_dt,
                    SourceType.USER_DEFINED,
                )
                target_var = new_var
                candidates.append(target_var)
                stack_offsets.add(offset)
            except (DuplicateNameException, InvalidInputException, Exception, Throwable) as exc:
                printerr(
                    "No available local slot for {} in {} and creation failed: {}".format(
                        name, func.getName(), exc
                    )
                )
                skipped += 1
                continue

        if dt is not None:
            storage = None
            current_offset = None
            try:
                storage = target_var.getVariableStorage()
            except Exception:
                storage = None
            if storage is not None and storage.hasStackStorage():
                try:
                    current_offset = storage.getStackOffset()
                except Exception:
                    current_offset = None
            dt_size = _data_type_length(dt)
            if dt_size is None or dt_size <= 0:
                try:
                    dt_size = target_var.getLength()
                except Exception:
                    dt_size = 1
            _ensure_frame_capacity(stack_frame, current_offset, dt_size, grows_negative)

            for attempt in range(2):
                try:
                    target_var.setDataType(dt, SourceType.USER_DEFINED)
                    break
                except (Exception, Throwable) as exc:
                    if current_offset is not None and attempt == 0:
                        _clear_stack_conflicts(
                            stack_frame, current_offset, dt_size, grows_negative, stack_offsets, keep_var=target_var
                        )
                        target_var = _refresh_stack_variable(stack_frame, current_offset, target_var)
                        try:
                            storage = target_var.getVariableStorage()
                        except Exception:
                            storage = None
                        continue
                    printerr(
                        "Failed to set type '{}' on {}::{}: {}".format(
                            type_str, func.getName(), target_var.getName(), exc
                        )
                    )
                    break

        try:
            if not target_var.isValid():
                skipped += 1
                if target_var in candidates:
                    candidates.remove(target_var)
                continue
        except Exception:
            pass

        _ensure_unique_local_name(name, target_var)
        try:
            target_var.setName(name, SourceType.USER_DEFINED)
        except (Exception, Throwable) as exc:
            printerr(
                "Failed to rename {} to '{}' in {}: {}".format(
                    target_var.getName(), name, func.getName(), exc
                )
            )
            skipped += 1
            candidates.remove(target_var)
            continue

        candidates.remove(target_var)
        updated += 1
        seen_names.add(name)

    return updated, skipped


def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    default_mapping = os.path.join(script_dir, "generated", "xzre_locals.json")
    mapping_path, mapping = _load_mapping(default_mapping, getScriptArgs())

    println("Applying locals from {}".format(mapping_path))
    fm = currentProgram.getFunctionManager()
    dtm = currentProgram.getDataTypeManager()
    resolver = TypeResolver(dtm, monitor)

    txn = currentProgram.startTransaction("Apply locals from xzre sources")
    success = False
    applied_total = 0
    skipped_total = 0
    missing_total = 0
    try:
        for func_name, payload in mapping.items():
            monitor.checkCanceled()
            func = _find_function_by_name(fm, func_name)
            if func is None:
                printerr("Function {} not found in current program".format(func_name))
                missing_total += 1
                continue
            locals_data = payload.get("locals") or []
            updated, skipped = _apply_locals_to_function(func, locals_data, resolver)
            applied_total += updated
            skipped_total += skipped
        success = True
    finally:
        currentProgram.endTransaction(txn, success)

    println(
        "Locals applied: {} updated, {} skipped, {} functions missing".format(
            applied_total, skipped_total, missing_total
        )
    )


if __name__ == "__main__":
    main()
