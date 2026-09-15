"""VB-style pseudocode generation from structured word-pcode analysis.

Pipeline:
  word_disasm.analyze()  ->  StackMachine  ->  formatted VB pseudocode

This module consumes structured analysis rather than rendered text, runs the
stack-machine decompiler per procedure, and emits readable VB-style pseudocode.
"""
import re

import stack_ir
import word_disasm


def _build_arg_counts(pal, analysis):
    """Map proc_index -> arg_count by scanning each proc's max stack+N.

    stack+8 is always the Me/object base.  stack+12 = arg1, stack+16 = arg2,
    etc.  arg_count = (max_stack_offset - 8) // 4.
    """
    arg_counts = {}
    entries = analysis["entries"]
    labels = analysis["labels"]
    for idx, (start, end, path) in enumerate(analysis["paths"]):
        max_off = 8
        for pos, opcode, size, _fallback in path:
            label = _label_for(entries, labels, opcode)
            operand = _operand_for(pal, analysis, pos, opcode, size, label,
                                    proc_start=start)
            for m in re.finditer(r'stack\+(\d+)', operand):
                off = int(m.group(1))
                if off > max_off:
                    max_off = off
        arg_counts[idx] = max(0, (max_off - 8) // 4)
    return arg_counts


def _label_for(entries, labels, opcode):
    target = entries.get(opcode, 0)
    label = labels.get(target, "<no CodeView label>")
    if label.startswith("lblEX_"):
        label = label[len("lblEX_"):]
    return label


def _display_label(label):
    return "LitI2" if label == "LitI2_10" else label


def _operand_for(pal, analysis, pos, opcode, size, label, proc_start):
    """Render one instruction's operand, sharing the word-disassembler logic."""
    raw = pal.bytes_at(pos, size)
    operand = word_disasm.special_operand(opcode, raw)
    if operand is not None:
        return operand
    return word_disasm.format_operand(
        opcode, label, raw, proc_start,
        analysis["stub_names"], analysis["declares"], pal)


def build_instrs(pal, analysis, index):
    """Build a list of _Instr objects for one procedure."""
    start, end, path = analysis["paths"][index]
    entries = analysis["entries"]
    labels = analysis["labels"]
    instrs = []
    for pos, opcode, size, _fallback in path:
        raw_label = _label_for(entries, labels, opcode)
        display = _display_label(raw_label)
        operand = _operand_for(pal, analysis, pos, opcode, size, raw_label,
                                proc_start=start)
        instrs.append(_Instr(pos, opcode, size, display, operand))
    return start, end, instrs


class _Instr(object):
    __slots__ = ("pos", "opcode", "size", "label", "operand")

    def __init__(self, pos, opcode, size, label, operand):
        self.pos = pos
        self.opcode = opcode
        self.size = size
        self.label = label
        self.operand = operand


def _build_exit_addrs(analysis):
    """Build a set of all ExitProc* instruction addresses across all procs.

    Used to convert ``GoTo L_XXXX`` (where XXXX is an ExitProc instruction)
    into ``Exit Sub`` — the VB equivalent of branching to a proc exit.
    """
    entries = analysis["entries"]
    labels = analysis["labels"]
    exit_addrs = set()
    for _start, _end, path in analysis["paths"]:
        for pos, opcode, _size, _fb in path:
            target = entries.get(opcode, 0)
            label = labels.get(target, "")
            if label.startswith("lblEX_"):
                label = label[len("lblEX_"):]
            if label.startswith("ExitProc"):
                exit_addrs.add(pos)
    return exit_addrs


def _convert_loops(stmts, label_at_stmt, proc_start, proc_end):
    """Detect backward-GoTo loop patterns and rewrite as While/Do loops.

    Patterns recognized (label L is the GoTo target, appearing earlier):

    1. While...Wend:
       L: If cond Then ... GoTo L ... End If
       → While cond ... Wend
       (label immediately followed by If; GoTo is inside the If block;
        End If closes the block)

    2. Do...Loop While cond:
       L: ...body... If cond Then GoTo L End If
       → Do ...body... If cond Then ... End If Loop While cond
       (GoTo is the ONLY stmt inside If; If is at loop bottom;
        condition controls whether to loop)

    3. Do...Loop While cond (If has body):
       L: ...body... If cond Then ...body... GoTo L End If
       → Do ...body... If cond Then ...body... End If Loop While cond
       (GoTo is inside If with other statements; If body runs when
        condition is true, then loops; falls through when false)

    4. Do...Loop:
       L: ...body... GoTo L
       → Do ...body... Loop
       (unconditional GoTo at outer level; exit via Exit Sub inside)
    """
    import re as _re

    # Build a map: label_va -> stmt index where label appears
    label_to_idx = {}
    for idx, labels in label_at_stmt.items():
        for lv in labels:
            label_to_idx[lv] = idx

    # Find all backward GoTos (target label appears before the GoTo)
    backward_gotos = []
    for i, stmt in enumerate(stmts):
        m = _re.search(r'GoTo L_([0-9A-F]+)', stmt.text)
        if m:
            tgt = int(m.group(1), 16)
            if tgt in label_to_idx and label_to_idx[tgt] < i:
                backward_gotos.append((i, tgt))

    if not backward_gotos:
        return stmts, label_at_stmt

    # Group backward GoTos by target label
    gotos_by_label = {}
    for gi, tgt in backward_gotos:
        gotos_by_label.setdefault(tgt, []).append(gi)

    def find_enclosing_if(idx):
        """Find the If...Then that encloses stmt at idx, or None.
        Returns (if_idx, end_if_idx) or None."""
        depth = 0
        for j in range(idx - 1, -1, -1):
            if stmts[j].indent_delta == -1:
                depth -= 1
            elif stmts[j].indent_delta == +1:
                if depth == 0:
                    # Check if this is an If (not a For/While/Do)
                    if stmts[j].text.startswith("If ") and stmts[j].text.endswith("Then"):
                        # Find matching End If
                        d2 = 1
                        for k in range(j + 1, len(stmts)):
                            if stmts[k].indent_delta == +1:
                                d2 += 1
                            elif stmts[k].indent_delta == -1:
                                d2 -= 1
                                if d2 == 0:
                                    return (j, k)
                        return None
                    return None  # Enclosing block is not an If
                depth += 1
        return None

    def stmts_between(start_idx, end_idx):
        """Count non-blank statements between start_idx and end_idx (exclusive)."""
        count = 0
        for j in range(start_idx + 1, end_idx):
            if stmts[j].text:
                count += 1
        return count

    def nesting_depth(idx):
        """Calculate the nesting depth at stmt idx (number of open blocks
        before this stmt)."""
        depth = 0
        for j in range(idx):
            if stmts[j].indent_delta == +1:
                depth += 1
            elif stmts[j].indent_delta == -1:
                depth -= 1
        return depth

    # Collect transformations
    transforms = []  # (label_idx, goto_idx, pattern, extra_info...)

    for tgt, goto_indices in gotos_by_label.items():
        label_idx = label_to_idx[tgt]
        if len(goto_indices) != 1:
            continue
        goto_idx = goto_indices[0]
        if label_idx >= len(stmts):
            continue

        # Skip if label and GoTo are at different nesting levels —
        # the loop body would span unbalanced blocks.
        # Exceptions:
        #  - While pattern: label IS the If (label at depth N, GoTo at N+1)
        #  - Do...Loop While pattern: label at same depth as the If
        enclosing_if = find_enclosing_if(goto_idx)
        if enclosing_if is None:
            # Do...Loop pattern: GoTo not inside any If
            if nesting_depth(label_idx) != nesting_depth(goto_idx):
                continue
        else:
            if_idx, end_if_idx = enclosing_if
            label_depth = nesting_depth(label_idx)
            if_depth = nesting_depth(if_idx)
            if if_idx == label_idx:
                # While pattern: label is the If itself
                pass
            elif label_depth == if_depth:
                # Do...Loop While: label at same depth as the If
                pass
            else:
                continue

        # Check if GoTo is inside an If block
        # (already computed above as enclosing_if)

        if enclosing_if is None:
            # GoTo is NOT inside any If — pattern 4: Do...Loop
            transforms.append((label_idx, goto_idx, tgt, "do_loop"))
            continue

        if_idx, end_if_idx = enclosing_if

        # GoTo IS inside an If
        if label_idx == if_idx:
            # Pattern 1: While...Wend — label is immediately followed by the If
            # L: If cond Then ... GoTo L ... End If
            transforms.append((label_idx, goto_idx, if_idx, end_if_idx, tgt, "while"))
        else:
            # Pattern 2/3: Do...Loop While cond
            # L: ...body... If cond Then [body2] GoTo L End If
            # Check if GoTo is the only stmt inside If
            body_count = stmts_between(if_idx, end_if_idx)
            if body_count == 1:
                # Case A: If...GoTo...End If (GoTo is the only body stmt)
                # → Do ...body... Loop While cond  (If/End If removed)
                transforms.append((label_idx, goto_idx, if_idx, end_if_idx, tgt, "do_while_empty"))
            else:
                # Case B: If has body + GoTo
                # → Do ...body... If cond Then [body2] End If Loop While cond
                transforms.append((label_idx, goto_idx, if_idx, end_if_idx, tgt, "do_while"))

    # Apply transforms.
    # Instead of modifying stmts in place, we collect per-index actions:
    #   replace[old_idx] = new Stmt
    #   insert_before[old_idx] = [Stmt, ...]  (inserted BEFORE old_idx)
    #   insert_after[old_idx] = [Stmt, ...]  (inserted AFTER old_idx)
    #   blank[old_idx] = True  (remove this stmt)
    replace = {}
    insert_before = {}
    insert_after = {}
    blank = set()
    new_label_at_stmt = {k: list(v) for k, v in label_at_stmt.items()}

    for transform in transforms:
        pattern = transform[-1]
        if pattern == "while":
            label_idx, goto_idx, if_idx, end_if_idx, tgt = transform[0], transform[1], transform[2], transform[3], transform[4]
        elif pattern == "do_while":
            label_idx, goto_idx, if_idx, end_if_idx, tgt = transform[0], transform[1], transform[2], transform[3], transform[4]
        elif pattern == "do_while_empty":
            label_idx, goto_idx, if_idx, end_if_idx, tgt = transform[0], transform[1], transform[2], transform[3], transform[4]
        elif pattern == "do_loop":
            label_idx, goto_idx, tgt = transform[0], transform[1], transform[2]

        # Remove this label from label_at_stmt
        for idx, labels in list(new_label_at_stmt.items()):
            if tgt in labels:
                labels = [l for l in labels if l != tgt]
                if labels:
                    new_label_at_stmt[idx] = labels
                else:
                    del new_label_at_stmt[idx]

        if pattern == "while":
            # L: If cond Then → While cond
            #   ...              ...
            #   GoTo L          (blank)
            # End If           → Wend
            if_stmt = stmts[if_idx]
            cond_text = if_stmt.text[len("If "):-len(" Then")]
            replace[if_idx] = stack_ir.Stmt(if_stmt.va, +1, "While %s" % cond_text,
                                            if_stmt.order)
            blank.add(goto_idx)
            replace[end_if_idx] = stack_ir.Stmt(stmts[end_if_idx].va, -1, "Wend",
                                                stmts[end_if_idx].order)

        elif pattern == "do_loop":
            # L: ...body... GoTo L → Do ...body... Loop
            # Insert Do BEFORE the label's stmt (don't replace it).
            stmts_label = stmts[label_idx]
            insert_before.setdefault(label_idx, []).append(
                stack_ir.Stmt(stmts_label.va, +1, "Do",
                              stmts_label.order))
            stmts_goto = stmts[goto_idx]
            replace[goto_idx] = stack_ir.Stmt(stmts_goto.va, -1, "Loop",
                                              stmts_goto.order)

        elif pattern == "do_while":
            # L: ...body... If cond Then [body2] GoTo L End If
            # → Do ...body... If cond Then [body2] End If Loop While cond
            # Insert Do BEFORE the label's stmt (don't replace it).
            if_stmt = stmts[if_idx]
            cond_text = if_stmt.text[len("If "):-len(" Then")]
            stmts_label = stmts[label_idx]
            insert_before.setdefault(label_idx, []).append(
                stack_ir.Stmt(stmts_label.va, +1, "Do",
                              stmts_label.order))
            blank.add(goto_idx)
            # Insert "Loop While cond" after End If
            stmts_endif = stmts[end_if_idx]
            insert_after.setdefault(end_if_idx, []).append(
                stack_ir.Stmt(stmts_endif.va, -1, "Loop While %s" % cond_text,
                              stmts_endif.order))

        elif pattern == "do_while_empty":
            # L: ...body... If cond Then GoTo L End If
            # → Do ...body... Loop While cond  (If/End If/GoTo all removed)
            # Insert Do BEFORE the label's stmt (don't replace it).
            if_stmt = stmts[if_idx]
            cond_text = if_stmt.text[len("If "):-len(" Then")]
            stmts_label = stmts[label_idx]
            insert_before.setdefault(label_idx, []).append(
                stack_ir.Stmt(stmts_label.va, +1, "Do",
                              stmts_label.order))
            blank.add(if_idx)
            blank.add(goto_idx)
            replace[end_if_idx] = stack_ir.Stmt(stmts[end_if_idx].va, -1,
                                                "Loop While %s" % cond_text,
                                                stmts[end_if_idx].order)

    # Build new stmts list applying replaces, blanks, and inserts.
    new_stmts = []
    for old_i, s in enumerate(stmts):
        if old_i in insert_before:
            new_stmts.extend(insert_before[old_i])
        if old_i in blank:
            continue
        if old_i in replace:
            new_stmts.append(replace[old_i])
        else:
            new_stmts.append(s)
        if old_i in insert_after:
            new_stmts.extend(insert_after[old_i])

    # Rebuild label_at_stmt indices
    old_to_new = {}
    new_i = 0
    for old_i, s in enumerate(stmts):
        if old_i in insert_before:
            new_i += len(insert_before[old_i])
        if old_i not in blank:
            old_to_new[old_i] = new_i
            new_i += 1
            if old_i in insert_after:
                new_i += len(insert_after[old_i])

    new_label_at = {}
    for old_idx, labels in new_label_at_stmt.items():
        new_idx = old_to_new.get(old_idx)
        if new_idx is not None:
            new_label_at[new_idx] = labels

    return new_stmts, new_label_at


def _convert_gotos(stmts, label_at_stmt, proc_start, proc_end):
    """Convert forward GoTo patterns to structured VB constructs.

    Patterns:
    1. Simple skip: GoTo L / End If / L: (label right after End If)
       → remove GoTo + label (GoTo is redundant).
    2. If...Then...Else: GoTo L / End If / ...false branch... / L:
       → If cond Then ... Else ...false... End If (single-target label,
       label at same nesting depth as the If).
    3. Exit For/Exit Do: GoTo L inside loop, L right after loop end
       → replace GoTo with Exit For/Do, remove label.
    """
    import re as _re

    # Build label maps
    label_to_idx = {}
    for idx, labels in label_at_stmt.items():
        for lv in labels:
            label_to_idx[lv] = idx

    label_refcount = {}
    for stmt in stmts:
        for m in _re.finditer(r'GoTo L_([0-9A-F]+)', stmt.text):
            tgt = int(m.group(1), 16)
            label_refcount[tgt] = label_refcount.get(tgt, 0) + 1

    # Nesting depth helper
    def nesting_depth(idx):
        depth = 0
        for j in range(idx):
            if stmts[j].indent_delta == +1:
                depth += 1
            elif stmts[j].indent_delta == -1:
                depth -= 1
        return depth

    # Find loop boundaries
    loops = []
    stk = []
    for i, stmt in enumerate(stmts):
        text = stmt.text.strip()
        if text.startswith('For ') and ' To' in text:
            stk.append((i, 'For'))
        elif text == 'Do':
            stk.append((i, 'Do'))
        elif text.startswith('While '):
            stk.append((i, 'While'))
        elif text == 'Next':
            if stk and stk[-1][1] == 'For':
                s, _ = stk.pop()
                loops.append((s, i, 'For'))
        elif text == 'Loop' or text.startswith('Loop '):
            if stk and stk[-1][1] == 'Do':
                s, _ = stk.pop()
                loops.append((s, i, 'Do'))
        elif text == 'Wend':
            if stk and stk[-1][1] == 'While':
                s, _ = stk.pop()
                loops.append((s, i, 'While'))

    def innermost_loop(idx):
        result = None
        for ls, le, lt in loops:
            if ls < idx < le:
                if result is None or ls > result[0]:
                    result = (ls, le, lt)
        return result

    def remove_label(lat, tgt):
        for idx, labels in list(lat.items()):
            if tgt in labels:
                labels = [l for l in labels if l != tgt]
                if labels:
                    lat[idx] = labels
                else:
                    del lat[idx]

    # Collect operations
    replace = {}
    insert_before = {}
    blank = set()
    new_label_at_stmt = {k: list(v) for k, v in label_at_stmt.items()}

    for i, stmt in enumerate(stmts):
        m = _re.search(r'GoTo L_([0-9A-F]+)', stmt.text)
        if not m:
            continue
        tgt = int(m.group(1), 16)
        if tgt not in label_to_idx:
            continue
        label_idx = label_to_idx[tgt]
        if label_idx <= i:
            continue  # backward GoTo (handled by _convert_loops)

        single_target = label_refcount.get(tgt, 0) == 1
        next_is_endif = (i + 1 < len(stmts)
                         and stmts[i + 1].text.strip() == 'End If')

        if next_is_endif:
            endif_idx = i + 1
            endif_depth = nesting_depth(endif_idx)

            if label_idx == endif_idx + 1:
                # Simple skip: label right after End If — GoTo is redundant.
                blank.add(i)
                remove_label(new_label_at_stmt, tgt)
            elif single_target and label_idx > endif_idx + 1:
                # If...Then...Else: label is after a false branch.
                # Check that label is at the same depth as the code after End If
                # (endif_depth - 1 = depth after End If closes the If).
                label_depth = nesting_depth(label_idx)
                if label_depth == endif_depth - 1:
                    blank.add(i)
                    replace[endif_idx] = stack_ir.Stmt(
                        stmts[endif_idx].va, 0, 'Else',
                        stmts[endif_idx].order)
                    insert_before.setdefault(label_idx, []).append(
                        stack_ir.Stmt(stmts[label_idx].va, -1, 'End If',
                                      stmts[label_idx].order))
                    remove_label(new_label_at_stmt, tgt)
            continue

        # Exit For/Do: GoTo inside loop targeting right after loop end
        loop = innermost_loop(i)
        if loop and single_target:
            ls, le, lt = loop
            if label_idx == le + 1:
                exit_kw = 'Exit For' if lt == 'For' else 'Exit Do'
                replace[i] = stack_ir.Stmt(stmt.va, 0, exit_kw, stmt.order)
                remove_label(new_label_at_stmt, tgt)

    if not replace and not blank and not insert_before:
        return stmts, label_at_stmt

    # Build new stmts list
    new_stmts = []
    for old_i, s in enumerate(stmts):
        if old_i in insert_before:
            new_stmts.extend(insert_before[old_i])
        if old_i in blank:
            continue
        if old_i in replace:
            new_stmts.append(replace[old_i])
        else:
            new_stmts.append(s)

    # Rebuild label_at_stmt indices
    old_to_new = {}
    new_i = 0
    for old_i, s in enumerate(stmts):
        if old_i in insert_before:
            new_i += len(insert_before[old_i])
        if old_i not in blank:
            old_to_new[old_i] = new_i
            new_i += 1

    new_label_at = {}
    for old_idx, labels in new_label_at_stmt.items():
        new_idx = old_to_new.get(old_idx)
        if new_idx is not None:
            new_label_at[new_idx] = labels

    return new_stmts, new_label_at


def _convert_select_case(stmts, label_at_stmt, proc_start, proc_end):
    """Convert multi-target If chains (Select Case patterns) to VB Select Case.

    Pattern:
        If var = N0 Then ...body0... GoTo MERGE End If
        If var = N1 Then ...body1... GoTo MERGE End If
        ...
        If var = Nlast Then ...bodyLast... [MERGE:] End If

    Becomes:
        Select Case var
            Case N0: ...body0...
            Case N1: ...body1...
            ...
            Case Nlast: ...bodyLast...
        End Select

    The MERGE label (and any merge-body after the last End If) stays outside
    the Select Case.
    """
    import re as _re

    # Build label maps
    label_to_idx = {}
    for idx, labels in label_at_stmt.items():
        for lv in labels:
            label_to_idx[lv] = idx

    label_refcount = {}
    for stmt in stmts:
        for m in _re.finditer(r'GoTo L_([0-9A-F]+)', stmt.text):
            tgt = int(m.group(1), 16)
            label_refcount[tgt] = label_refcount.get(tgt, 0) + 1

    # Nesting depth helper
    def nesting_depth(idx):
        depth = 0
        for j in range(idx):
            if stmts[j].indent_delta == +1:
                depth += 1
            elif stmts[j].indent_delta == -1:
                depth -= 1
        return depth

    def remove_label(lat, tgt):
        for idx, labels in list(lat.items()):
            if tgt in labels:
                labels = [l for l in labels if l != tgt]
                if labels:
                    lat[idx] = labels
                else:
                    del lat[idx]

    # Find Select Case patterns
    # For each multi-target label, check if all GoTos are before End If
    # and all Ifs compare the same variable.
    converted = False
    new_label_at_stmt = {k: list(v) for k, v in label_at_stmt.items()}

    # Collect all patterns first, then apply (to avoid index issues)
    patterns = []

    for tgt_va, count in label_refcount.items():
        if count < 2:
            continue
        if tgt_va not in label_to_idx:
            continue
        label_idx = label_to_idx[tgt_va]

        # Find all GoTos to this label
        goto_indices = []
        for i, stmt in enumerate(stmts):
            if _re.search(r'GoTo L_%08X' % tgt_va, stmt.text):
                goto_indices.append(i)

        if len(goto_indices) < 2:
            continue

        # Check all GoTos are before End If
        all_before_endif = True
        if_conds = []  # (goto_idx, if_idx, if_text)
        for gl in goto_indices:
            if gl + 1 >= len(stmts) or stmts[gl + 1].text.strip() != 'End If':
                all_before_endif = False
                break
            # Find matching If (walk backwards)
            depth = 0
            if_idx = None
            for j in range(gl - 1, -1, -1):
                if stmts[j].indent_delta == -1:
                    depth += 1
                elif stmts[j].indent_delta == +1:
                    # Any opener (If, For, While, Do, Select Case, Case)
                    # consumes a nesting level.  Only match when it's an If
                    # at depth 0.
                    if depth == 0 and stmts[j].text.strip().startswith('If '):
                        if_idx = j
                        break
                    depth -= 1
            if if_idx is None:
                all_before_endif = False
                break
            if_conds.append((gl, if_idx, stmts[if_idx].text.strip()))

        if not all_before_endif:
            continue

        # Check all Ifs compare the same variable
        var_name = None
        case_vals = []
        for gl, if_idx, if_text in if_conds:
            m2 = _re.match(r'If (.+?) (=|<|>|<=|>=|<>) (.+) Then', if_text)
            if not m2:
                all_before_endif = False
                break
            vn = m2.group(1).strip()
            if var_name is None:
                var_name = vn
            elif vn != var_name:
                all_before_endif = False
                break
            case_vals.append((m2.group(2), m2.group(3).strip(), if_idx, gl))

        if not all_before_endif or var_name is None:
            continue

        # Verify the Ifs are consecutive: between each If's End If and
        # the next If, there should be no intervening statements.
        # Sort if_conds by if_idx to ensure ascending order.
        if_conds.sort(key=lambda x: x[1])
        consecutive = True
        for k in range(len(if_conds) - 1):
            end_if_k = if_conds[k][0] + 1  # End If after GoTo
            next_if_k = if_conds[k + 1][1]
            if end_if_k + 1 != next_if_k:
                consecutive = False
                break
        if not consecutive:
            continue

        # Find the last If in the chain (the one whose End If is after
        # the last GoTo, or the one containing the label).
        # The chain starts at the first If and ends at the last If's End If.
        first_if_idx = if_conds[0][1]
        last_goto_idx = goto_indices[-1]
        last_endif_idx = last_goto_idx + 1  # End If after last GoTo

        # Check if there's a "last case" If after the last GoTo's End If
        # (this is the If that contains the MERGE label or the default case).
        # The last case If is the one right before the label, or right after
        # the last GoTo's End If.
        last_case_if_idx = None
        last_case_endif_idx = None
        # Check if the stmt after last End If is another If with same var
        next_idx = last_endif_idx + 1
        if next_idx < len(stmts):
            next_text = stmts[next_idx].text.strip()
            m3 = _re.match(r'If (.+?) (=|<|>|<=|>=|<>) (.+) Then', next_text)
            if m3 and m3.group(1).strip() == var_name:
                # This is the last case If
                last_case_if_idx = next_idx
                # Find its End If
                depth2 = 1
                for j in range(next_idx + 1, len(stmts)):
                    if stmts[j].indent_delta == +1:
                        depth2 += 1
                    elif stmts[j].indent_delta == -1:
                        depth2 -= 1
                        if depth2 == 0:
                            last_case_endif_idx = j
                            break
                if last_case_endif_idx is not None:
                    # Extract the final case value.  Its body is copied below.
                    case_vals.append((m3.group(2), m3.group(3).strip(),
                                      last_case_if_idx, None))

        # Determine the range to replace
        if last_case_if_idx is not None:
            chain_end = last_case_endif_idx
        else:
            chain_end = last_endif_idx

        # Build the new statements
        new_stmts_list = []
        # Select Case var
        new_stmts_list.append(stack_ir.Stmt(
            stmts[first_if_idx].va, +1, 'Select Case %s' % var_name,
            stmts[first_if_idx].order))

        for ci, (op, val, if_idx, gl) in enumerate(case_vals):
            # Case label
            if op == '=':
                case_text = 'Case %s' % val
            else:
                case_text = 'Case Is %s %s' % (op, val)
            case_delta = +1 if ci == 0 else 0  # first Case opens, rest are special
            new_stmts_list.append(stack_ir.Stmt(
                stmts[if_idx].va, case_delta, case_text, stmts[if_idx].order))

            # Body: copy stmts between If and End If (or between If and GoTo)
            if gl is not None:
                # Regular case: body is between If and GoTo
                for j in range(if_idx + 1, gl):
                    new_stmts_list.append(stmts[j])
                # GoTo is removed (not copied)
                # End If is removed (not copied)
            else:
                # Last case: body is between If and End If (excluding label)
                for j in range(if_idx + 1, last_case_endif_idx):
                    # Skip the GoTo if present (shouldn't be, but just in case)
                    if 'GoTo' in stmts[j].text:
                        continue
                    new_stmts_list.append(stmts[j])
                # End If is replaced by End Select

        # End Select
        new_stmts_list.append(stack_ir.Stmt(
            stmts[chain_end].va, -1, 'End Select', stmts[chain_end].order))

        patterns.append({
            'first_if_idx': first_if_idx,
            'chain_end': chain_end,
            'new_stmts': new_stmts_list,
            'tgt_va': tgt_va,
        })
        remove_label(new_label_at_stmt, tgt_va)

    if not patterns:
        return stmts, label_at_stmt

    # Sort patterns by start index (descending) to avoid index shifts
    patterns.sort(key=lambda p: p['first_if_idx'], reverse=True)

    # Apply replacements
    new_stmts = list(stmts)
    for pat in patterns:
        start = pat['first_if_idx']
        end = pat['chain_end']
        new_stmts = new_stmts[:start] + pat['new_stmts'] + new_stmts[end + 1:]

    # Rebuild labels after replacements.  Labels for converted targets were
    # removed above; remaining labels are reattached by target VA.

    new_label_at = {}
    remaining_labels = {}
    for idx, labels in new_label_at_stmt.items():
        for lv in labels:
            remaining_labels[lv] = idx

    if remaining_labels:
        # Map each remaining label to the new stmt index
        # by finding the first new stmt with VA >= label VA
        sorted_labels = sorted(remaining_labels.keys())
        label_iter = iter(sorted_labels)
        next_label = next(label_iter, None)
        for new_idx, stmt in enumerate(new_stmts):
            while next_label is not None and next_label <= stmt.va:
                new_label_at.setdefault(new_idx, []).append(next_label)
                next_label = next(label_iter, None)
        # Any remaining labels go on the last stmt
        if next_label is not None:
            last = len(new_stmts) - 1
            while next_label is not None:
                new_label_at.setdefault(last, []).append(next_label)
                next_label = next(label_iter, None)

    return new_stmts, new_label_at


def decompile_proc(pal, analysis, index, name, arg_map=None, exit_addrs=None):
    """Decompile one procedure into VB pseudocode text."""
    start, end, instrs = build_instrs(pal, analysis, index)
    entry_stub = analysis["method_stubs"].get(end)

    # Classify each param slot ByRef/ByVal using the same rule as the disasm
    # (word_disasm.classify_params).  The ByRef/ByVal annotation goes directly
    # into the pseudocode signature here, so remap.py only needs to do plain
    # name substitution (preserving the prefix) on pal_code.txt.
    kinds = word_disasm.classify_params([(i.label, i.operand) for i in instrs])[1]

    # Build parameter list and a substitution map for stack+N references.
    nargs = (arg_map or {}).get(name, 0)
    params = []
    param_map = {8: "Me"}   # stack+8 is always the implicit object base
    for i in range(nargs):
        pname = "a%d" % i
        if i < len(kinds) and kinds[i] == "ByRef":
            params.append("ByRef " + pname)   # signature: prefix ByRef
        else:
            params.append(pname)   # body refs stay plain a0/a1/...
        param_map[8 + 4 * (i + 1)] = pname

    sig = "Sub %s(%s)" % (name, ", ".join(params))
    if entry_stub:
        sig += "  ' MethCallEngine entry"

    if not instrs:
        return "%s\n    ' (empty procedure)\nEnd Sub" % sig

    machine = stack_ir.StackMachine()
    machine.proc_start = start
    machine.proc_end = end
    machine.arg_map = arg_map or {}
    machine.param_map = param_map
    for instr in instrs:
        machine.process(instr)
    # Close any remaining open Ifs at end of proc.
    machine.close_ifs(end)
    machine.close_crossproc_ifs()
    machine.flush_leftovers(end)

    # Post-process GoTo statements:
    #  1. GoTo targeting an ExitProc* address -> "Exit Sub"
    #  2. Resolve chained GoTos (GoTo A where A is itself a GoTo B)
    #  3. Collect intra-proc GoTo targets that need labels.
    stmts = machine.statements
    import re as _re

    # Build a map: VA -> GoTo target VA, for all GoTo statements.
    # This lets us resolve chained GoTos (GoTo A → GoTo B → ...).
    goto_target_at_va = {}
    for stmt in stmts:
        m = _re.search(r'GoTo L_([0-9A-F]+)', stmt.text)
        if m:
            tgt = int(m.group(1), 16)
            goto_target_at_va[stmt.va] = tgt

    def _resolve_chain(tgt, depth=0):
        """Follow chained GoTos to the final target."""
        seen = set()
        while depth < 20:
            if tgt in seen:
                break  # cycle
            seen.add(tgt)
            next_tgt = goto_target_at_va.get(tgt)
            if next_tgt is None:
                break
            tgt = next_tgt
            depth += 1
        return tgt

    # Resolve chained GoTos in all GoTo statements.
    for stmt in stmts:
        m = _re.search(r'GoTo L_([0-9A-F]+)', stmt.text)
        if not m:
            continue
        tgt = int(m.group(1), 16)
        final = _resolve_chain(tgt)
        if final != tgt:
            stmt.text = stmt.text.replace(
                'GoTo L_%08X' % tgt, 'GoTo L_%08X' % final)

    label_targets = set()   # intra-proc addresses that need a label
    for stmt in stmts:
        m = _re.search(r'GoTo L_([0-9A-F]+)', stmt.text)
        if not m:
            # Also check for GoSub targets.
            m = _re.search(r'GoSub L_([0-9A-F]+)', stmt.text)
        if not m:
            continue
        tgt = int(m.group(1), 16)
        if exit_addrs and tgt in exit_addrs:
            # Branch to an ExitProc instruction = early exit from the proc.
            stmt.text = "Exit Sub"
        elif start <= tgt < end:
            # Intra-proc target — will need a label at the target stmt.
            label_targets.add(tgt)

    # Map each label target to the first stmt with VA >= target.
    # A GoTo may target a LOAD/PLUMBING instruction that doesn't produce
    # a statement (it folds into a later expression).  The label must go
    # on the next stmt that does produce output.
    label_at_stmt = {}  # stmt index -> sorted list of label addresses
    remaining = sorted(label_targets)
    for i, stmt in enumerate(stmts):
        while remaining and remaining[0] <= stmt.va:
            label_at_stmt.setdefault(i, []).append(remaining.pop(0))
    # Any remaining targets (all > every stmt VA) go on the last stmt.
    if remaining:
        last_i = len(stmts) - 1
        label_at_stmt.setdefault(last_i, []).extend(remaining)

    # Convert backward-GoTo loop patterns to While/Do loops.
    stmts, label_at_stmt = _convert_loops(stmts, label_at_stmt, start, end)

    # Convert forward-GoTo patterns to If...Else / Exit For-Do / simple skip.
    stmts, label_at_stmt = _convert_gotos(stmts, label_at_stmt, start, end)

    # Convert multi-target If chains to Select Case.
    stmts, label_at_stmt = _convert_select_case(stmts, label_at_stmt, start, end)

    # Post-process: when a label's VA matches a closer's VA, the label
    # is a merge point that belongs AFTER the closer (not before it).
    # If there are consecutive closers at the same VA (nested Ifs that
    # all close at the same BranchF target), the label must go after ALL
    # of them.  Move such labels forward to the first non-closer stmt.
    if label_at_stmt:
        adjusted = {}
        for idx in sorted(label_at_stmt):
            labels = sorted(label_at_stmt[idx])
            if idx >= len(stmts):
                adjusted[idx] = labels
                continue
            stmt = stmts[idx]
            is_closer = (stmt.indent_delta < 0
                         or stmt.text == 'End Select')
            if not is_closer:
                adjusted[idx] = labels
                continue
            # Split: VA < stmt.va stays before closer;
            # VA >= stmt.va moves after all consecutive closers at this VA.
            stay = [t for t in labels if t < stmt.va]
            move = [t for t in labels if t >= stmt.va]
            if stay:
                adjusted[idx] = stay
            if move:
                skip_va = stmt.va
                j = idx + 1
                while j < len(stmts):
                    sj = stmts[j]
                    sj_closer = (sj.indent_delta < 0
                                 or sj.text == 'End Select')
                    if sj_closer and sj.va == skip_va:
                        j += 1
                    else:
                        break
                existing = adjusted.get(j, [])
                adjusted[j] = sorted(set(existing) | set(move))
        label_at_stmt = adjusted

    # Dead code elimination: after a terminator (GoTo, Exit Sub, Return),
    # remove unreachable GoTo/Exit Sub statements until the next structural
    # marker (End If, Next, Wend, Loop, End Select, Else, Case) or label.
    structural_markers = {'End If', 'End Select', 'Next', 'Wend', 'Loop',
                          'Loop While', 'Else'}
    terminators = ('GoTo ', 'Exit Sub', 'Exit For', 'Exit Do', 'Return')
    label_indices = set(label_at_stmt.keys())
    dead = set()
    in_dead_zone = False
    for i, stmt in enumerate(stmts):
        if i in dead:
            continue
        text = stmt.text.strip()
        if in_dead_zone:
            # Check if this is a structural marker or label target.
            is_marker = (text in structural_markers
                         or text.startswith('Case ')
                         or text.startswith('Loop '))
            is_label_target = i in label_indices
            if is_marker or is_label_target:
                in_dead_zone = False
            elif text.startswith(terminators):
                # Dead GoTo/Exit Sub after a terminator.
                dead.add(i)
            # Other statements (assignments, calls) in the dead zone are
            # kept — they may produce output needed for structure balance.
        else:
            if text.startswith(terminators) and text != 'Return':
                in_dead_zone = True
            elif text == 'Return':
                in_dead_zone = True
    if dead:
        new_stmts = []
        new_label_at = {}
        old_to_new = {}
        for i, stmt in enumerate(stmts):
            if i in dead:
                continue
            new_idx = len(new_stmts)
            old_to_new[i] = new_idx
            new_stmts.append(stmt)
        for idx, labels in label_at_stmt.items():
            new_idx = old_to_new.get(idx)
            if new_idx is not None:
                new_label_at[new_idx] = labels
            else:
                # Label was on a dead stmt — find next alive stmt.
                for j in range(idx + 1, len(stmts)):
                    if j not in dead:
                        new_idx = old_to_new[j]
                        new_label_at.setdefault(new_idx, []).extend(labels)
                        break
        stmts = new_stmts
        label_at_stmt = new_label_at

    lines = [sig]
    indent = 1
    for i, stmt in enumerate(stmts):
        labels_here = sorted(label_at_stmt.get(i, []))
        is_closer = (stmt.indent_delta < 0
                     or stmt.text == 'End Select')
        if is_closer:
            # For closers, labels with VA == stmt.va are merge points
            # that belong AFTER the closer (at the outer level).
            # Labels with VA < stmt.va go before the closer.
            labels_before = [t for t in labels_here if t < stmt.va]
            labels_after = [t for t in labels_here if t >= stmt.va]
        else:
            labels_before = labels_here
            labels_after = []
        # Labels are always at column 0 (VB convention for line labels).
        for tgt in labels_before:
            lines.append("L_%08X:" % tgt)
        if stmt.text == 'Else':
            # Else prints at the opener's indent (one level less than
            # the body), but does not change the indent for the body.
            prefix = "    " * max(1, indent - 1)
            lines.append("%s%s" % (prefix, stmt.text))
        elif stmt.text == 'End Select':
            # End Select closes both the last Case body and the Select block.
            indent -= 2
            if indent < 1:
                indent = 1
            prefix = "    " * indent
            lines.append("%s%s" % (prefix, stmt.text))
        elif stmt.text.startswith('Case ') and stmt.indent_delta == 0:
            # Subsequent Case: print at Select level (one less than body),
            # keep indent unchanged for the body.
            prefix = "    " * max(1, indent - 1)
            lines.append("%s%s" % (prefix, stmt.text))
        elif stmt.indent_delta < 0:
            # Closing keyword (End If, Next): decrease first, then print
            # at the same indent as the matching opener.
            indent += stmt.indent_delta
            if indent < 1:
                indent = 1
            prefix = "    " * indent
            lines.append("%s%s" % (prefix, stmt.text))
        else:
            # Opener (If, For): print at current indent, then increase
            # so the body is indented one level deeper.
            prefix = "    " * indent
            lines.append("%s%s" % (prefix, stmt.text))
            indent += stmt.indent_delta
            if indent < 1:
                indent = 1
        for tgt in labels_after:
            lines.append("L_%08X:" % tgt)
    lines.append("End Sub")
    return "\n".join(lines)


def decompile_all(pal, analysis, procs):
    """Decompile all procedures.  Returns full text."""
    arg_counts = _build_arg_counts(pal, analysis)
    # Map proc name -> arg_count.
    arg_map = {}
    for idx, (_ps, _pd, name) in enumerate(procs):
        arg_map[name] = arg_counts.get(idx, 0)
    exit_addrs = _build_exit_addrs(analysis)
    out = []
    out.append("VB4 p-code decompilation (VB-style pseudocode)")
    out.append("Procedures: %d\n" % len(procs))
    for idx, (_ps, _pd, name) in enumerate(procs):
        out.append(decompile_proc(pal, analysis, idx, name,
                                  arg_map=arg_map, exit_addrs=exit_addrs))
        out.append("")
    return "\n".join(out)
