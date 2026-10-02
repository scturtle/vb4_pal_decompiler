"""CFG + dominator-based control-flow structuring.

Pipeline per procedure (the stack machine only folds expressions):
CFG -> dominators/postdominators -> natural loops (irreducible SCCs
render as flat GoTo blocks) -> recursive structuring (If/ElseIf/Else
from postdominator joins, While/Do/For..Next from loop analysis, Exit
For/Do/Sub for region-leaving edges, GoTo+label for the rest).  VB4
has no short-circuit And/Or, so conditions are single folded
expressions; unrepresentable shapes raise StructureUnsupported (the
driver isolates per-proc error stubs).
"""

import stack_ir
from collections import deque
from stack_ir import strip


class StructureUnsupported(Exception):
    """CFG shape beyond what the structurer handles."""


# True-polarity branch opcodes (BranchF* variants live only in
# COND_BRANCH); emission sites test membership to pick the DISPLAYED condition.
_BRANCH_TRUE = ("BranchT", "BranchTVar", "BranchTVarFree")

# Largest body trusting the latch_pred heuristic (bare-branch latch
# whose sole pred is the closing test); larger cond+latch-trampoline
# bodies are state machines, not tests.
# TUNING NOTE: shifts Do..Loop While/Until vs plain Do; re-run the
# golden hash gate after changes.
_LATCH_PRED_MAX_BODY = 4

# Step cap for the bounded reachability walks (_arm_ok, _arm_reaches,
# _side_reaches_join): cheap insurance against quadratic blowup.
_ARM_WALK_MAX = 512

# Maximum ElseIf legs in one structural test ladder.
_CHAIN_MAX_LEGS = 64

# Maximum bare-uncond trampoline hops when threading an edge's
# effective target (_exit_stmt_for_target, _side_reaches_join).
_TRAMP_HOPS_MAX = 8

# Labels that never emit statements: pure stack/value plumbing.  A
# header made only of these is "condition-only" (While-shaped).
_NO_EMIT_LABELS = frozenset(
    stack_ir.LOAD_LABELS | stack_ir.PLUMBING | stack_ir.CONV_LABELS
    | stack_ir.FFREE_LABELS | stack_ir.ARY_LOAD | stack_ir.ARY_N_LOAD
    | stack_ir.MEM_LD | stack_ir.FIXED_STR_LOAD
    | set(stack_ir.BINARY_OPS) | set(stack_ir.COMPARE_OPS)
    | set(stack_ir.UNARY_OPS) | set(stack_ir.VAR_BINARY_OPS)
    | {"LitVar_Missing"})


# ----------------------------------------------------------------------
# CFG
# ----------------------------------------------------------------------

def _wrap_not(cond_text):
    """Display negation of *cond_text*: collapse "Not (Not x)", invert a
    top-level comparison, or mask-test against 0.  VB4's Not is bitwise
    on Integer: double negation is the identity, and on comparison
    results (-1/0) the exact inverse ("Not (x = c)" -> "x <> c").
    Only a TOP-LEVEL comparison inverts; connectors keep their Not."""
    if cond_text.startswith("Not (") and cond_text.endswith(")"):
        depth = 0
        for i, ch in enumerate(cond_text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(cond_text) - 1:
                    # outer group closes early: the trailing ")" is
                    # not its partner ("Not (x) = y") -- not a wrapper
                    break
        else:
            if depth == 0:
                return cond_text[5:-1]
    inv = _invert_cmp(cond_text)
    if inv is not None:
        return inv
    mz = _mask_zero(cond_text)
    if mz is not None:
        return mz
    return "Not (%s)" % cond_text


def _scan_top_level(text):
    """Yield (index, char) at paren depth 0, outside string literals:
    the one scanner shared by _top_level_splits/_has_top_cmp/
    _invert_cmp so the passes cannot diverge.  A ')' closing back to
    depth 0 is yielded (inert: never starts a word)."""
    depth = 0
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0:
            yield i, ch
        i += 1


def _word_bounded(text, i, w):
    """True when text[i:i+w] is surrounded by non-word characters
    (a string edge counts as a boundary)."""
    before = text[i-1] if i > 0 else " "
    after = text[i+w] if i + w < len(text) else " "
    return not (before.isalnum() or before in "_.") \
        and not (after.isalnum() or after in "_.")


def _top_level_splits(cond_text, word):
    """Yield (lhs, rhs) splits at every top-level word-bounded *word*
    (quote- and paren-aware), or nothing."""
    w = len(word)
    for i, _ch in _scan_top_level(cond_text):
        # position 0 has no LEFT word boundary: a split there would
        # have an empty lhs
        if i == 0 or not cond_text.startswith(word, i):
            continue
        if _word_bounded(cond_text, i, w):
            yield cond_text[:i].rstrip(), cond_text[i+w:].lstrip()


def _has_top_cmp(text):
    """True when *text* has a top-level comparison operator."""
    for _lhs, _rhs in _top_level_splits(text, "="):
        return True
    for op in ("<=", ">=", "<>", "<", ">"):
        for i, _ch in _scan_top_level(text):
            if text.startswith(op, i):
                return True
    return False


def _mask_zero(cond_text):
    """'(<expr> And <int-literal>) = 0' -- the faithful negation of a
    bitmask test (VB's If is truthy on ANY nonzero value, so
    'Not (x And 8)' is TRUE even with the bit set: Not 8 = -9).  Only
    a LITERAL-mask And qualifies.  The outer parens are REQUIRED:
    comparisons bind tighter than And."""
    for lhs, rhs in _top_level_splits(cond_text, "And"):
        l, r = lhs.strip(), rhs.strip()
        for a, b in ((l, r), (r, l)):
            if a != "" and b != "" \
                    and a.lstrip("-").isdigit() \
                    and not _has_top_cmp(b):
                return "(%s) = 0" % cond_text
    return None


_CMP_INV = {"=": "<>", "<>": "=", "<": ">=", ">": "<=",
            "<=": ">", ">=": "<"}


def _invert_cmp(cond_text):
    """Top-level comparison inversion, or None when inapplicable: the
    comparison must be THE top-level operator (a top-level connector
    needs De Morgan -- refuse; each connector matches at its OWN
    length -- the old [i:i+3] test never matched the 2-char "Or")."""
    connectors = ("And", "Or", "Xor", "Eqv", "Imp")
    for i, _ch in _scan_top_level(cond_text):
        for cn in connectors:
            if cond_text.startswith(cn, i) \
                    and _word_bounded(cond_text, i, len(cn)):
                return None       # top-level boolean compound
    for i, _ch in _scan_top_level(cond_text):
        for op in ("<=", ">=", "<>", "<", ">", "="):
            if cond_text.startswith(op, i):
                lhs = cond_text[:i].rstrip()
                rhs = cond_text[i + len(op):].lstrip()
                if lhs and rhs:
                    return "%s %s %s" % (lhs, _CMP_INV[op], rhs)
                return None
    return None


class Block(object):
    """One basic block: straight-line instrs plus a single control exit."""

    __slots__ = ("start", "index", "instrs", "term", "kind",
                 "fall", "taken", "taken_va", "preds")

    def __init__(self, start, index, instrs):
        self.start = start            # VA of the first instruction
        self.index = index
        self.instrs = instrs          # [_Instr, ...]
        self.term = instrs[-1] if instrs else None
        # kind: "cond" | "uncond" | "gosub" | "term" | "for" | "next" | None
        self.kind = None
        self.fall = None              # fall-through successor (Block or None)
        self.taken = None             # branch target successor (Block or None)
        self.taken_va = None          # raw branch target VA (even cross-proc)
        self.preds = []

    def __repr__(self):
        return "Block(0x%08X, kind=%s)" % (self.start, self.kind)


def _succs(b):
    return [s for s in (b.fall, b.taken) if s is not None]


def build_cfg(instrs, proc_start, proc_end):
    """Slice a decoded instruction stream into basic blocks.  Returns
    (blocks_in_addr_order, block_by_start, entry_block)."""
    if not instrs:
        return [], {}, None
    addr_index = {ins.pos: i for i, ins in enumerate(instrs)}

    def in_proc(va):
        return va is not None and proc_start <= va < proc_end

    leaders = set([instrs[0].pos])
    for i, ins in enumerate(instrs):
        lab = ins.label
        nxt = instrs[i + 1].pos if i + 1 < len(instrs) else None
        if lab in stack_ir.COND_BRANCH or lab in stack_ir.UNCOND_BRANCH \
                or lab in stack_ir.LOOP_START or lab in stack_ir.LOOP_END:
            tgt = stack_ir.parse_target(ins.operand)
            if in_proc(tgt) and tgt in addr_index:
                leaders.add(tgt)
            if nxt is not None:
                leaders.add(nxt)
        elif lab in stack_ir.TERMINATOR_LABELS or lab == "Return":
            if nxt is not None:
                leaders.add(nxt)

    sorted_leaders = sorted(leaders)
    blocks = []
    block_by_start = {}
    for li, va in enumerate(sorted_leaders):
        end_va = (sorted_leaders[li + 1] if li + 1 < len(sorted_leaders)
                  else instrs[-1].pos + instrs[-1].size)
        idx = addr_index[va]
        blk_instrs = []
        j = idx
        while j < len(instrs) and instrs[j].pos < end_va:
            blk_instrs.append(instrs[j])
            j += 1
        b = Block(va, li, blk_instrs)
        blocks.append(b)
        block_by_start[va] = b

    # Terminals and edges.
    for bi, b in enumerate(blocks):
        term = b.term
        if term is None:
            continue
        lab = term.label
        if lab in stack_ir.COND_BRANCH:
            b.kind = "cond"
        elif lab == "Branch":
            b.kind = "uncond"
        elif lab == "Gosub":
            b.kind = "gosub"
        elif lab in stack_ir.TERMINATOR_LABELS or lab == "Return":
            b.kind = "term"
        elif lab in stack_ir.LOOP_START:
            b.kind = "for"
        elif lab in stack_ir.LOOP_END:
            b.kind = "next"
        # else: plain fall-through block (kind stays None)
        if b.kind in ("cond", "uncond", "gosub", "for", "next"):
            b.taken_va = stack_ir.parse_target(term.operand)
            b.taken = block_by_start.get(b.taken_va)
        if b.kind in ("term", "uncond"):
            continue  # no fall-through
        # Other kinds fall into the next block in address order: a
        # fall edge never leaves the proc (only taken can be
        # cross-proc; b.taken is None then).
        if bi + 1 < len(blocks):
            b.fall = blocks[bi + 1]

    for b in blocks:
        for s in _succs(b):
            s.preds.append(b)

    entry = blocks[0] if blocks else None
    return blocks, block_by_start, entry


# ----------------------------------------------------------------------
# Dominators / postdominators (Cooper-Harvey-Kennedy)
# ----------------------------------------------------------------------

def _dominators(succ_map, preds_map, entry):
    """CHK iterative dominators.  Returns {node: idom or None}."""
    # Postorder from entry.
    postorder = []
    seen = {entry}
    stack = [(entry, iter(succ_map.get(entry, ())))]
    while stack:
        node, it = stack[-1]
        advanced = False
        for s in it:
            if s not in seen:
                seen.add(s)
                stack.append((s, iter(succ_map.get(s, ()))))
                advanced = True
                break
        if not advanced:
            postorder.append(node)
            stack.pop()
    po_index = {n: i for i, n in enumerate(postorder)}
    rpo = [n for n in reversed(postorder) if n is not entry]

    idom = {entry: entry}

    def intersect(a, b):
        # Walk the deeper finger up toward the entry; the assert
        # guards an aliased po_index that would hang.
        while a is not b:
            assert po_index[a] != po_index[b], \
                "po_index not per-node: fingers aliased"
            while po_index[a] < po_index[b]:
                a = idom[a]
            while po_index[b] < po_index[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for b in rpo:
            preds = [p for p in preds_map.get(b, ()) if p in idom]
            if not preds:
                continue
            new = preds[0]
            for p in preds[1:]:
                new = intersect(p, new)
            if idom.get(b) is not new:
                idom[b] = new
                changed = True
    idom[entry] = None
    return idom


def _reachability(blocks, entry):
    succ_map = {b: _succs(b) for b in blocks}
    reachable = set()
    if entry is not None:
        work = [entry]
        reachable.add(entry)
        while work:
            b = work.pop()
            for s in succ_map[b]:
                if s not in reachable:
                    reachable.add(s)
                    work.append(s)
    return reachable, succ_map


def compute_idom(blocks, entry, reachable):
    succ_map = {b: _succs(b) for b in blocks if b in reachable}
    preds_map = {}
    for b in succ_map:
        for s in succ_map[b]:
            preds_map.setdefault(s, []).append(b)
    return _dominators(succ_map, preds_map, entry)


def compute_ipost(blocks, reachable):
    """Immediate postdominators via the reverse graph (virtual exit
    root, every no-successor block flows into it; conds whose taken
    edge leaves the proc contribute only their fall edge).  When
    nothing reaches an exit, _refine_ipost_in_loops fills in joins."""
    EXIT = "__exit__"
    # rsucc[n] = original preds of n (+ EXIT -> exit blocks);
    # rpreds[n] = original succs of n (+ exit blocks -> EXIT).
    rsucc = {EXIT: []}
    rpreds = {}
    for b in blocks:
        if b not in reachable:
            continue
        succs = _succs(b)
        if not succs:
            rsucc[EXIT].append(b)
            rpreds.setdefault(b, []).append(EXIT)
        for s in succs:
            rsucc.setdefault(s, []).append(b)
            rpreds.setdefault(b, []).append(s)
    if not rsucc[EXIT]:
        return {}
    idom = _dominators(rsucc, rpreds, EXIT)
    ipost = {}
    for b in blocks:
        if b in reachable:
            d = idom.get(b)
            ipost[b] = None if d is EXIT else d
    return ipost


# ----------------------------------------------------------------------
# Loop analysis
# ----------------------------------------------------------------------

def analyze_loops(blocks, entry, reachable, idom):
    """Natural loops via back edges; irreducible SCCs via Tarjan.
    Returns (loops, irreducible): loops = {header: {"body": set,
    "latches": [...]}}; irreducible = SCC blocks without a dominating
    header.  Dominator sets via idom chains."""
    dom_set = {}
    for b in reachable:
        chain = []
        cur = b
        while cur is not None:
            chain.append(cur)
            cur = idom.get(cur)
        dom_set[b] = set(chain)

    loops = {}
    for u in reachable:
        for h in _succs(u):
            if h in dom_set[u]:  # back edge u -> h
                info = loops.setdefault(h, {"body": set([h]), "latches": []})
                info["latches"].append(u)
                # Natural loop: nodes reaching u without passing h;
                # unreachable preds are filtered (they skew the heuristics).
                work = [u]
                while work:
                    n = work.pop()
                    if n in info["body"]:
                        continue
                    info["body"].add(n)
                    for p in n.preds:
                        if p is not h and p in reachable:
                            work.append(p)
                info["body"].add(h)

    # Tarjan SCC over the reachable subgraph.
    index_of, lowlink, on_stack = {}, {}, set()
    scc_stack = []
    counter = [0]
    sccs = []

    # Iterative Tarjan (deep recursion risk on big procs).
    for root in reachable:
        if root in index_of:
            continue
        work = [(root, iter(_succs(root)))]
        index_of[root] = lowlink[root] = counter[0]
        counter[0] += 1
        scc_stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for s in it:
                if s not in index_of:
                    index_of[s] = lowlink[s] = counter[0]
                    counter[0] += 1
                    scc_stack.append(s)
                    on_stack.add(s)
                    work.append((s, iter(_succs(s))))
                    advanced = True
                    break
                elif s in on_stack:
                    lowlink[node] = min(lowlink[node], index_of[s])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == index_of[node]:
                comp = []
                while True:
                    n = scc_stack.pop()
                    on_stack.discard(n)
                    comp.append(n)
                    if n is node:
                        break
                if len(comp) > 1:
                    sccs.append(comp)

    irreducible = set()
    for comp in sccs:
        comp_set = set(comp)
        headers = [h for h in comp
                   if all(h in dom_set[n] for n in comp)]
        if not headers:
            irreducible |= comp_set
    return loops, irreducible


# ----------------------------------------------------------------------
# Structurer
# ----------------------------------------------------------------------

class LoopCtx(object):
    __slots__ = ("kind", "header", "body", "latch", "exit_block", "depth",
                 "shared_exit")

    def __init__(self, kind, header, body, latch, exit_block, depth):
        self.kind = kind          # "while" | "dowhile" | "do" | "for"
        self.header = header
        self.body = body
        self.latch = latch
        self.exit_block = exit_block
        self.depth = depth
        # True when exit_block is a hoisted shared epilogue (the Exit
        # Do upgrade): falling into it from ANY walk inside the loop
        # renders the exit statement, never the epilogue inline (the
        # natural path renders it once after Loop).
        self.shared_exit = False


class Structurer(object):
    def __init__(self, instrs, proc_start, proc_end, machine, exit_addrs,
                 exit_stmt):
        self.proc_start = proc_start
        self.proc_end = proc_end
        self.machine = machine
        self.exit_addrs = exit_addrs or set()
        self.exit_stmt = exit_stmt   # "Exit Sub" / "Exit Function"
        # Fail fast on machines without the exit_keyword contract.
        self._exit_keyword = getattr(machine, "exit_keyword", None)
        if self._exit_keyword is None:
            raise ValueError("machine must expose exit_keyword")

        self.blocks, self.block_by_start, self.entry = \
            build_cfg(instrs, proc_start, proc_end)
        self.reachable, _ = _reachability(self.blocks, self.entry)
        self.idom = compute_idom(self.blocks, self.entry, self.reachable)
        self.ipost = compute_ipost(self.blocks, self.reachable)
        self.loops, self.irreducible = \
            analyze_loops(self.blocks, self.entry, self.reachable, self.idom)
        # For-loop headers are driven by their ForI2 preheader, not as
        # generic loops.
        self.for_headers = set()
        for b in self.blocks:
            if b.kind == "for" and b.fall is not None:
                self.for_headers.add(b.fall)
        # block_first_stmt: VA -> first emitted stmt index (labels).
        self.block_first_stmt = {}
        self.stats = {
            "blocks": len(self.blocks),
            "loops": 0,
            "gotos": 0,
            # Back edges rendered as Continue Do/For/While (VB4 spells
            # them "label + GoTo").
            "continues": 0,
            # Out-of-proc GoTos never resolve; counted for probes
            # (zero probed).
            "cross_proc_gotos": 0,
            "exits": 0,
            "irreducible": len(self.irreducible),
            "unreachable": len(self.blocks) - len(self.reachable),
            "unsupported": None,
        }
        self._refine_ipost_in_loops()

        # Blocks on or inside a cycle: a cond side reaching one is a
        # CONTINUATION (not a handler): jumped to, not inlined.
        self._cyclic_blocks = set(self.irreducible) | set(self.for_headers)
        for info in self.loops.values():
            self._cyclic_blocks |= info["body"]
        # Every loop's latch: never penetrated by an exit-edge jump
        # (its label is the gold-locked Loop close; `stop` guards the
        # main walk, this set guards the orphan pass).
        self._latches = set()
        for info in self.loops.values():
            self._latches.update(info["latches"])
        # Blocks reaching the virtual exit: compute_ipost sees only
        # exit-reaching paths, so a non-exiting side makes the SIBLING
        # the spurious "join".
        self._reaches_exit = set(b for b in self.blocks if b in self.reachable
                                 and not _succs(b))
        work = list(self._reaches_exit)
        while work:
            n = work.pop()
            for p in n.preds:
                if p in self.reachable and p not in self._reaches_exit:
                    self._reaches_exit.add(p)
                    work.append(p)

        self.visited = set()
        self.needed_labels = set()
        # Bare proc-exit joins currently folded by _emit_if_join_exit.
        self._if_join_exit_stack = []
        # Depth of in-progress leaving-side walks: the "fall exits
        # loop" safety net must not fire there (by design).
        self._leaving_side_depth = 0
        # #19 edge audit: every implicit walk transition logs here;
        # run() verifies the target renders adjacent (an inserted
        # region = an intercepted fall = silent flow change).
        self._edge_log = []
        self._last_begin = None
        self._emitting_orphans = False

    def _can_reach(self, src, dst):
        """True if *dst* is reachable from *src* over the static CFG."""
        if src is dst:
            return True
        seen = set()
        work = [src]
        while work:
            n = work.pop()
            for s in (n.fall, n.taken):
                if s is None:
                    continue
                if s is dst:
                    return True
                if s not in seen:
                    seen.add(s)
                    work.append(s)
        return False

    @staticmethod
    def _enclosing_loop_blocks(ctx):
        """Union of every enclosing loop's body (covers nested
        sub-cycles too)."""
        excl = set()
        for c in ctx:
            excl |= c.body
        return excl

    def _reaches_cycle(self, blk, ignore_cycles_in=frozenset()):
        """True if any cyclic block is reachable from *blk*: a side
        running into ongoing control flow is a continuation,
        straight-line sides converging on an exit are handlers.
        Cycles inside *ignore_cycles_in* are traversed but never
        counted (re-entering an ENCLOSING loop is no continuation)."""
        seen = set()
        work = [blk]
        while work:
            n = work.pop()
            if n in seen:
                continue
            seen.add(n)
            if n not in ignore_cycles_in and n in self._cyclic_blocks:
                return True
            for s in (n.fall, n.taken):
                if s is not None and s not in seen:
                    work.append(s)
        return False

    def _refine_ipost_in_loops(self):
        """Fill in ipost for blocks that cannot reach the proc exit: an
        infinite outer loop leaves inner blocks ipost=None.  When a
        loop header dominates its body, the header plays the virtual
        exit (outgoing edges cut) and ipost is recomputed over the
        body subgraph."""
        # Deterministic order: the first loop to assign wins (a hash
        # order would depend on PYTHONHASHSEED).
        for h, info in sorted(self.loops.items(),
                              key=lambda kv: kv[0].start):
            if h not in self.reachable or h in self.for_headers:
                continue
            body = set(info["body"])
            # The header must dominate every body block.
            dominated = True
            for n in body:
                if n is h:
                    continue
                cur = n
                ok = False
                while cur is not None:
                    if cur is h:
                        ok = True
                        break
                    cur = self.idom.get(cur)
                if not ok:
                    dominated = False
                    break
            if not dominated:
                continue
            # Local reverse graph; the header is the virtual exit.
            rsucc = {h: []}
            rpreds = {}
            for n in body:
                if n is h:
                    continue
                succs = [s2 for s2 in (n.fall, n.taken)
                         if s2 is not None and s2 in body]
                if not succs:
                    rsucc[h].append(n)
                    rpreds.setdefault(n, []).append(h)
                for s2 in succs:
                    rsucc.setdefault(s2, []).append(n)
                    rpreds.setdefault(n, []).append(s2)
            if not rsucc[h]:
                continue
            idom_local = _dominators(rsucc, rpreds, h)
            for n in body:
                if n is h or self.ipost.get(n) is not None:
                    continue
                d = idom_local.get(n)
                if d is not None:
                    # Local ipost == header: every path leaves through
                    # the loop itself -- no join info; keep None.
                    if d is h:
                        continue
                    # Soundness: d must be reachable from BOTH of
                    # n's successors without re-entering n (else a
                    # spurious "join" collapses the dispatch).
                    def _reaches(src):
                        seen = {n}
                        stack = [src]
                        while stack:
                            cur = stack.pop()
                            if cur is d:
                                return True
                            for s2 in (cur.fall, cur.taken):
                                if s2 is not None and s2 in body \
                                        and s2 not in seen:
                                    seen.add(s2)
                                    stack.append(s2)
                        return False
                    if n.fall is None or n.taken is None \
                            or not _reaches(n.fall) or not _reaches(n.taken):
                        continue
                    self.ipost[n] = d

    # -- emission helpers -------------------------------------------------

    def emit(self, va, delta, text):
        self.machine.emit(va, delta, text)

    def _begin_block(self, b):
        """Mark a block as being emitted now (labels attach here)."""
        self.visited.add(b)
        self._last_begin = b
        self.block_first_stmt.setdefault(b.start, len(self.machine.statements))

    def _block_after(self, b):
        """The block physically following *b* in address order, or None."""
        return self.blocks[b.index + 1] if b.index + 1 < len(self.blocks) \
            else None

    def _bare_tramp(self, blk):
        """True for a bare unconditional 1-instr trampoline with an
        in-proc taken edge (the skip-to shape jump threading follows)."""
        return (blk is not None and blk.kind == "uncond"
                and len(blk.instrs) == 1 and blk.taken is not None)

    def _cond_repeats(self, term, src, latch):
        """True when the condition's TRUE edge is the back edge to the
        latch (Loop While) vs the false edge (Loop Until)."""
        return src.taken is latch if term.label in _BRANCH_TRUE \
            else src.fall is latch

    def _close_cond_loop(self, term, src, latch, body, depth):
        """Close a Do loop at the bare latch with "Loop While/Until":
        _pop_cond first (deferred calls stay above the label), then
        _begin_block right before the Loop line (a GoTo to the latch
        labels the back edge), then the non-back edge of *src*
        continues (fall-back: after the latch)."""
        cond_text = self._pop_cond(term)
        repeats = self._cond_repeats(term, src, latch)
        self._begin_block(latch)
        self.emit(term.pos, -1,
                  "Loop While %s" % cond_text if repeats
                  else "Loop Until %s" % cond_text)
        self._flush_to_depth(term.pos, depth)
        exit2 = src.taken if src.fall is latch else src.fall
        if exit2 is None or exit2 in body:
            exit2 = self._block_after(latch)
        if exit2 is None:
            return ("term",)
        return ("next", exit2)

    def _consume_latch(self, latch, what="latch"):
        """Loop-tail invariant: a pre-visited latch must be a bare
        1-instr trampoline (else double emission -- raise); mark it
        emitted and process its non-branch instrs."""
        if latch in self.visited and len(latch.instrs) != 1:
            raise StructureUnsupported(
                "%s re-emitted @0x%08X" % (what, latch.start))
        self._begin_block(latch)
        for j in latch.instrs[:-1]:
            self.machine.process(j)

    def _flush_to_depth(self, va, depth):
        if len(self.machine.stack) > depth:
            self.machine._flush_to_depth(va, depth)  # noqa: SLF001

    def _pop_cond(self, ins):
        # strip() removes only formatting whitespace (a trailing string
        # literal still ends in a quote).
        cond = self.machine.pop()
        self.machine.flush_leftovers(ins.pos)
        return strip(cond.text)

    def _cond_text(self, ins, cond_text):
        """FALL-side If display: BranchF keeps the condition (fall = Then),
        BranchT shows Not(cond)."""
        if ins.label in _BRANCH_TRUE:
            return _wrap_not(cond_text)
        return cond_text

    def _taken_disp(self, ins, cond_text):
        """TAKEN-side If display: BranchT keeps the condition (taken
        runs when true), BranchF shows it negated."""
        return cond_text if ins.label in _BRANCH_TRUE \
            else _wrap_not(cond_text)

    def _emit_one_sided(self, ins, disp, arm, stop, ctx, close_va=None,
                        allowed_stops=()):
        """If disp Then <walk arm> End If; returns the arm walk result.
        close_va anchors the leftover drain and the End If (the join
        when closing at a join, else the opener's VA).  allowed_stops
        lists stop members the caller realizes right after the End If
        (the If's continuation point): an arm stopping there keeps
        its edge by adjacency; anything else renders explicitly
        (#19)."""
        va = ins.pos if close_va is None else close_va
        self.emit(ins.pos, +1, "If %s Then" % disp)
        depth = len(self.machine.stack)
        r = self.walk(arm, stop, ctx)
        allowed = set(allowed_stops)
        if close_va is not None:
            allowed.add(close_va)
        r = self._arm_stop_edge(r, allowed, ins, stop, ctx)
        self._flush_to_depth(va, depth)
        self.emit(va, -1, "End If")
        return r

    def _arm_stop_edge(self, r, allowed_starts, ins, stop, ctx):
        """#19: an arm walk returning ("stop", X) means the arm ends by
        falling into stop member X.  That edge renders by adjacency
        only when X is the point the caller emits right after the
        End If (a join / boundary in *allowed_starts*) -- otherwise
        the If's own fall-through owns that position and the arm's
        edge must be explicit, inside the arm.  A propagated
        ("stop", latch) from an arm also made _emit_do's interior
        append place a barrier for an edge the fall-through crosses
        (the #18 regression: re-dispatch on stale input)."""
        if r[0] == "stop" and r[1].start not in allowed_starts:
            self._exit_stmt_for_target(r[1].start, ctx, ins.pos, stop)
            return ("term",)
        return r

    def _exit_stmt_for_target(self, va, ctx, at_va, stop):
        """Render an edge that leaves the current region as a statement."""
        if va is None:
            # Abnormal operand (no VA): raise so the driver's error
            # stub takes over (not the range check's TypeError).
            raise StructureUnsupported(
                "null branch target @0x%08X" % at_va)
        # Penetrate bare uncond trampolines so a jump chain renders
        # one direct GoTo.  Barriers: latch trampolines/stop members
        # (gold-locked loop close), loop headers (restart, not hop),
        # already-structured blocks (the orphan pass walks with empty
        # `stop` -- `visited` is its only marker).
        seen = set()
        while va not in seen and len(seen) < _TRAMP_HOPS_MAX:
            seen.add(va)
            blk = self.block_by_start.get(va)
            if (not self._bare_tramp(blk)
                    or blk.start in stop or blk in self._latches
                    or blk in self.loops
                    or not (self.proc_start <= blk.taken.start
                            < self.proc_end)):
                break
            va = blk.taken.start
        if ctx:
            inner = ctx[-1]
            exit_blk = inner.exit_block
            # The loop's own exit wins even over the bare proc exit
            # ("Exit For" reads better than "Exit Sub").
            if exit_blk is not None and va == exit_blk.start:
                self.machine.flush_leftovers(at_va)
                if self.exit_addrs and va in self.exit_addrs:
                    self.emit(at_va, 0, self._exit_keyword)
                elif inner.kind == "for":
                    self.emit(at_va, 0, "Exit For")
                elif inner.kind in ("do", "dowhile"):
                    self.emit(at_va, 0, "Exit Do")
                else:  # While: no Exit While in VB4 — jump past the Wend.
                    self.needed_labels.add(va)
                    self.emit(at_va, 0, "GoTo L_%08X" % va)
                    self.stats["gotos"] += 1
                self.stats["exits"] += 1
                return
            # A back edge to the INNERMOST loop's restart point is that
            # loop's next iteration: VB4 spells it "label + GoTo";
            # render the modern Continue statement instead (the label
            # disappears when no other edge needs it).  The match must
            # run the same code the Continue would:
            #   * Do/While: to the header -- a While/Do While header
            #     IS the test (re-test = Continue) and a bare-latch
            #     infinite Do...Loop has no test to skip; a bottom-
            #     tested restart (Loop While/Until) would skip the
            #     test and keeps its GoTo (_loop_bottom_tested);
            #   * For: to the latch (the Next line: increment + test).
            #     A jump to the ForI2 preheader RE-INITIALIZES the loop
            #     and a jump to the body start skips the increment --
            #     both keep their GoTo.
            # Outer loops never match (VB has no labeled Continue):
            # multi-level restarts (pub_070 / pub_186 / pub_196 shapes)
            # and re-entries from OUTSIDE a closed loop (pub_197 Case
            # 122/123 jumping back into the walk Do) keep their GoTo.
            if inner.kind == "for":
                is_cont = (inner.latch is not None
                           and va == inner.latch.start)
            else:
                is_cont = (va == inner.header.start
                           and not self._loop_bottom_tested(inner))
            if is_cont:
                self.machine.flush_leftovers(at_va)
                self.emit(at_va, 0,
                          "Continue While" if inner.kind == "while"
                          else "Continue For" if inner.kind == "for"
                          else "Continue Do")
                self.stats["continues"] += 1
                return
        if va in self.exit_addrs:
            self.machine.flush_leftovers(at_va)
            self.emit(at_va, 0, self.exit_stmt)
            self.stats["exits"] += 1
            return
        self.machine.flush_leftovers(at_va)
        # Out-of-proc targets render a label-less GoTo, counted for
        # probes (PAL.EXE has zero, probed); the cond/uncond cross-
        # proc treatments are per-construct mirrors.
        if self.proc_start <= va < self.proc_end:
            self.needed_labels.add(va)
            self.stats["gotos"] += 1
        else:
            self.stats["cross_proc_gotos"] += 1
        self.emit(at_va, 0, "GoTo L_%08X" % va)

    # -- main walk ---------------------------------------------------------

    def run(self):
        if self.entry is None:
            return self.machine.statements, {}, self.stats
        # A StructureUnsupported leaves bookkeeping partially updated
        # -- fine, this instance becomes an error stub.
        self.walk(self.entry, frozenset(), [])
        # Orphan cleanup: reachable blocks never structured (jumped
        # into), emitted with labels so reaching GoTos resolve (one
        # round suffices; the bound is a safety net).
        max_rounds = len(self.blocks) + 1
        for _ in range(max_rounds):
            orphans = [b for b in self.blocks
                       if b in self.reachable and b not in self.visited]
            if not orphans:
                break
            for b in orphans:
                if b in self.visited:
                    continue
                # Exit trampolines with no label refs need no render.
                if b.start not in self.needed_labels and (
                        (b.kind == "term" and len(b.instrs) == 1
                         and b.start in self.exit_addrs)
                        or (b.kind == "uncond" and len(b.instrs) == 1
                            and b.taken_va in self.exit_addrs)):
                    self.visited.add(b)
                    continue
                self.needed_labels.add(b.start)
                self.walk(b, frozenset(), [])
        # Every GoTo target must carry a label: walk needed-label
        # blocks consumed without emitting anything (the orphan pass
        # covers only never-visited ones).
        pending = deque(sorted(self.needed_labels))
        while pending:
            va = pending.popleft()
            b = self.block_by_start.get(va)
            if b is None or self.block_first_stmt.get(va) is not None:
                continue
            before = set(self.needed_labels)
            self.walk(b, frozenset(), [])
            pending.extend(sorted(
                set(self.needed_labels) - before))
        # Unreachable blocks: emit flat (informational) after a
        # marker; bare single-branch trampolines are skipped (#18: a
        # marker with nothing under it reads as "the code above is
        # dead" -- exactly backwards for a live hoisted region).
        unreachable = [b for b in self.blocks if b not in self.reachable]
        rendered_unreachable = [
            b for b in unreachable
            if not (b.kind == "uncond" and len(b.instrs) == 1
                    and b.taken is not None)]
        if rendered_unreachable:
            stmts = self.machine.statements
            before = len(stmts)
            labels_before = set(self.needed_labels)
            self.emit(rendered_unreachable[0].start, 0,
                      "' ---- unreachable p-code ----")
            for b in unreachable:
                if b.kind == "uncond" and len(b.instrs) == 1 \
                        and b.taken is not None:
                    continue
                self._begin_block(b)
                self.needed_labels.add(b.start)
                for ins in b.instrs:
                    self.machine.process(ins)
                self.machine.flush_leftovers(b.term.pos if b.term
                                             else b.start)
                if b.kind == "uncond" and b.taken is not None:
                    self.needed_labels.add(b.taken.start)
                    self.emit(b.term.pos, 0, "GoTo L_%08X" % b.taken.start)
            if len(stmts) == before + 1 \
                    or all(s.text in ("Exit Sub", "Exit Function")
                           for s in stmts[before + 1:]):
                # nothing (or only bare exit keywords) rendered: the
                # writers drop trailing Exit Sub/Function at the proc
                # tail (#4), which would leave a bare marker reading
                # as "the code above is dead" -- drop the whole tail
                stmts[:] = stmts[:before]
                self.needed_labels.clear()
                self.needed_labels.update(labels_before)
                for k in list(self.block_first_stmt):
                    if self.block_first_stmt[k] >= before:
                        del self.block_first_stmt[k]
        # Map needed labels to statement indices.
        label_at_stmt = {}
        for va in sorted(self.needed_labels):
            b = self.block_by_start.get(va)
            idx = self.block_first_stmt.get(va)
            if b is not None and idx is not None:
                label_at_stmt.setdefault(idx, []).append(va)
        self.stats["edge_audit"] = self._audit_edges()
        return self.machine.statements, label_at_stmt, self.stats

    def _audit_edges(self):
        """#19 acceptance gate: every implicit walk edge ("fall" = the
        walk continued into the successor; "defer" = the walk stopped
        at a stop member for the caller to realize) must survive the
        render: the flow from the transition position must reach the
        target block's first statement on EVERY path, without flowing
        into any other block's code (an inserted region = an
        intercepted fall = silent flow change; the #19 shape: the
        round tail check fell into the appended dispatch region).  A
        defer whose next statement is an explicit jump (the #18
        barrier) counts as realized.  Back edges (loop latches ->
        headers) are exempt: loop closes own them.  Edges into proc
        exits are exempt: the exit statement machinery owns them.
        Returns a list of violation strings (empty = clean)."""
        stmts = self.machine.statements
        firsts_by_idx = {}
        for va, idx in self.block_first_stmt.items():
            firsts_by_idx.setdefault(idx, set()).add(va)
        bad = []
        for kind, u, v, pos in self._edge_log:
            if v <= u:
                continue          # back edge: realized by the loop close
            vb = self.block_by_start.get(v)
            if vb is not None and vb.kind == "term":
                continue          # proc exit: Exit Sub/Return own it
            # Bare trampolines into a proc exit (the _emit_if_join_exit
            # fold renders one Exit Sub for such joins): the exit
            # statement owns the edge.
            tb = vb
            hops = 0
            while tb is not None and hops < 8 \
                    and tb.kind == "uncond" and len(tb.instrs) == 1 \
                    and tb.taken is not None \
                    and self.proc_start <= tb.taken.start < self.proc_end:
                tb = tb.taken
                hops += 1
                if tb is not None and (tb.kind == "term"
                                       or tb.start in self.exit_addrs):
                    tb = None
                    break
            if hops and tb is None:
                continue
            iv = self.block_first_stmt.get(v)
            if iv is None:
                bad.append("%s 0x%08X->0x%08X @%d: target not rendered"
                           % (kind, u, v, pos))
                continue
            if pos < len(stmts):
                t0 = stmts[pos].text.strip()
                if t0.startswith("Continue"):
                    continue      # explicit barrier realized the edge
                if t0.startswith("Exit "):
                    continue      # exit statement owns the edge (the
                    # shared-exit fold / Exit Do upgrade chose it)
                if t0.startswith("GoTo L_"):
                    # explicit jump penetrating bare trampolines: the
                    # walk's edge target may be a tramp chain whose
                    # ultimate target the GoTo spells directly
                    try:
                        gva = int(t0[8:], 16)
                    except ValueError:
                        gva = None
                    tb = self.block_by_start.get(v)
                    hops = 0
                    while tb is not None and gva is not None and hops < 8 \
                            and tb.kind == "uncond" and len(tb.instrs) == 1 \
                            and tb.taken is not None \
                            and self.proc_start <= tb.taken.start < self.proc_end:
                        if tb.start == gva:
                            break
                        tb = tb.taken
                        hops += 1
                    if tb is not None and gva is not None \
                            and tb.start == gva:
                        continue
            if not self._flow_reaches(pos, iv, v, u, firsts_by_idx, stmts):
                bad.append("%s 0x%08X->0x%08X @%d: flow does not reach "
                           "the target cleanly" % (kind, u, v, pos))
        return bad

    def _flow_reaches(self, pos, iv, v_va, u_va, firsts_by_idx, stmts):
        """All-paths reachability from statement *pos* to *iv*: every
        path must arrive at the target's first statement (or an
        explicit jump to it) without flowing into another block's
        first statement.  Simulates the rendered VB control flow from
        the indent-delta structure."""
        n = len(stmts)
        # depth[j]: nesting depth BEFORE statement j
        depth = [0] * (n + 1)
        d = 0
        for j, s in enumerate(stmts):
            depth[j] = d
            d += s.indent_delta
        depth[n] = d

        def label_idx(va):
            j = self.block_first_stmt.get(va)
            return j

        work = [pos]
        seen = set()
        while work:
            j = work.pop()
            while True:
                if j in seen:
                    break
                seen.add(j)
                if j >= n:
                    return False        # fell off the proc end
                if j == iv:
                    break               # path arrived
                t = stmts[j].text.strip()
                if t == "Else" or t.startswith("ElseIf ") \
                        or t.startswith("Case "):
                    # falling onto an arm divider from the previous
                    # arm: leave the construct at its close.  (The
                    # divider line is itself a cond block's first
                    # statement -- check it BEFORE the foreign-block
                    # rule; the flow does not enter it.)
                    j = self._matching_close(j, depth, stmts, n) + 1
                    continue
                if t == "End If" or t == "End Select":
                    j += 1
                    continue
                vas = firsts_by_idx.get(j)
                if vas and v_va not in vas and u_va not in vas:
                    return False        # flows into foreign block code
                dj = depth[j]
                if t == "Loop" or t.startswith("Loop ") \
                        or t == "Wend" or t == "Next" \
                        or t.startswith("Next "):
                    return False        # iterates that loop, not our edge
                if t.startswith("GoTo L_"):
                    try:
                        va = int(t[8:], 16)
                    except ValueError:
                        return False
                    if va == v_va:
                        break           # explicit jump to the target
                    # or to the end of the target's bare-tramp chain
                    # (the renderer penetrates trampolines)
                    tb = self.block_by_start.get(v_va)
                    hops = 0
                    while tb is not None and hops < 8 \
                            and tb.kind == "uncond" and len(tb.instrs) == 1 \
                            and tb.taken is not None \
                            and self.proc_start <= tb.taken.start \
                            < self.proc_end:
                        if tb.start == va:
                            break
                        tb = tb.taken
                        hops += 1
                    if tb is not None and tb.start == va:
                        break
                    return False
                if t.startswith("Continue"):
                    return False        # restarts a loop, not our edge
                if t.startswith("Exit Do") or t.startswith("Exit For") \
                        or t.startswith("Exit While"):
                    # leaves the enclosing loop, continues after its
                    # close (the close at this depth)
                    j = self._enclosing_close(j, depth, stmts, n) + 1
                    continue
                if t.startswith("Exit Sub") or t.startswith("Exit Function") \
                        or t == "End" or t.startswith("Return"):
                    return False        # leaves the proc
                if t.startswith("If "):
                    # fork: the Then arm and the false continuation
                    work.append(self._false_side(j, depth, stmts, n))
                    j += 1
                    continue
                if t.startswith("While "):
                    work.append(self._matching_close(j, depth, stmts, n) + 1)
                    j += 1
                    continue
                # Do / For / Select Case / plain statements: enter
                j += 1
        return True

    @staticmethod
    def _matching_close(j, depth, stmts, n):
        """Index of the close that returns to depth[j] (End If /
        Wend / Loop / Next / End Select), scanning forward."""
        dj = depth[j]
        k = j + 1
        while k < n:
            if depth[k] <= dj and stmts[k].indent_delta < 0:
                return k
            k += 1
        return n

    def _false_side(self, j, depth, stmts, n):
        """Where an If's FALSE flow continues: after Else (into the
        else arm) or after End If."""
        dj = depth[j]
        k = j + 1
        while k < n:
            t = stmts[k].text.strip()
            if depth[k] == dj + 1 and t == "Else":
                return k + 1
            if depth[k] == dj and stmts[k].indent_delta < 0:
                return k + 1
            k += 1
        return n

    @staticmethod
    def _enclosing_close(j, depth, stmts, n):
        """Index of the Loop/Next/Wend closing the innermost loop
        enclosing *j*."""
        dj = depth[j]
        k = j + 1
        d = dj
        while k < n:
            nd = d + stmts[k].indent_delta
            if stmts[k].indent_delta < 0 and nd < dj \
                    and (stmts[k].text.strip() == "Loop"
                         or stmts[k].text.strip().startswith("Loop ")
                         or stmts[k].text.strip() == "Wend"
                         or stmts[k].text.strip() == "Next"
                         or stmts[k].text.strip().startswith("Next ")):
                return k
            d = nd
            k += 1
        return n

    def walk(self, b, stop, ctx, primary=False):
        """Structure the linear spine starting at *b*.  Returns
        ("stop", block) at a caller's join, or ("term",) when this path
        ends (exit/goto emitted at the edge).

        Every implicit transition logs an audit record (#19): the
        edge renders by adjacency, so the target must be the next
        block begun after the transition position -- run() verifies
        that at proc end (an appended region between the two = an
        intercepted fall = silent flow change).

        *primary* marks the loop-body spine walk launched by
        _emit_do: only it reaches the pre-latch placement hook (arm
        and leaving-side walks must not splice regions -- their
        pending sets are mid-walk states, not orphan sets)."""
        prev = None
        while b is not None:
            if b.start in stop:
                if prev is not None:
                    self._edge_log.append(
                        ("defer", prev.start, b.start,
                         len(self.machine.statements)))
                return ("stop", b)
            if ctx and ctx[-1].exit_block is not None \
                    and b is ctx[-1].exit_block \
                    and (self._leaving_side_depth > 0
                         or ctx[-1].shared_exit):
                # A walk reaching the loop's own exit renders the exit
                # statement, not the post-loop region (the natural path
                # renders that).  Leaving-side walks always; spine/arm
                # walks when the exit is a hoisted shared epilogue
                # (a fall into it -- e.g. pub_167's last Select Case
                # leg -- is an Exit Do, never an inline epilogue).
                self._exit_stmt_for_target(b.start, ctx, b.start, stop)
                return ("term",)
            if b in self.visited:
                # Jump into already-structured code: degrade to a GoTo.
                self._exit_stmt_for_target(b.start, ctx, b.start, stop)
                return ("term",)
            if b in self.irreducible:
                res = self.emit_flat_block(b, ctx)
                if res[0] == "next":
                    prev = b
                    b = res[1]
                    if b is not None and b not in self.reachable:
                        return ("term",)
                    continue
                return res
            if b in self.loops and b not in self.for_headers:
                res = self.emit_loop(b, stop, ctx)
                if res[0] == "next":
                    # The loop exit is ordinary continuation code.
                    prev = None   # loop emit internals own their edges
                    b = res[1]
                    if b is not None and b not in self.reachable:
                        return ("term",)
                    continue
                return res
            if primary and not self._emitting_orphans and ctx \
                    and ctx[-1].latch is not None \
                    and b.fall is ctx[-1].latch \
                    and b is not ctx[-1].latch:
                # #19 pre-latch placement: *b* is the block that
                # falls into this loop's latch -- the loop's natural
                # closing flow.  Interior orphan regions due now
                # splice in ahead of it (not at body end), so *b*
                # keeps its fall-to-Loop position; the spine's
                # implicit edge into *b* is intercepted by the
                # region -- make it explicit first (a GoTo over the
                # region to *b*'s label).  *b* itself is about to
                # render: it is not an orphan.
                ok = self._interior_orphan_ok(ctx[-1].header,
                                              ctx[-1].body,
                                              ctx[-1].latch)
                if ok:
                    ok.discard(b)
                if ok:
                    self.needed_labels.add(b.start)
                    self.machine.flush_leftovers(b.start)
                    self.emit(b.start, 0, "GoTo L_%08X" % b.start)
                    self.stats["gotos"] += 1
                    self._emit_orphan_regions(
                        ok, ctx[-1].latch, stop | {b.start}, ctx)
            self._begin_block(b)
            res = self.process_block(b, stop, ctx)
            if res[0] == "next":
                nxt = res[1]
                # A plain fall out of the innermost loop body is not
                # structured -- except in a leaving-side walk.
                if self._leaving_side_depth == 0 and ctx \
                        and nxt is not None and nxt not in ctx[-1].body \
                        and nxt.start not in stop \
                        and ctx[-1].latch is not None \
                        and nxt is not ctx[-1].latch:
                    raise StructureUnsupported(
                        "fall exits loop at 0x%08X" % nxt.start)
                self._edge_log.append(
                    ("fall", b.start, nxt.start,
                     len(self.machine.statements)))
                prev = b
                b = nxt
                continue
            return res
        return ("term",)

    # -- block processing ---------------------------------------------------

    @staticmethod
    def _frame_slot(operand):
        """Frame-slot offset of a plain mem=stack-N operand, else None.
        (mem=stack+8.fXXXX module fields parse to None.)"""
        if not operand.startswith("mem=stack"):
            return None
        try:
            return int(operand[len("mem=stack"):])
        except ValueError:
            return None

    def _ret_move_fold(self, b, i, ins):
        """True when *ins* (index *i*) is the `T = expr` store directly
        before an unconditional Branch to the bare return-move epilogue
        {FLdI2 T; FStI2 <result slot>; ExitProc}: the pair folds to one
        `Return expr` statement.

        A plain Exit Function is NOT equivalent here: the epilogue's
        result-slot store (`name = T`) must run, and folding it into the
        exit is safe only when the epilogue does nothing else.  T is
        dead past the branch (the epilogue only moves it into the
        result slot), so skipping the temp store is exact."""
        if i != len(b.instrs) - 2 or b.taken is None:
            return False
        if b.instrs[-1].label != "Branch":
            return False
        ep = b.taken
        if ep.kind != "term" or len(ep.instrs) != 3:
            return False
        if not (self.proc_start <= ep.start < self.proc_end):
            return False
        e0, e1, e2 = ep.instrs
        if e0.label != "FLdI2" or e1.label != "FStI2" \
                or not e2.label.startswith("ExitProc"):
            return False
        if self.machine.result_slot is None:
            return False
        src = self._frame_slot(ins.operand)
        if src is None or self._frame_slot(e0.operand) != src:
            return False
        return self._frame_slot(e1.operand) == self.machine.result_slot

    def process_block(self, b, stop, ctx):
        """Process one block's instructions and its control transfer."""
        depth0 = len(self.machine.stack)
        for i, ins in enumerate(b.instrs):
            lab = ins.label
            if lab in stack_ir.COND_BRANCH or lab in stack_ir.UNCOND_BRANCH:
                return self.emit_branch_terminal(b, ins, stop, ctx)
            if lab in stack_ir.LOOP_START:
                return self.emit_for(b, ins, stop, ctx)
            if lab in stack_ir.LOOP_END:
                # A Next outside a For-emitter walk: unbalanced structure.
                raise StructureUnsupported(
                    "stray Next at 0x%08X" % ins.pos)
            if lab in stack_ir.TERMINATOR_LABELS or lab == "Return":
                self.machine.process(ins)
                return ("term",)
            if lab == "FStI2" and self._ret_move_fold(b, i, ins):
                # `T = expr` + Branch to the bare return-move epilogue:
                # pop the expr before the store consumes it and emit the
                # folded return (the Branch's sole effect is that jump).
                expr = self.machine.pop()
                self.machine.flush_leftovers(ins.pos)
                self.emit(ins.pos, 0, "Return %s" % strip(expr.text))
                self.stats["exits"] += 1
                return ("term",)
            self.machine.process(ins)
        if b.fall is None:
            return ("term",)
        # A pure fall-through must not strand deferred call values
        # (a consumer in the NEXT block crosses a branch boundary --
        # a discarded void call; flush HERE so following labels do
        # not shift).
        self.machine.flush_calls_above(b.start, depth0)
        return ("next", b.fall)

    def emit_branch_terminal(self, b, ins, stop, ctx):
        lab = ins.label
        if lab == "Gosub":
            tgt = b.taken_va or 0
            if self.proc_start <= tgt < self.proc_end:
                self.needed_labels.add(tgt)
            self.machine.flush_leftovers(ins.pos)
            self.emit(ins.pos, 0, "GoSub L_%08X" % tgt)
            return ("next", b.fall)
        if lab in stack_ir.COND_BRANCH:
            return self.emit_cond(b, ins, stop, ctx)
        # Unconditional Branch.
        tgt_va = b.taken_va
        tgt = b.taken
        # NOTE: no special case for a 2-instr "ImpAdCall +
        # Branch-to-header" latch: the loop TAIL emits the call once
        # per iteration (an inline case double-executed it; never
        # fired on PAL.EXE).
        if tgt is not None and tgt.start in stop:
            # A branch to the enclosing join/latch is the structured
            # "fall out", not a GoTo -- except to the bare shared
            # exit (folds emit it after End If).
            if tgt.start in self._if_join_exit_stack:
                return ("stop", tgt)
            if not (tgt.kind == "term" and len(tgt.instrs) == 1
                    and tgt.start in self.exit_addrs):
                return ("next", tgt)
        if tgt is not None and tgt is b.fall:
            return ("next", b.fall)   # redundant jump
        self._exit_stmt_for_target(tgt_va, ctx, ins.pos, stop)
        return ("term",)

    # -- conditionals -------------------------------------------------------

    def emit_cond(self, b, ins, stop, ctx):
        """Structure one conditional branch.  Dispatch order (each case
        assumes the ones above did not fire): 1 join one side reaches
        -> demote; 2 in-loop leaving side -> _emit_cond_exit/fold;
        3 cross-proc taken -> _emit_dangling_if; 4 join swallowed by
        loop -> header; 5 fall exits + taken is a fresh loop -> the
        loop is the join; 6 side empty -> one-sided; 7 side terminator
        -> guard; 8 no-exit side -> _emit_infinite_side_guard;
        9 ladder; 10 local diamond; 11 no join -> open If/Else;
        12 real join -> _resolve_join_sides/ladder."""
        cond_text = self._pop_cond(ins)
        then_cond = self._cond_text(ins, cond_text)
        fall, taken = b.fall, b.taken
        join = self.ipost.get(b)
        if join is not None and (
                (join is fall and taken is not None
                 and not self._can_reach(taken, join))
                or (join is taken and fall is not None
                    and not self._can_reach(fall, join))):
            # A join equal to one side is honest only if the OTHER
            # side passes through it; a non-exiting side makes the
            # global pass report the sibling spuriously -- null it.
            join = None
        if ctx:
            inner = ctx[-1]
            if join is not None and join not in inner.body:
                join = None
            # A leaving side renders as a guarded Exit/GoTo.
            f_out = (fall is not None and fall not in inner.body
                     and fall.start not in stop)
            t_out = (taken is not None and taken not in inner.body
                     and taken.start not in stop)
            # A bare branch to an ANCESTOR header continues that
            # outer loop -- a departure from the innermost (re-check
            # each side not already flagged).
            anc = {c.header.start for c in ctx[:-1]}
            if anc:
                if not f_out and fall is not None and self._bare_tramp(fall) \
                        and fall.taken_va in anc:
                    f_out = True
                if not t_out and taken is not None \
                        and self._bare_tramp(taken) \
                        and taken.taken_va in anc:
                    t_out = True
            if t_out and f_out:
                # Both sides leave but converge on the bare shared
                # exit: fold the exit after End If (the RAW ipost is
                # the target here -- the join was nulled above).
                fold_join = self.ipost.get(b)
                exit_va = None
                if fold_join is not None:
                    if fold_join.kind == "term" \
                            and len(fold_join.instrs) == 1 \
                            and fold_join.start in self.exit_addrs:
                        exit_va = fold_join.start
                    elif fold_join.kind == "uncond" \
                            and len(fold_join.instrs) == 1 \
                            and fold_join.taken_va in self.exit_addrs:
                        exit_va = fold_join.taken_va
                if exit_va is not None:
                    return self._emit_if_join_exit(
                        b, ins, cond_text, then_cond, fold_join, exit_va,
                        stop, ctx)
            if t_out or f_out:
                return self._emit_cond_exit(b, ins, cond_text, stop, ctx,
                                            f_out, t_out)

        if taken is None:
            # Cross-proc taken edge: one-sided If closed at the next
            # control boundary (PAL.EXE has zero, probed).
            return self._emit_dangling_if(b, ins, then_cond, stop, ctx)

        if join is None and ctx:
            # The innermost loop swallowed the join: the loop IS the
            # join -- one-sided If, the guard walks the other side.
            inner = ctx[-1]
            if (fall is not None and fall not in inner.body
                    and fall.start not in stop) \
                    or (taken not in inner.body
                        and taken.start not in stop):
                join = inner.header

        if join is None:
            # Fall exits + taken is a fresh loop header: the loop IS
            # the join -- one-sided guard If, then the loop itself.
            if fall is not None and (fall.kind == "term"
                                     or fall.start in self.exit_addrs) \
                    and (taken in self.loops or taken.kind == "for") \
                    and taken not in self.visited \
                    and (not ctx or taken not in ctx[-1].body):
                join = taken

        if join is None:
            # A side that is itself a stop-set member carries NO
            # code: the other edge is the only real arm.
            t_empty = taken is not None and taken.start in stop
            f_empty = fall is not None and fall.start in stop
            if t_empty != f_empty:
                if t_empty:
                    r = self._emit_one_sided(ins, then_cond, fall,
                                             stop, ctx,
                                             allowed_stops={taken.start})
                else:
                    r = self._emit_one_sided(
                        ins, self._taken_disp(ins, cond_text), taken,
                        stop, ctx, allowed_stops={fall.start})
                if r[0] == "stop":
                    return r
                return ("next", taken if t_empty else fall)
            # A terminator side ends every path through it: guard it
            # one-sided and continue on the OTHER side (a term walk
            # always returns ("term",) -- the flip is exact).
            t_term = (taken is not None and taken.kind == "term"
                      and taken.start not in stop)
            f_term = (fall is not None and fall.kind == "term"
                      and fall.start not in stop)
            if f_term != t_term:
                if f_term:
                    self._emit_one_sided(ins, then_cond, fall, stop, ctx,
                                         allowed_stops={taken.start})
                    return ("next", taken)
                self._emit_one_sided(
                    ins, self._taken_disp(ins, cond_text), taken,
                    stop, ctx, allowed_stops={fall.start})
                return ("next", fall)
            # A side that cannot reach the proc exit is an infinite
            # continuation: guard its departure one-sided.
            res = self._emit_infinite_side_guard(
                b, ins, cond_text, then_cond, stop, ctx)
            if res is not None:
                return res
            # A test ladder whose join the global pass cannot see
            # flattens into the If/ElseIf ladder the p-code spells.
            chain = self._find_structural_chain(b, ins, stop, ctx)
            if chain is not None:
                res = self._emit_structural_chain(
                    b, ins, cond_text, then_cond, stop, ctx, chain)
                if res is not None:
                    return res
            # A diamond merge the postdominator pass cannot see: fold
            # at the local join (absorbing it forces a forward GoTo).
            J = self._local_diamond_join(b, fall, taken, stop, ctx)
            if J is not None:
                jstop = stop | {J.start}
                self.emit(ins.pos, +1, "If %s Then" % then_cond)
                depth0 = len(self.machine.stack)
                r1 = self.walk(fall, jstop, ctx)
                self._flush_to_depth(ins.pos, depth0)
                self.emit(ins.pos, 0, "Else")
                r2 = self.walk(taken, jstop, ctx)
                self._flush_to_depth(ins.pos, depth0)
                self.emit(ins.pos, -1, "End If")
                # The plain side provably stops at J; a sibling arm
                # stopping elsewhere cannot be expressed -- propagate
                # it verbatim.
                for r in (r1, r2):
                    if r[0] == "stop" and r[1] is not J:
                        return r
                return ("next", J)
            # Both sides leave the region (or never rejoin): open If/Else.
            self.emit(ins.pos, +1, "If %s Then" % then_cond)
            depth0 = len(self.machine.stack)
            r1 = self.walk(fall, stop, ctx)
            self._flush_to_depth(ins.pos, depth0)
            self.emit(ins.pos, 0, "Else")
            r2 = self.walk(taken, stop, ctx)
            # Drain the else-side leftovers too (a stranded deferred
            # call must stay inside its arm).
            self._flush_to_depth(ins.pos, depth0)
            self.emit(ins.pos, -1, "End If")
            for r in (r1, r2):
                if r[0] == "stop":
                    return r
            return ("term",)

        res = self._resolve_join_sides(b, ins, cond_text, then_cond,
                                       join, stop, ctx)
        if res is not None:
            return res
        # Both sides are real arms: If/Else (ElseIf chaining when the
        # skip side is another test on the same join).
        return self._emit_if_else_chain(b, ins, cond_text, then_cond,
                                        join, stop, ctx)

    def _emit_infinite_side_guard(self, b, ins, cond_text, then_cond,
                                  stop, ctx):
        """One-sided If guarding the side that cannot reach the proc
        exit: a non-exiting side ends in a cycle -- guard its
        departure with a GoTo (the orphan/label pass emits the region
        flat) and continue on the exit-reaching side.  ("next",
        other_side), or None when neither/both sides are non-exiting."""
        fall, taken = b.fall, b.taken
        t_inf = taken is not None and taken not in self._reaches_exit
        f_inf = fall is not None and fall not in self._reaches_exit
        if t_inf == f_inf:
            return None
        if t_inf:
            disp, side, other = self._taken_disp(ins, cond_text), taken, fall
        else:
            disp, side, other = then_cond, fall, taken
        self.emit(ins.pos, +1, "If %s Then" % disp)
        self._exit_stmt_for_target(side.start, ctx, ins.pos, stop)
        self.emit(ins.pos, -1, "End If")
        return ("next", other)

    def _resolve_join_sides(self, b, ins, cond_text, then_cond, join,
                            stop, ctx):
        """One-sided If when one cond side IS the join (seeing through
        bare trampolines); None when both sides are real arms.  Latch
        trampolines stay opaque (gold-locked) and headers are restart
        barriers; a trampoline variant defers to the ladder machinery
        when the body side is a chainable leg."""
        fall, taken = b.fall, b.taken

        def _thru_tramp(blk, consume=False):
            seen = set()
            while blk is not None and blk.kind == "uncond" \
                    and len(blk.instrs) == 1 and blk.taken is not None \
                    and blk.start not in stop and blk not in self._latches \
                    and blk not in self.loops and blk not in seen \
                    and (self.proc_start <= blk.taken.start
                         < self.proc_end):
                seen.add(blk)
                if consume:
                    # the trampoline's effect was rendered; consume it
                    # for the orphan walk
                    self._begin_block(blk)
                blk = blk.taken
            return blk

        _taken_eff = _thru_tramp(taken)
        _fall_eff = _thru_tramp(fall)
        _depth_now = len(self.machine.stack)

        if taken is join or (
                _taken_eff is join
                and not self._chainable_leg(fall, _depth_now, set(), stop)):
            if taken is not join:
                _thru_tramp(taken, consume=True)
            # Then-only: If cond Then <fall..join> End If
            r = self._emit_one_sided(ins, then_cond, fall,
                                     stop | {join.start}, ctx,
                                     close_va=join.start)
            if r[0] == "stop" and r[1] is not join:
                return r
            return ("next", join)

        if fall is join or (
                _fall_eff is join
                and not self._chainable_leg(taken, _depth_now, set(), stop)):
            if fall is not join:
                _thru_tramp(fall, consume=True)
            # Body on the taken side: flip the displayed condition.
            r = self._emit_one_sided(
                ins, self._taken_disp(ins, cond_text), taken,
                stop | {join.start}, ctx, close_va=join.start)
            if r[0] == "stop" and r[1] is not join:
                return r
            return ("next", join)

        return None

    def _emit_cond_exit(self, b, ins, cond_text, stop, ctx, f_out, t_out):
        """Conditional branch out of the innermost loop: the exiting
        side becomes a guarded Exit, control continues on the other
        side ("If cond Then Exit For End If").  A cross-proc side
        (b.taken None) renders as an out-of-proc GoTo, never dropped."""
        # Both flags CAN be true here (the If/Else below renders both
        # guards).  A "leaving" side branching back to the innermost
        # header is a CONTINUE: re-classify only when the OTHER side
        # already leaves (neither flip fires on PAL.EXE).
        inner = ctx[-1] if ctx else None
        if inner is not None:
            inner_h = inner.header
            if t_out and b.taken is not None \
                    and b.taken.kind == "uncond" \
                    and len(b.taken.instrs) == 1 \
                    and b.taken.taken is inner_h:
                if f_out:
                    t_out = False
            elif f_out and b.fall is not None \
                    and b.fall.kind == "uncond" \
                    and len(b.fall.instrs) == 1 \
                    and b.fall.taken is inner_h:
                if t_out:
                    f_out = False

        def side_stmt(blk):
            if blk is None:
                return
            if blk.kind == "term":
                self._exit_stmt_for_target(blk.start, ctx, ins.pos, stop)
                return
            if blk.kind == "uncond" and not (
                    len(blk.instrs) == 1 and blk.taken_va is not None):
                # Real-code exit block (statements + a branch): render
                # the statements inline, then follow the branch -- even
                # back inside the loop (label-pass resolved).
                self._begin_block(blk)
                if len(blk.instrs) >= 2 \
                        and blk.instrs[-2].label == "FStI2" \
                        and self._ret_move_fold(blk, len(blk.instrs) - 2,
                                                 blk.instrs[-2]):
                    # `... ; T = expr` + Branch to the bare return-move
                    # epilogue folds to `... ; Return expr` (the temp
                    # store and the epilogue's result move cancel out;
                    # an Exit Function alone would skip that move).
                    for j in blk.instrs[:-2]:
                        self.machine.process(j)
                    expr = self.machine.pop()
                    self.machine.flush_leftovers(blk.instrs[-2].pos)
                    self.emit(blk.instrs[-2].pos, 0,
                              "Return %s" % strip(expr.text))
                    self.stats["exits"] += 1
                    return
                for j in blk.instrs[:-1]:
                    self.machine.process(j)
                self.machine.flush_leftovers(blk.term.pos)
                tgt_va = blk.taken_va
                if tgt_va is not None:
                    self._exit_stmt_for_target(tgt_va, ctx, ins.pos, stop)
                return
            # Bare trampoline or complex block: jump to it.
            va = blk.start
            if blk.kind == "uncond" and len(blk.instrs) == 1 \
                    and blk.taken_va is not None:
                # trampoline: jump to its target; its effect was
                # rendered, mark it consumed for the orphan walk
                va = blk.taken_va
                self._begin_block(blk)
            self._exit_stmt_for_target(va, ctx, ins.pos, stop)

        def side_walk(blk):
            # A complex leaving side is stripped in place -- but ONLY
            # when it is a HANDLER: a side running into ongoing control
            # flow is a CONTINUATION, rendered as a GoTo to its entry
            # (the orphan/label pass emits it flat; walking the loop's
            # OWN exit block would duplicate the post-loop region).
            if blk is None or blk in self.visited or blk in self.loops \
                    or blk in self.for_headers or blk in self.irreducible \
                    or blk.kind in ("term", "uncond"):
                side_stmt(blk)
                return
            if ctx and ctx[-1].exit_block is not None \
                    and blk.start == ctx[-1].exit_block.start:
                side_stmt(blk)
                return
            if self._reaches_cycle(blk, self._enclosing_loop_blocks(ctx)):
                self._exit_stmt_for_target(blk.start, ctx, ins.pos, stop)
                return
            self._leaving_side_depth += 1
            try:
                self.walk(blk, stop, ctx)
            finally:
                self._leaving_side_depth -= 1

        if t_out and f_out:
            self.emit(ins.pos, +1, "If %s Then"
                      % self._taken_disp(ins, cond_text))
            side_walk(b.taken)
            self.emit(ins.pos, 0, "Else")
            side_walk(b.fall)
            self.emit(ins.pos, -1, "End If")
            return ("term",)
        if t_out:
            self.emit(ins.pos, +1, "If %s Then"
                      % self._taken_disp(ins, cond_text))
            side_walk(b.taken)
            self.emit(ins.pos, -1, "End If")
            return ("next", b.fall)
        # The fall side leaves the loop.
        self.emit(ins.pos, +1, "If %s Then"
                  % self._cond_text(ins, cond_text))
        side_walk(b.fall)
        self.emit(ins.pos, -1, "End If")
        if b.taken is None:
            # Cross-proc taken edge: both sides depart -- render it
            # as an out-of-proc GoTo (dropping it is not faithful).
            self._exit_stmt_for_target(b.taken_va, ctx, ins.pos, stop)
            return ("term",)
        return ("next", b.taken)

    def _emit_if_join_exit(self, b, ins, cond_text, then_cond, join,
                           exit_va, stop, ctx):
        """Both arms of an in-loop cond converge on the bare shared proc
        exit: structure them with the exit as their stop point, then
        ONE exit after the End If ("If y < 15 Then y = 15 End If:
        Exit Sub"), not per-arm exits or orphaning GoTos."""
        fall, taken = b.fall, b.taken
        arm_stop = stop | {join.start}
        if exit_va != join.start:
            arm_stop = arm_stop | {exit_va}

        def empty_arm(side):
            if side is None or side is join:
                return True
            # a bare one-instr branch straight to the join/exit: no code
            if side.kind == "uncond" and len(side.instrs) == 1:
                return side.taken is join or side.taken_va == exit_va
            return False

        t_empty = empty_arm(taken)
        f_empty = empty_arm(fall)

        # When join and exit_va coincide, arm edges to either are
        # indistinguishable -- folding treats them as one.
        self._if_join_exit_stack.append(join.start)
        if exit_va != join.start:
            self._if_join_exit_stack.append(exit_va)
        try:
            if t_empty and f_empty:
                pass  # degenerate: both paths go straight to the exit
            elif f_empty:
                # Only the taken side has code: the Then arm is the
                # TAKEN side (BranchF taken runs on FALSE -- guard
                # Not(cond); BranchT on TRUE).
                self._emit_one_sided(
                    ins, self._taken_disp(ins, cond_text), taken,
                    arm_stop, ctx, close_va=join.start,
                    allowed_stops={exit_va})
            else:
                self.emit(ins.pos, +1, "If %s Then" % then_cond)
                depth = len(self.machine.stack)
                r1 = self.walk(fall, arm_stop, ctx)
                r1 = self._arm_stop_edge(
                    r1, {join.start, exit_va}, ins, arm_stop, ctx)
                self._flush_to_depth(join.start, depth)
                if not t_empty:
                    self.emit(ins.pos, 0, "Else")
                    r2 = self.walk(taken, arm_stop, ctx)
                    r2 = self._arm_stop_edge(
                        r2, {join.start, exit_va}, ins, arm_stop, ctx)
                    self._flush_to_depth(join.start, depth)
                self.emit(join.start, -1, "End If")
        finally:
            if exit_va != join.start:
                self._if_join_exit_stack.pop()
            self._if_join_exit_stack.pop()
        # The fold's target is BY CONSTRUCTION the bare proc exit:
        # render directly (_exit_stmt_for_target would print the
        # misleading "Exit For" here).
        self.machine.flush_leftovers(ins.pos)
        self.emit(ins.pos, 0, self.exit_stmt)
        self.stats["exits"] += 1
        return ("term",)

    def _chainable_leg(self, blk, chain_depth, leg_set, stop):
        """A skip-side block that can become an ElseIf leg: a pure
        single-predecessor BranchF test nobody has walked yet.
        *leg_set*/*stop* are caller-owned shared sets; read-only here."""
        return (blk is not None
                and blk.kind == "cond"
                and blk.term is not None
                and blk.term.label not in _BRANCH_TRUE
                and blk not in self.visited
                and blk not in self.loops
                and blk not in self.for_headers
                and blk not in self.irreducible
                and blk not in leg_set
                and blk.start not in stop
                and blk.taken is not None
                and len(blk.preds) == 1
                and self._leg_is_pure_cond(blk, chain_depth))

    def _edge_departs(self, s, stop, ctx):
        """True when an edge to *s* ends a chain arm's local path: the
        arm walk renders its own departure and never flows past End If."""
        if s is None:
            return True
        if s.kind == "term" or s in self.visited or s.start in stop:
            return True
        if ctx:
            inner = ctx[-1]
            if s is inner.header or s not in inner.body:
                return True
        return False

    def _arm_ok(self, arm, legset, arm_entries, J, stop, ctx):
        """Every path from one dispatch arm either reaches the chain
        join J or departs early (its own GoTo/Exit/loop-bottom).
        Rejects: paths above J's address (End If territory); a PLAIN
        block's fall out of the innermost loop (the spine raises; a
        cond's fall is fine); paths creeping into another leg or arm;
        the arm ENTRY in stop, or a plain spine FALL into a
        non-innermost stop member (the edge would be lost silently).
        Other stop-member edges are safe (a TAKEN edge renders a GoTo;
        the innermost latch is the empty fall to the Loop line).  An
        arm entry OUTSIDE the innermost body walks in "out-of-body
        mode": traversable, but an edge re-entering the body rejects.
        *legset*/*arm_entries*/*stop* are caller-owned; not mutated."""
        if arm is None:
            return False
        inner_latch = ctx[-1].latch if ctx else None
        if arm.start in stop and arm is not inner_latch:
            return False              # entry walk would stop mid-edge
        inner = ctx[-1] if ctx else None
        out_of_body = bool(inner and arm not in inner.body)
        seen = set()
        work = [arm]
        steps = 0
        while work:
            n = work.pop()
            if n in seen:
                continue
            seen.add(n)
            steps += 1
            if steps > _ARM_WALK_MAX:
                return False
            if J is not None and n is J:
                continue                      # joins at the End If
            if n in legset or (n in arm_entries and n is not arm):
                return False                  # ladder re-entry
            if J is not None and n.index > J.index:
                return False                  # post-join territory
            for s in (n.fall, n.taken):
                if s is None:
                    continue
                if J is not None and s is J:
                    continue                  # joins
                # (out_of_body implies inner is not None.)
                if out_of_body and s in inner.body and s is not inner.header:
                    return False   # out-of-body arm re-enters walked region
                if s is n.fall and n.kind != "cond" \
                        and s.start in stop and s is not inner_latch:
                    return False      # plain spine fall into a
                                     # non-innermost stop member:
                                     # silent edge loss
                if self._edge_departs(s, stop, ctx):
                    # Out-of-body mode: every fall leaves the body by
                    # definition; the emitters wrap such legs in a
                    # leaving-side walk.
                    if s is n.fall and inner is not None \
                            and s not in inner.body \
                            and n.kind != "cond" and not out_of_body:
                        return False          # spine fall out of the loop
                    continue                  # own departure
                work.append(s)
        return True

    def _walk_chain_arm(self, blk, stop, ctx):
        """Walk a chain arm, wrapping it in a leaving-side walk when its
        entry lies outside the innermost body (the spine would raise);
        _emit_cond_exit's side_walk uses the same mechanism."""
        if ctx and blk is not None and blk not in ctx[-1].body:
            self._leaving_side_depth += 1
            try:
                return self.walk(blk, stop, ctx)
            finally:
                self._leaving_side_depth -= 1
        return self.walk(blk, stop, ctx)

    def _arm_reaches(self, arm, J, ctx, limit=_ARM_WALK_MAX):
        """True when some path from *arm* reaches J; loop headers are
        barriers (a restart only reaches J on the NEXT round)."""
        headers = {c.header for c in ctx} if ctx else set()
        seen = set()
        work = [arm]
        while work:
            n = work.pop()
            if n is None or n in seen or n in headers:
                continue
            seen.add(n)
            if len(seen) > limit:
                return False
            if n is J:
                return True
            for s in (n.fall, n.taken):
                if s is not None and s not in seen:
                    work.append(s)
        return False

    def _find_structural_chain(self, b, ins, stop, ctx):
        """Detect a mutually-exclusive test ladder reached at *b* and
        prove each leg's arm walkable in isolation: legs extend along
        the skip side one pure test at a time; a failing _arm_ok ends
        the ladder (that block becomes the Else).  Returns (legs,
        else_entry) or None; no join needed up front."""
        if ins.label in _BRANCH_TRUE:
            return None            # chain side = taken assumes BranchF
        chain_depth = len(self.machine.stack)
        legs = [b]
        # leg_set / arm_entries are maintained incrementally (one
        # _arm_ok call per leg).
        leg_set = {b}
        arm_entries = {b.fall}
        if not self._arm_ok(b.fall, leg_set, arm_entries, None,
                             stop, ctx):
            return None
        cur = b.taken
        while len(legs) < _CHAIN_MAX_LEGS \
                and self._chainable_leg(cur, chain_depth, leg_set, stop) \
                and self._arm_ok(cur.fall, leg_set, arm_entries,
                                 None, stop, ctx):
            legs.append(cur)
            leg_set.add(cur)
            arm_entries.add(cur.fall)
            cur = cur.taken
        if len(legs) < 2 or cur is None:
            return None
        return legs, cur

    def _emit_structural_chain(self, b, ins, cond_text, then_cond, stop,
                               ctx, chain):
        """Render a structurally-proven dispatch ladder; None when even
        the legs do not extend (caller falls back to nested If/Else).
        Flavors: A -- skip side is the join some arm reaches: plain
        If/ElseIf ending at the join, ("next", join); B -- every arm
        departs, skip side too: the Else leg IS the departure; C -- no
        provable join: skip side walks as the Else arm (one level)."""
        legs, else_entry = chain
        # Shared across every per-leg _arm_ok call below.
        legset = frozenset(legs)
        arm_entries = {L.fall for L in legs}
        # Flavor A: the else side is the join the arms converge on.
        if (else_entry.kind != "term"
                and else_entry not in self.visited
                and else_entry not in self.loops
                and else_entry not in self.for_headers
                and else_entry not in self.irreducible
                and (ctx is None or else_entry in ctx[-1].body)
                and all(self._arm_ok(L.fall, legset, arm_entries,
                                     else_entry, stop, ctx)
                        for L in legs)
                and any(self._arm_reaches(L.fall, else_entry, ctx)
                        for L in legs)):
            return self._emit_if_else_chain(
                b, ins, cond_text, then_cond, else_entry, stop, ctx,
                legs=legs, else_entry=else_entry)
        # Flavor B: everything departs; the Else IS the departure.
        if self._edge_departs(else_entry, stop, ctx) \
                and all(self._arm_ok(L.fall, legset, arm_entries,
                                     None, stop, ctx)
                        for L in legs):
            return self._emit_departing_chain(
                b, ins, cond_text, then_cond, stop, ctx, legs, else_entry)
        # Flavor C: flatten the legs, keep the skip side as the Else arm.
        if all(self._arm_ok(L.fall, legset, arm_entries, None, stop, ctx)
               for L in legs):
            return self._emit_open_chain(
                b, ins, cond_text, then_cond, stop, ctx, legs, else_entry)
        return None

    def _emit_chain_ladder(self, ins, then_cond, legs, arm_stop, ctx,
                           arm_exit=None):
        """Emit the shared "If/ElseIf" ladder of the three chain flavors
        and return (results, depth): each leg's pure condition becomes
        the ElseIf line, then its arm walks under *arm_stop*;
        *arm_exit* optionally post-processes each result (the join
        flavor folds bare-exit arms inline).  Else/End If are LEFT to
        the caller."""
        self.emit(ins.pos, +1, "If %s Then" % then_cond)
        depth = len(self.machine.stack)
        results = []
        for i, leg in enumerate(legs):
            if i > 0:
                # Drain the previous arm's leftovers BEFORE the
                # ElseIf (a later flush would land in the wrong arm).
                self._flush_to_depth(ins.pos, depth)
                self._begin_block(leg)
                for j in leg.instrs[:-1]:
                    self.machine.process(j)
                leg_cond = self._pop_cond(leg.term)
                leg_text = self._cond_text(leg.term, leg_cond)
                self.emit(leg.term.pos, 0, "ElseIf %s Then" % leg_text)
            r = self._walk_chain_arm(leg.fall, arm_stop, ctx)
            self._flush_to_depth(ins.pos, depth)
            if arm_exit is not None:
                r = arm_exit(r)
            results.append(r)
        return results, depth

    def _emit_departing_chain(self, b, ins, cond_text, then_cond, stop,
                              ctx, legs, else_entry):
        """Flavor B ladder: every arm departs, the final skip side
        departs -- the Else leg IS the departure statement."""
        results, _depth = self._emit_chain_ladder(ins, then_cond, legs,
                                                  stop, ctx)
        self.emit(ins.pos, 0, "Else")
        self._exit_stmt_for_target(else_entry.start, ctx, ins.pos, stop)
        self.emit(else_entry.start, -1, "End If")
        for r in results:
            if r[0] == "stop":
                return r
        return ("term",)

    def _emit_open_chain(self, b, ins, cond_text, then_cond, stop, ctx,
                         legs, else_entry):
        """Flavor C ladder: legs flatten to If/ElseIf, the final skip
        side walks as the Else arm -- the same walks the nested fallback
        would perform, one nesting level instead of N."""
        results, depth = self._emit_chain_ladder(ins, then_cond, legs,
                                                 stop, ctx)
        if else_entry is not None:
            self.emit(ins.pos, 0, "Else")
            r = self._walk_chain_arm(else_entry, stop, ctx)
            self._flush_to_depth(ins.pos, depth)
            results.append(r)
        self.emit(ins.pos, -1, "End If")
        for res in results:
            if res[0] == "stop":
                return res
        return ("term",)

    def _leg_is_pure_cond(self, leg, depth):
        """Trial-process a candidate ElseIf leg and roll the machine
        back: chainable legs are PURE (no statements emitted, exactly
        one value above *depth*); real statements would execute between
        two chain conditions, where ElseIf syntax has nowhere for them.
        DEFERRED calls are invisible by design (a side-effecting call
        surfaces inside the "ElseIf <cond>" line -- VB4 has no
        short-circuit; the chain loop re-processes the leg for keeps)."""
        m = self.machine
        snap_len = len(m.statements)
        cp = m.checkpoint()  # complete rollback, see StackMachine.restore
        try:
            for j in leg.instrs[:-1]:
                m.process(j)
            pure = (len(m.statements) == snap_len
                    and len(m.stack) == depth + 1)
        finally:
            m.restore(cp)
        return pure

    def _emit_if_else_chain(self, b, ins, cond_text, then_cond, join, stop,
                            ctx, legs=None, else_entry=None):
        """Full If/Else (with ElseIf chaining when the skip side is
        another test on the same join); legs/else_entry precomputed by
        _emit_structural_chain bypass the ipost derivation below."""
        if legs is None:
            legs = [b]
            leg_set = {b}
            else_entry = b.taken
            # chain_depth: pre-If stack baseline for the leg trials
            # (`depth` below is the post-If flush baseline).
            chain_depth = len(self.machine.stack)
            while (else_entry is not None and else_entry is not join
                   and self._chainable_leg(else_entry, chain_depth,
                                           leg_set, frozenset())
                   and self.ipost.get(else_entry) is join):
                legs.append(else_entry)
                leg_set.add(else_entry)
                else_entry = else_entry.taken

        side_stop = stop | {join.start}

        def arm_exit(r):
            """Uniform bare-exit rendering for join arms: an arm merely
            FALLING into the bare exit renders it inside the arm, like
            branch-side arms (so _fold_returns makes "Return X" for
            both; the join needs no rendering)."""
            if (r[0] == "stop" and r[1] is join
                    and join.kind == "term" and len(join.instrs) == 1
                    and join.start in self.exit_addrs):
                self.emit(join.start, 0, self.exit_stmt)
                self.stats["exits"] += 1
                return ("term",)
            return r

        results, depth = self._emit_chain_ladder(
            ins, then_cond, legs, side_stop, ctx, arm_exit=arm_exit)
        # Same drain before Else.
        if else_entry is not None and else_entry is not join:
            self.emit(ins.pos, 0, "Else")
            r = self._walk_chain_arm(else_entry, side_stop, ctx)
            self._flush_to_depth(join.start, depth)
            results.append(arm_exit(r))
        self.emit(join.start, -1, "End If")
        if all(r[0] == "term" for r in results):
            return ("term",)   # every arm left the region; join unreached
        for r in results:
            if r[0] == "stop" and r[1] is join:
                return ("next", join)
        for r in results:
            if r[0] == "stop":
                return r
        return ("next", join)

    def _local_diamond_join(self, b, fall, taken, stop, ctx):
        """The diamond merge the global postdominator pass cannot see
        (compute_ipost sees only exit-reaching paths, so mid-body loop
        exits hide plain If/Else merges): when one side is a plain
        fall-through whose continuation is a fresh forward block the
        OTHER side's subtree reaches (through bare trampolines), that
        block is the join -- stop both arms there and continue after
        the End If, instead of absorbing the merge into one arm.
        Rejected joins: stop members, visited, loop headers/latches,
        irreducible entries, terminators, backward targets; in a loop
        the join must stay inside the innermost body.

        Second family -- a shared RETURN TAIL: one side's own
        postdominator is a fresh REAL-CODE term block (a bare ExitProc
        stays rejected: it renders inline in each arm -- the uniform-
        exit rule) that the other side's subtree also reaches.  The
        term block then plays the join: both arms stop at it, it
        renders once after the End If (pub_184 enemy_attack_role: the
        If-Then tail branched into the Else arm's tail -- a forward
        GoTo into the arm's middle; the early in-Then Exit Sub hides
        the merge from the global pass)."""
        inner = ctx[-1] if ctx else None
        for mine, other in ((taken, fall), (fall, taken)):
            J = mine.fall if (mine is not None and mine.kind is None) \
                else None
            if J is None or J is b or J.start in stop \
                    or J in self.visited or J in self.loops \
                    or J in self._latches or J in self.irreducible \
                    or J.kind == "term" or J.index < b.index \
                    or (inner is not None and J not in inner.body):
                continue
            if self._side_reaches_join(other, J, stop, ctx):
                return J
        for side, other in ((fall, taken), (taken, fall)):
            J = self.ipost.get(side) if side is not None else None
            if J is None or J is b or J.start in stop \
                    or J in self.visited or J in self.loops \
                    or J in self._latches or J in self.irreducible \
                    or J.index < b.index \
                    or J.kind != "term" or len(J.instrs) == 1 \
                    or J.start in self.exit_addrs \
                    or (inner is not None and J not in inner.body):
                continue
            if self._side_reaches_join(other, J, stop, ctx):
                return J
        return None

    def _side_reaches_join(self, other, J, stop, ctx):
        """True when *other*'s subtree holds an edge whose effective
        target (through bare trampolines) is *J*, and none lands on any
        OTHER stop member (mixed destinations would drop a path).
        Loop headers/latches, terminators, visited and out-of-body
        targets are the arm's own departures: neither count nor
        reject."""
        if other is None:
            return False
        inner = ctx[-1] if ctx else None
        seen = set()
        work = [other]
        steps = 0
        found = False
        while work:
            n = work.pop()
            if n is None or n in seen:
                continue
            seen.add(n)
            steps += 1
            if steps > _ARM_WALK_MAX:
                return False
            for s in (n.fall, n.taken):
                if s is None:
                    continue
                eff = s
                hops = 0
                while eff is not None and eff is not J \
                        and eff.kind == "uncond" \
                        and len(eff.instrs) == 1 \
                        and eff.taken is not None \
                        and eff.start not in stop \
                        and eff not in self._latches \
                        and eff not in self.loops \
                        and hops < _TRAMP_HOPS_MAX:
                    eff = eff.taken
                    hops += 1
                if eff is J:
                    found = True
                    continue
                if eff.start in stop:
                    return False   # a stop member the fold would drop
                if eff.kind == "term" or eff in self.visited \
                        or eff in self.loops or eff in self._latches \
                        or eff in self.irreducible \
                        or (inner is not None and eff not in inner.body):
                    continue          # the arm's own departure
                work.append(eff)
        return found

    def _emit_dangling_if(self, b, ins, then_cond, stop, ctx):
        """Cross-proc taken edge: If cond Then <fall> End If, closed at
        the next control boundary (join, terminator or loop edge; a
        cross-proc target cannot be an in-proc loop header)."""
        boundary = self._dangling_boundary(b.fall, ctx)
        bstop = stop | ({boundary.start} if boundary is not None else set())
        r = self._emit_one_sided(
            ins, then_cond, b.fall, bstop, ctx,
            close_va=boundary.start if boundary is not None else None)
        if r[0] == "stop":
            return r
        return ("term",)

    def _dangling_boundary(self, fall, ctx):
        """First block that must start OUTSIDE a cross-proc If: plain
        single-pred blocks stay inside, structured blocks start
        outside, a proc tail is swallowed whole; a plain block whose
        fall leaves the innermost loop ENDS the If there."""
        b = fall
        # fall edges always point to the NEXT block: strictly
        # increasing, no cycles -- this terminates.
        while b is not None:
            if b.kind == "term" and len(b.preds) == 1 \
                    and b not in self.visited:
                return None
            if b.kind is None and len(b.preds) == 1 \
                    and b not in self.visited and b not in self.loops \
                    and b not in self.irreducible:
                if b.fall is None:
                    return None
                if ctx and b.fall not in ctx[-1].body:
                    return b.fall
                b = b.fall
                continue
            return b
        return None

    # -- loops ---------------------------------------------------------------

    def emit_loop(self, h, stop, ctx):
        info = self.loops[h]
        body, latches = info["body"], info["latches"]
        self._begin_block(h)
        self.stats["loops"] += 1

        # While-shaped header: a condition-only top test whose taken
        # edge leaves the loop.
        header_exits = (h.kind == "cond" and h.taken is not None
                        and h.taken not in body)
        cond_only = all(i.label in _NO_EMIT_LABELS
                        for i in h.instrs[:-1]) if h.instrs else True
        if header_exits and cond_only:
            return self._emit_while(h, body, latches, stop, ctx)

        # Do-shaped: header is ordinary body; the latch tests at the bottom.
        return self._emit_do(h, body, latches, stop, ctx)

    def _latch_for(self, body, latches, h):
        """Pick the structural latch: the highest-address back-edge source."""
        cands = [u for u in latches if u in body]
        if not cands:
            raise StructureUnsupported("loop without latch @0x%08X" % h.start)
        return max(cands, key=lambda b: b.start)

    def _emit_while(self, h, body, latches, stop, ctx):
        latch = self._latch_for(body, latches, h)
        if latch is h or latch.kind != "uncond" or latch.taken is not h:
            # Mixed shapes (conditional back edge with a top test):
            # the Do renderer handles it.
            return self._emit_do(h, body, latches, stop, ctx)
        # cond_only guarantees pure value ops, so the stack top IS the
        # tested value -- including the EMPTY lone-branch case (the
        # machine carries the pushed condition across the boundary;
        # the eval stack is statement-scoped: nothing deeper is live).
        for j in h.instrs[:-1]:
            self.machine.process(j)
        cond_text = self._pop_cond(h.term)
        # The body is the FALL side: BranchF keeps the condition,
        # BranchT (fall = cond-FALSE) displays it negated (latent on
        # PAL.EXE -- headers test BranchF, probed).
        cond_text = self._cond_text(h.term, cond_text)
        # Internal exits (non-header branches out) force the Do form
        # so Exit Do stays legal VB4.
        exits = self._loop_exits(h, body, exclude_blocks=[h, latch])
        exit_block = h.taken
        if exits:
            open_text, close_text = "Do While %s" % cond_text, "Loop"
            kind = "dowhile"
        else:
            open_text, close_text = "While %s" % cond_text, "Wend"
            kind = "while"
        self.emit(h.start, +1, open_text)
        depth = len(self.machine.stack)
        ctx2 = ctx + [LoopCtx(kind, h, body, latch, exit_block, depth)]
        result = self.walk(h.fall, stop | {latch.start}, ctx2)
        if result[0] != "stop" or result[1] is not latch:
            pass  # body path ended early (exit inside): still close
        self._consume_latch(latch)
        self.machine.flush_leftovers(latch.term.pos)
        self.emit(latch.term.pos, -1, close_text)
        self._flush_to_depth(latch.term.pos, depth)
        if exit_block is None:
            return ("term",)
        return ("next", exit_block)

    def _cond_latch_shape(self, h, latch):
        """True when the header's own closing test drives a bare uncond
        latch (the Loop While/Until shape _close_cond_loop renders)."""
        term_h = h.term
        return (term_h is not None
                and term_h.label in stack_ir.COND_BRANCH
                and latch.kind == "uncond" and latch.taken is h
                and len(latch.instrs) == 1
                and (h.taken is latch or h.fall is latch))

    def _latch_pred_candidate(self, h, body, latch):
        """The closing test block driving a bare-branch latch (a
        separate test whose sole successor-set feeds the latch), or
        None.  Trusted only for tiny loops; bigger "tests" may be
        state-machine legs."""
        if not (latch.kind == "uncond" and latch.taken is h
                and len(latch.instrs) == 1
                and len(latch.preds) == 1
                and len(body) <= _LATCH_PRED_MAX_BODY):
            return None
        cand = latch.preds[0]
        if cand is not h and cand.kind == "cond" \
                and cand in body and (cand.fall is latch
                                      or cand.taken is latch):
            return cand
        return None

    def _loop_bottom_tested(self, lc):
        """True when a kind="do" loop evaluates its condition at the
        Loop line (cond-latch or latch-pred shape).  Restarting such a
        loop at its header would skip that test -- not a Continue."""
        if lc.kind != "do" or lc.latch is None:
            return False
        if self._cond_latch_shape(lc.header, lc.latch):
            return True
        return (self._latch_pred_candidate(lc.header, lc.body, lc.latch)
                is not None)

    def _shared_loop_exit(self, body):
        """The single shared epilogue every loop-leaving edge converges
        on -- the Exit Do upgrade for uncond-latch Do loops (None when
        absent or unsafe to take).

        A Do closed by an unconditional latch has no fall-out exit:
        every departure is an in-body branch.  When >= 2 such edges
        (through bare skip-over trampolines, resolved the way
        _exit_stmt_for_target resolves them) meet at ONE term block
        outside the loop that is not itself a bare ExitProc address
        (those already render inline as Exit Sub / Return; a post-Loop
        copy would be dead) and not on any cycle (a restart target
        keeps its GoTo), that block is the loop's real exit: edges to
        it render as Exit Do and the epilogue renders once after
        Loop -- no label anchored mid-block inside one arm, no GoTo
        jumping into that arm."""
        targets = set()
        for n in body:
            for succ in (n.fall, n.taken):
                if succ is not None and succ not in body:
                    targets.add(succ)
        resolved = set()
        for t in targets:
            # Penetrate bare skip trampolines; a tramp re-entering the
            # body (or leaving the proc) stays as-is and fails the
            # term gate below -- conservative, never a wrong exit.
            seen = set()
            while self._bare_tramp(t) and t.start not in seen \
                    and t.taken not in body \
                    and self.proc_start <= t.taken.start < self.proc_end:
                seen.add(t.start)
                t = t.taken
            resolved.add(t)
        if len(resolved) < 2:
            return None     # a lone departure renders inline already
        chains = []
        for t in resolved:
            chain, cur, seen = [], t, set()
            while cur is not None and cur not in seen:
                seen.add(cur)
                chain.append(cur)
                cur = self.ipost.get(cur)
            chains.append(chain)
        x = None
        for cand in chains[0]:
            if all(cand in c for c in chains[1:]):
                x = cand
                break
        if x is None or x in body or x in self._cyclic_blocks:
            return None
        if x.kind != "term" or x.start in self.exit_addrs:
            return None
        return x

    def _resolve_natural_exit(self, t, body):
        """The loop's real exit when the block after the latch is a
        bare-trampoline run (pub_167 process_AutoScript: the post-latch
        tramp chain ends at the shared advance-and-return tail, which
        only arm GoTos ever reach -- the tramp head itself has no
        predecessors, so the default exit_block is unreachable and the
        tail gets absorbed into an arm with 7 GoTos jumping into it).

        The resolved block -- it must differ from the tramp head, be
        reachable, outside the body, off every cycle, and exit-bound
        (a real-code term block, or a plain block whose branch-free
        fall continuation runs straight to a bare ExitProc without
        re-entering the loop; a shared BODY continuation keeps the
        default) -- plays exit_block: in-loop edges to it render Exit
        Do, it renders once after Loop, and an arm's fall into it is
        an Exit Do (LoopCtx.shared_exit).  None keeps the default."""
        head = t
        seen = set()
        while self._bare_tramp(t) and t.start not in seen \
                and t.taken not in body \
                and self.proc_start <= t.taken.start < self.proc_end:
            seen.add(t.start)
            t = t.taken
        if t is head:
            return None     # no tramp run: default behavior
        if t in body or t in self._cyclic_blocks \
                or t not in self.reachable or t in self.loops \
                or t in self.irreducible:
            return None
        if t.kind == "term":
            return t if len(t.instrs) > 1 else None
        cur, hops = t, 0
        while cur is not None and hops < 4:
            if cur.kind == "term":
                return t if (len(cur.instrs) == 1
                             and cur.start in self.exit_addrs) else None
            if cur.taken is not None or cur in body:
                return None
            cur = cur.fall
            hops += 1
        return None

    def _emit_do(self, h, body, latches, stop, ctx):
        latch = self._latch_for(body, latches, h)
        self.emit(h.start, +1, "Do")
        depth = len(self.machine.stack)
        exit_block = latch.fall
        if exit_block is None:
            # An uncond latch never falls through; the exit is usually
            # the physically following block.  Exception (generic tail
            # only -- the closing-test shapes take their own exits):
            # every in-body departure converges on one shared
            # epilogue outside the loop; that block is then the real
            # exit (in-loop edges render as Exit Do, the epilogue
            # renders once after Loop).
            exit_block = self._block_after(latch)
            if latch is not h and not self._cond_latch_shape(h, latch) \
                    and self._latch_pred_candidate(h, body, latch) is None:
                shared = self._shared_loop_exit(body)
                if shared is not None:
                    exit_block = shared
                elif exit_block is not None:
                    # The post-latch block may be a bare-tramp run to
                    # the loop's real exit (pub_167): resolve so its
                    # edges render Exit Do and it renders post-Loop.
                    resolved = self._resolve_natural_exit(exit_block,
                                                          body)
                    if resolved is not None:
                        exit_block = resolved
        ctx2 = ctx + [LoopCtx("do", h, body, latch, exit_block, depth)]
        # A hoisted/resolved exit (not the plain block-after-latch):
        # any walk inside the loop that lands on it renders the exit
        # statement.  Depth-0 landings happen when a NESTED loop's
        # emit returns ("next", <this exit_block>) -- the walk's
        # loops-branch continues without the fall-exits-loop raise
        # (pub_186: the middle loop's spine receives the inner loop's
        # exit and must render Exit Do, not the epilogue inline).
        ctx2[-1].shared_exit = exit_block is not None \
            and latch.fall is None \
            and exit_block is not self._block_after(latch)
        if latch is h:
            # Single-block loop: the header is also the latch.
            for j in h.instrs[:-1]:
                self.machine.process(j)
        else:
            # Test-at-bottom form: the test ends the header, the back
            # edge is a separate bare branch block (the len==1 guard
            # enforces "bare"; real-code latches take the generic
            # tail below, which emits them).
            if self._cond_latch_shape(h, latch):
                for j in h.instrs[:-1]:
                    self.machine.process(j)
                # _close_cond_loop pops the condition and does
                # _begin_block right before the Loop line (a GoTo to
                # the latch then labels the back edge).
                return self._close_cond_loop(h.term, h, latch, body, depth)
            # The header is ordinary body code: process_block directly
            # (walk() would reject it as already-visited).  Latch_pred
            # special case: a bare-branch latch whose sole pred is the
            # closing test (Loop While/Until), trusted only for tiny
            # loops; bigger "tests" may be state-machine legs.
            latch_pred = self._latch_pred_candidate(h, body, latch)
            if latch_pred is not None:
                walk_stop = stop | {latch.start, latch_pred.start}
                res = self.process_block(h, walk_stop, ctx2)
                if res[0] == "next" and res[1] is not None \
                        and res[1] is not latch_pred:
                    self.walk(res[1], walk_stop, ctx2)
                if res[0] == "term":
                    # Body ended with an exit: close the loop anyway
                    # (_begin_block first so a GoTo to the latch
                    # labels the back edge).
                    self._begin_block(latch)
                    self.emit(latch.term.pos, -1, "Loop")
                    self._flush_to_depth(latch.term.pos, depth)
                    return ("term",)
                exit2 = self._block_after(latch)
                if latch_pred in self.visited:
                    # The body walk consumed the test block (a nested
                    # loop's latch, or a guard ate the branch): close
                    # plainly at the trampoline.
                    self._begin_block(latch)
                    for j in latch.instrs[:-1]:
                        self.machine.process(j)
                    self._flush_to_depth(latch.term.pos, depth)
                    self.emit(latch.term.pos, -1, "Loop")
                    self._flush_to_depth(latch.term.pos, depth)
                    if exit2 is None:
                        return ("term",)
                    return ("next", exit2)
                self._begin_block(latch_pred)
                for j in latch_pred.instrs[:-1]:
                    self.machine.process(j)
                # _close_cond_loop pops the condition; the latch's
                # sole effect is the rendered back edge (flushed
                # deferred calls stay above the label).
                return self._close_cond_loop(latch_pred.term, latch_pred,
                                             latch, body, depth)
            res = self.process_block(h, stop | {latch.start}, ctx2)
            crossing = None
            if res[0] == "next" and res[1] is not None:
                res = self.walk(res[1], stop | {latch.start}, ctx2,
                                primary=True)
            if res[0] == "stop":
                # The body walk ended on an edge rendered implicitly
                # (by adjacency to whatever emits next).  Appending
                # interior orphans between would intercept that fall
                # (#19: process_Battle's round tail-check fell into
                # the dispatch region instead of the latch restart).
                crossing = res[1]
            # #18: branch-only regions inside the loop render BEFORE the
            # close (see _emit_interior_orphans), not hoisted after it
            # by the orphan pass (which produced jump-into-block edges
            # at inventory_use_menu / process_Battle).
            self._emit_interior_orphans(h, body, latch, stop, ctx2,
                                        crossing)
            self._consume_latch(latch)
        term = latch.term
        lab = term.label
        if lab == "Branch" and latch.taken is h:
            self.machine.flush_leftovers(term.pos)
            self.emit(term.pos, -1, "Loop")
        elif lab in stack_ir.COND_BRANCH:
            # Which edge continues the loop: directly to the header,
            # or via a bare branch block back to it (the compiler
            # splits test and back edge)?
            cont_blk = None
            if latch.taken is h:
                cont_taken = True
            elif latch.fall is h:
                cont_taken = False
            elif self._bare_tramp(latch.taken) and latch.taken.taken is h:
                cont_blk, cont_taken = latch.taken, True
            elif self._bare_tramp(latch.fall) and latch.fall.taken is h:
                cont_blk, cont_taken = latch.fall, False
            else:
                raise StructureUnsupported(
                    "unrecognized loop latch @0x%08X" % latch.start)
            cond_text = self._pop_cond(term)
            # Does the continuing edge carry the true or false value?
            if lab == "BranchF":
                cont_true = not cont_taken   # taken=false side, fall=true side
            else:
                cont_true = cont_taken       # BranchT: taken=true side
            self.machine.flush_leftovers(term.pos)
            # _begin_block before the Loop line so a GoTo to the
            # silent back-edge trampoline labels the back edge.
            if cont_blk is not None:
                self._begin_block(cont_blk)
            self.emit(term.pos, -1,
                      "Loop While %s" % cond_text if cont_true
                      else "Loop Until %s" % cond_text)
        else:
            raise StructureUnsupported(
                "unrecognized loop latch @0x%08X" % latch.start)
        self._flush_to_depth(term.pos, depth)
        if exit_block is None:
            return ("term",)
        if exit_block in self.visited:
            # The block after the latch was already rendered by a body
            # branch: no further reachable code (continuing would
            # degrade to a phantom GoTo + dangling label).
            return ("term",)
        return ("next", exit_block)

    def _interior_orphan_ok(self, h, body, latch):
        """#18 query: pending span blocks of this loop that are clean
        (no in-edge from a pred that will not render inside).
        Returns the clean set or None."""
        pending = [b for b in body
                   if b not in self.visited and b is not latch]
        if not pending:
            return None
        span = set(b for b in pending if h.start < b.start < latch.start)
        if not span:
            return None
        tainted = set()
        changed = True
        while changed:
            changed = False
            for b in span:
                if b in tainted:
                    continue
                if any(p is not b and p not in self.visited
                       and (p not in span or p in tainted)
                       for p in b.preds):
                    tainted.add(b)
                    changed = True
        ok = span - tainted
        return ok or None

    def _emit_orphan_regions(self, ok, latch, stop, ctx):
        """Walk the clean region blocks in address order (#18).
        A loop-exit epilogue already rendered INSIDE this loop (a
        nested loop's shared-exit upgrade grabbed it): an "Exit Do"
        from a region rendered here would land past the Loop close,
        skipping that epilogue -- clear the ctx exit so region edges
        render plain GoTos to the label instead."""
        if ctx and ctx[-1].exit_block is not None \
                and ctx[-1].exit_block in self.visited:
            trimmed = LoopCtx(ctx[-1].kind, ctx[-1].header, ctx[-1].body,
                              ctx[-1].latch, None, ctx[-1].depth)
            trimmed.shared_exit = False
            ctx = ctx[:-1] + [trimmed]
        self._emitting_orphans = True
        try:
            blocks = sorted(ok, key=lambda x: x.start)
            for i, blk in enumerate(blocks):
                if blk in self.visited:
                    continue
                self.needed_labels.add(blk.start)
                res = self.walk(blk, stop | {latch.start}, ctx)
                if res[0] == "stop" and i + 1 < len(blocks):
                    # The walk deferred its edge to *res[1]* counting
                    # on adjacency -- but more region blocks render
                    # before the caller resumes, so adjacency is gone:
                    # make the edge explicit (#19 audit caught this as
                    # fall 0041E404->0041EAAA landing in 0041E134).
                    self._exit_stmt_for_target(
                        res[1].start, ctx, blk.term.pos, stop)
        finally:
            self._emitting_orphans = False

    def _emit_interior_orphans(self, h, body, latch, stop, ctx, crossing):
        """#18/#19: loop-interior branch-only regions render before the
        Loop close -- not hoisted after the loop by the orphan pass
        (which produced VB4-illegal jump-into-block edges).

        A region qualifies when its head address falls inside the
        loop's [head, latch) span and no in-edge comes from a block
        that will not render inside: a pred outside the loop body, or
        a pending span block that itself hoists (taint propagates
        along successors -- mutual pred cycles among span blocks are
        internal and stay clean).  Regions addressed at/after the
        latch (cleanup epilogues) stay for the post-loop walk /
        orphan pass.

        This is the body-END fallback (before the Loop close): the
        pre-latch hook in walk() places regions before the block
        that falls into the latch, so the loop's tail flow keeps its
        natural fall-to-Loop close.  A region still pending here
        never met its pre-latch chance -- safe only because every
        region block ends in an explicit jump and its entry edge is
        an explicit GoTo (#19: appending without guarding broke the
        body walk's implicit fall into the latch -- the tail check
        fell into the region and re-dispatched stale input).  When
        the walk just ended on such an implicit edge (crossing is
        its target) the edge is re-rendered explicitly first: a
        Continue Do barrier for the latch; any other crossing
        target is unknown territory -- skip the append for this
        loop (the orphan pass hoists, as before #18)."""
        ok = self._interior_orphan_ok(h, body, latch)
        if ok is None:
            return
        if crossing is not None:
            if crossing is not latch:
                # Unknown implicit edge -- do not risk intercepting it.
                return
            # The walk fell/branched into the latch and that edge
            # renders by adjacency to the next emission; the appended
            # region would sit in between.  Fall-to-latch + latch's
            # Branch-to-head = the loop restart -- spell it out.
            src = self._last_begin
            va = src.term.pos if src is not None and src.term \
                else latch.start
            self.machine.flush_leftovers(va)
            self.emit(va, 0, "Continue Do")
            self.stats["continues"] += 1
        self._emit_orphan_regions(ok, latch, stop, ctx)

    def _loop_exits(self, h, body, exclude_blocks):
        """Blocks in the loop body that branch (not fall) out of it."""
        exits = []
        for n in body:
            if n in exclude_blocks:
                continue
            if n.taken is not None and n.taken not in body:
                exits.append(n)
        return exits

    def emit_for(self, b, ins, stop, ctx):
        """For..Next loop: the ForI2 preheader drives the body walk."""
        h = b.fall
        if h is None or h not in self.loops:
            raise StructureUnsupported("For without loop @0x%08X" % ins.pos)
        info = self.loops[h]
        body, latches = info["body"], info["latches"]
        latch = max((u for u in latches
                     if u.kind == "next" and u.taken is h),
                    key=lambda blk: blk.start, default=None)
        if latch is None:
            raise StructureUnsupported(
                "For without Next latch @0x%08X" % ins.pos)
        self.machine._loop_start(ins.label, ins.operand, ins.pos)  # noqa: SLF001
        # _loop_start/_loop_end: StackMachine-internal For bookkeeping
        # (contract in stack_ir.py, golden-hash covered); the noqa
        # markers document the deliberate private access.
        self.stats["loops"] += 1
        depth = len(self.machine.stack)
        exit_block = b.taken
        ctx2 = ctx + [LoopCtx("for", h, body, latch, exit_block, depth)]
        result = self.walk(h, stop | {latch.start}, ctx2)
        if result[0] != "stop" or result[1] is not latch:
            pass  # body path ended via an exit; close the loop anyway
        self._consume_latch(latch, "For latch")
        self.machine._loop_end(latch.term.label, latch.term.operand,
                               latch.term.pos)  # noqa: SLF001
        self._flush_to_depth(latch.term.pos, depth)
        cont = latch.fall
        if cont is None:
            return ("term",)
        return ("next", cont)

    # -- irreducible fallback --------------------------------------------------

    def emit_flat_block(self, b, ctx):
        """Emit one block of an irreducible region with explicit gotos."""
        self._begin_block(b)
        for ins in b.instrs:
            lab = ins.label
            if lab in stack_ir.COND_BRANCH:
                cond_text = self._pop_cond(ins)
                if ins.label in _BRANCH_TRUE:
                    self.emit(ins.pos, +1, "If %s Then" % cond_text)
                else:
                    self.emit(ins.pos, +1, "If Not (%s) Then" % cond_text)
                if b.taken is not None:
                    self.needed_labels.add(b.taken.start)
                self.emit(ins.pos, 0,
                          "GoTo L_%08X" % (b.taken_va or 0))
                self.emit(ins.pos, -1, "End If")
            elif lab in stack_ir.UNCOND_BRANCH:
                self.machine.flush_leftovers(ins.pos)
                if b.taken is not None:
                    self.needed_labels.add(b.taken.start)
                self.emit(ins.pos, 0, "GoTo L_%08X" % (b.taken_va or 0))
            else:
                self.machine.process(ins)
        if b.fall is None:
            return ("term",)
        return ("next", b.fall)


def structure_proc(instrs, proc_start, proc_end, machine, exit_addrs,
                   exit_stmt):
    """Structure one procedure.  Returns (stmts, label_at_stmt, stats);
    label_at_stmt maps {stmt index: [label VA, ...]} for every GoTo
    target that resolved inside this proc.  Raises on unrepresentable
    shapes (the driver surfaces per-proc error stubs)."""
    s = Structurer(instrs, proc_start, proc_end, machine, exit_addrs,
                   exit_stmt)
    return s.run()
