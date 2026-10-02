"""Post-fix invariants for the style-review batch (run on fresh out/)."""
import re
import sys

fail = 0


def check(name, cond, detail=""):
    global fail
    if cond:
        print("PASS %s" % name)
    else:
        fail += 1
        print("FAIL %s  %s" % (name, detail))


pseudo = open("out/pal_pseudocode.txt").read()
code = open("out/pal_code.txt").read()
disasm = open("out/pal_disasm.txt").read()

# ---- #2/#7/#9: signature modifiers + pointee types -----------------------
# The old "modifier match disasm annotations" check was self-confirming
# (#9: both sides came from the same classifier).  The anchors below were
# hand-verified against pal_disasm.txt call sites (STYLE_REVIEW #9).
ANCHORS = [
    # pub_132 play_theurgy_anim: ARG1 body x2 (FLdRfVar 0041A55A/0041BE9A),
    # ARG2 copy x2 (FMemLdI2 f0314 + PopTmpLdAd2), ARG3 body x2; a0's
    # pointee via the forward chain into pub_013's ILdI2.
    ("play_theurgy_anim",
     "Sub play_theurgy_anim(ByRef magicIdx As Integer, "
     "ByVal startFrame As Integer, ByRef minFrames As Integer)"),
    # pub_060 calc_battle_damage: attack copies at pub_155/178/182,
    # defense copy at pub_195; body is ILdI2 read-only.
    ("calc_battle_damage",
     "Function calc_battle_damage(ByVal attack As Integer, "
     "ByVal defense As Integer) As Integer"),
    # pub_099 display_number: a2 copies at pub_151/pub_187.
    ("display_number",
     "Sub display_number(ByRef x As Integer, ByRef y As Integer, "
     "ByVal number As Integer, ByRef colorType As Integer)"),
    # pub_184 enemy_attack_role: ARG1 copy at pub_196 (I2 source, so
    # Integer -- the old "As Long" was the FLdI4 width artifact).
    ("enemy_attack_role",
     "Sub enemy_attack_role(ByRef enemyIdx As Integer, "
     "ByVal targetRole As Integer, ByRef itemID As Integer)"),
    # pub_005 swap_values: IStI2 write-through swap, both callers push
    # variable bodies -- the canonical ByRef.
    ("swap_values",
     "Sub swap_values(ByRef v1 As Integer, ByRef v2 As Integer)"),
]
for name, want in ANCHORS:
    got = re.search(r"^(Sub|Function) %s\(.*$" % re.escape(name),
                    code, re.M)
    check("#9 anchor %s" % name, got is not None
          and got.group(0) == want,
          "got %r" % (got.group(0) if got else None))

sig_re = re.compile(r"^(?:Sub|Function) \S+\(([^)]*)\)", re.M)
total = 0
typed = 0
byval_params = 0
for m in sig_re.finditer(pseudo):
    for p in (x.strip() for x in m.group(1).split(",") if x.strip()):
        total += 1
        if p.startswith("ByVal "):
            byval_params += 1
        if re.search(r"\bAs [\w ]+$", p):
            typed += 1
check("#9 ByVal param count == 5 (hand-verified sites only)",
      byval_params == 5, "got %d" % byval_params)
check("#9 no 'ByVal ... As Long' width artifacts left",
      not re.search(r"ByVal \w+ As Long",
                    "\n".join(l for l in pseudo.splitlines()
                               if not l.startswith("Declare "))))
print("     params with As clause: %d / %d" % (typed, total))

# ---- #14: VCall receiver + result inference -------------------------------
check("#14 no hardcoded Me. prefix on object receivers",
      len(re.findall(r"Me\.method_", code)) == 2)  # priv_163's 2 Me sites
check("#14 no receiver-as-trailing-arg leak",
      not re.search(r"method_[0-9A-F]{4}\([^)]*\bvb_com_object_[12]\.f0000\)\s*$",
                    code, re.M))
check("#14 object receivers prefixed",
      len(re.findall(r"vb_com_object_[12]\.f0000\.method_", code)) == 22)
check("#14 sub-like vcalls render as Call statements",
      len(re.findall(r"\bCall vb_com_object_[12]\.f0000\.method_", code)) == 15)

# ---- #15: Declare block + table dump --------------------------------------
check("#15 Declare statements rendered", len(re.findall(r"^Declare ", code, re.M)) == 74)
check("#15 every Declare carries Lib and Alias",
      len(re.findall(r'^Declare (?:Function|Sub) \S+ Lib ".*" Alias ".*" \(',
                     code, re.M)) == 74)
check("#15 binary's wrong-lib strings exposed faithfully",
      'Declare Sub winmm.ShowCursor Lib "winmm"' in code
      and 'Alias "mciSendStringA"' in code)
check("#15 disasm table dump present",
      "==== Declares (Declare table) ====" in disasm
      and len(re.findall(r"^\d+\s+\S+\s+\S+\s+0x[0-9A-F]{8}", disasm, re.M)) == 77)

# ---- #16: LateIdLdVar invoke + FLdPr receiver ----------------------------
check("#16 lateid gets rendered inline (3 sites)",
      len(re.findall(r"\.lateid_[0-9A-F]{8}", code)) == 3)
check("#16 zero-argument get (no parenthesized lateid call)",
      not re.search(r"lateid_[0-9A-F]{8}\(", code))
check("#16 no LateIdLdVar/FLdPr/PopAd opcode names leak to code",
      not re.search(r"\b(LateIdLdVar|FLdPr|PopAd)\b", code))
check("#16 Sub_Main lateid get flows into InitInput arg",
      re.search(r"initResult = PAL_InitInput\(diTmp\.lateid_00010017,"
                r" dsInitResult\)", code) is not None)
check("#16 priv_092 lateid temp Dim eliminated (3 legit menu tmps remain)",
      len(re.findall(r"^    Dim tmp$", code, re.M)) == 3)
check("#16 receiver no longer leaks as trailing vcall arg",
      "method_0038(vb_com_object_2.f0000.method_000C(diTmp), diTmp,"
      " dsInitResult)" not in code)

# ---- #17: Open flags -> VB4 syntax ----------------------------------------
check("#17 Open renders canonical VB4 syntax",
      code.count("Open 'WORD.DAT' For Random Access Read As #2 Len = 10") == 1)
check("#17 no bare pseudo Open form left",
      not re.search(r"^\s*Open '[^']*', \d+, \d+$", code, re.M))
check("#17 unknown flag fields stay visible",
      re.search(r"For \?[0-9A-F]{2}", code) is None
      and "' lock=" not in code.split("Open 'WORD.DAT'")[0])

# ---- #18: loop-interior regions render inside, no jump-IN edges ----------
# pub_186: the m = 1 dispatch test renders before the outer Loop close;
# its fall-through is the backedge, so the old phantom GoTo L_004160F2
# (and its label) are gone.  pub_196: the dirResult region renders inside
# the nested Do -- the old hoisted GoTo L_0041DBEE is now Continue Do,
# and the battle_role jump lands on the rendered L_0041EAAA (same block).
inv = code[code.index("Sub inventory_use_menu"):]
inv = inv[:inv.index("End Sub")]
check("#18 pub_186 dispatch region inside outer loop (before Loop)",
      re.search(r"L_004160E6:\n        If m <> 1 Then\n"
                r"            GoTo L_004160F6\n        End If\n"
                r"    Loop\n", inv) is not None)
check("#18 pub_186 phantom backedge GoTo gone",
      "GoTo L_004160F2" not in inv and "L_004160F2:" not in inv)
check("#18 pub_186 epilogue label kept for its middle-loop edges",
      "L_004160F6:" in inv)
bat = code[code.index("Function process_Battle"):]
bat = bat[:bat.index("End Function")]
check("#18 pub_196 hoisted restart now Continue Do",
      len(re.findall(r"GoTo L_0041DBEE", bat)) == 1  # in-arm -15 restart stays
      and "battle_curr_role_idx = prevRoleIdx\n"
      "                    Continue Do" in bat)
check("#18 pub_196 dirResult region renders inside the nested Do",
      "L_0041DECC:" in bat
      and bat.index("L_0041DECC:") > bat.index("L_0041DBEE:"))
check("#18 pub_196 role-jump target rendered (same-block edge)",
      "L_0041EAAA:" in bat and "L_0041E404:" in bat
      and re.search(r"GoTo L_0041EAAA\n", bat) is not None)
check("#18 no dangling unreachable markers",
      not re.search(r"unreachable p-code ----\n(End Sub|End Function)",
                    code))
check("#18 no trailing Exit Sub before End Sub",
      not re.search(r"^ {4}Exit Sub$\nEnd Sub", code, re.M))

# ---- #19: pre-latch placement keeps the loop tail natural --------
# The round tail check (0041EAAA) falls into the per-round latch
# (0041EABC -> header restart).  The interior dispatch region
# splices in AHEAD of the tail check (not at body end): the menu
# path's fall edge over the region renders as an explicit GoTo, and
# the tail check keeps its natural fall-to-Loop close -- no
# Continue-Do-before-live-code (the "apparent dead code" the first
# cut produced).  The structurer's edge audit (walk-logged fall/
# defer edges vs all-paths flow reachability) is the acceptance
# gate: the summary line must read "edge audit: clean".
check("#19 menu-path fall over the region renders explicit",
      re.search(r"Call draw_battle_status_bar\(\)\n"
                r"                GoTo L_0041EAAA\n"
                r"L_0041DECC:", bat) is not None)
check("#19 region exit renders explicit (no adjacency over later "
      "region blocks)",
      re.search(r"                    battle_role_idx_2 = 0\n"
                r"                End If\n"
                r"                GoTo L_0041EAAA\n", bat) is not None)
check("#19 tail check falls straight into the Loop close",
      re.search(r"L_0041EAAA:\n"
                r"                If battle_curr_role_idx >= "
                r"battle_extra_param Then\n"
                r"                    Exit Do\n"
                r"                End If\n"
                r"            Loop", bat) is not None
      and "Continue Do\nL_0041DECC:" not in bat)

# ---- #12: lifecycle suppression -------------------------------------------
check("#12 no AryLock/AryUnlock statements", "AryLock" not in code
      and "AryUnlock" not in code)
check("#12 phantom lock Dims gone",
      not re.search(r"^    Dim (seekResult|lockMem)$", code, re.M))
check("#12 real seekResult variables unaffected",
      len(re.findall(r"^    Dim seekResult As Long$", code, re.M)) == 2)

# ---- #13: CodeView label alias --------------------------------------------
check("#13 FMemLdStr renamed in disasm (126 sites)",
      len(re.findall(r"\bFMemLdStr\b", disasm)) == 0
      and len(re.findall(r"\bFMemLd4\b", disasm)) == 126)
check("#13 operand format unchanged (FMem prefix)",
      re.search(r"FMemLd4  mem=stack\+8\.f", disasm) is not None)
check("#13 scalar Dim types unchanged (hint exclusion intact)",
      len(re.findall(r"^Dim screen_buffer_ptr As Long$", code, re.M)) == 1
      and len(re.findall(r"^Dim RPG_money As Long$", code, re.M)) == 1)

# ---- #3: runtime builtins -------------------------------------------------
# Mapped subset: rtcAnsiValueBstr->Asc, rtcStrFromVar->Str (rtcBstrFromAnsi->
# Chr predates the batch).  Deliberately raw (follow-up decision, disasm
# traceability): rtcRandomNext/rtcGetTimer/rtcMsgBox/rtcRandomize/rtcDoEvents.
for raw, n in (("rtcRandomNext", 59), ("rtcMsgBox", 3), ("rtcGetTimer", 1),
               ("rtcRandomize", 1), ("rtcDoEvents", 1)):
    got = len(re.findall(r"\bVB40032\.%s\b" % raw, code))
    check("#3 %s stays raw (%d sites)" % (raw, n), got == n, "got %d" % got)
check("#3 mapped names gone",
      not re.findall(r"VB40032\.rtc(AnsiValueBstr|StrFromVar|BstrFromAnsi)\b", code))
check("#3 Str mapped", re.search(r"[^\w]Str\(", code) is not None)
check("#3 Asc mapped", re.search(r"\bAsc\(", code) is not None)
check("#3 Chr mapped (pre-existing)", re.search(r"\bChr\(", code) is not None)
check("#3 no other rtc* leaks",
      not re.findall(r"VB40032\.rtc(?!RandomNext|MsgBox|GetTimer|Randomize|"
                     r"DoEvents|AnsiValueBstr|StrFromVar|BstrFromAnsi)\w+", code))

# ---- #4: tail Exit Sub ----------------------------------------------------
tail_exit = re.findall(r"(L_[0-9A-F]{8}:)?\n(    Exit Sub|    Exit Function)\n(End Sub|End Function)", code)
print("     remaining tail exits: %d (all label-anchored)" % len(tail_exit))
for lbl, _ex, _end in tail_exit:
    if not lbl:
        fail += 1
        print("FAIL #4 unlabeled tail exit kept", lbl)
mid_exits = len(re.findall(r"^ *Exit (?:Sub|Function)$", code, re.M))
print("     Exit Sub/Function stmts now: %d (was 148)" % mid_exits)
for_exits = len(re.findall(r"^ *Exit (?:For|Do)$", code, re.M))
print("     Exit For/Do stmts (unchanged machinery): %d" % for_exits)

# ---- #5: CSng literal drops ----------------------------------------------
lit_csng = re.findall(r"CSng\(-?\d+(\.\d+)?\)", code)
check("#5 no CSng(<literal>) left", not lit_csng, str(lit_csng[:5]))
print("     remaining CSng total: %d (was 124; expect 62 var/expr)" % code.count("CSng("))

# ---- #1: module scalar Dims ----------------------------------------------
scalar_dims = re.findall(r"^Dim (\w+) As (\w+)$", code, re.M)
print("     module scalar Dims: %d (expect 143)" % len(scalar_dims))
check("#1 scalar Dim count", len(scalar_dims) == 143, str(len(scalar_dims)))
check("#1 f02AC theurgy_effect_max",
      ("theurgy_effect_max", "Integer") in scalar_dims)
check("#1 f02A4 screen_buffer_ptr Long",
      ("screen_buffer_ptr", "Long") in scalar_dims)
check("#1 f01FC max_subfile_size Long",
      ("max_subfile_size", "Long") in scalar_dims)
check("#1 no stack- Dim leaked to module block",
      not re.search(r"^Dim stack-", code, re.M))

# ---- #6: local Dims completeness & minimality -----------------------------
procs = re.split(r"^(?=^(?:Sub|Function) )", code, flags=re.M)
missing = []
extra = []
for chunk in procs[1:]:
    hdr = re.match(r"(?:Sub|Function) (\S+)", chunk)
    if not hdr:
        continue
    hdr_line = chunk.splitlines()[0]
    body = chunk[len(hdr_line):]
    dimmed = set(re.findall(r"^\s{4}Dim (\S+?)(?: As \S.+)?$", body, re.M))
    used = set()
    for line in body.splitlines():
        if line.strip().startswith("Dim "):
            continue
        for m in re.finditer(r"\bstack-(\d+)\b", line):
            used.add("stack-" + m.group(1))
    for u in sorted(used):
        if u not in dimmed:
            missing.append((hdr.group(1), u))
    for d in dimmed:
        base = d.split()[0]
        if base not in body[len("\n    Dim " + d):]:
            extra.append((hdr.group(1), d))
check("#6 every rendered stack-N has a Dim", not missing, str(missing[:8]))
check("#6 no Dim for unrendered slots", not extra, str(extra[:8]))
bare_dims = re.findall(r"^\s{4}Dim (stack-\d+)$", code, re.M)
print("     bare (Variant) local Dims: %d" % len(bare_dims))

print()
print("RESULT: %s" % ("ALL PASS" if fail == 0 else "%d FAILURES" % fail))
sys.exit(1 if fail else 0)
