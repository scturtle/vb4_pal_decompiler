"""Declare-table call signatures (argument counts).

The VB4 Declare table does not record a parameter count that the p-code
disassembler can read directly, so external calls had no known arity and
``_collect_args(None)`` drained the whole evaluation stack.  When a nested
sub/function result was still on the stack (a discarded Sub return), that
leftover was consumed as a spurious extra argument.

The authoritative count is the trailing ``ret N`` of the target export, i.e.
``N // 4`` stdcall parameters.  This table was generated from ``Pal.dll``'s
export table (every Declare-table entry whose name matches a Pal.dll export)
and is keyed by the fully-qualified ``"Lib.Func"`` name used in the disasm.

Regenerate with::

    uv run scripts/gen_declare_specs.py Pal.dll input/PAL.EXE

Only entries whose name is an export of the PAL library are listed; the
kernel32/user32/winmm Win32 APIs are covered by ``stack_ir.WIN32_SPECS``.
"""

DECLARE_SPECS = {
    "Pal.GetKeyDefine": 1,
    "user32.StopApp": 1,
    "Pal.cvlong": 1,
    "Pal.PlayAvi": 3,
    "Pal.CKey": 1,
    "Pal.ReadKey": 1,
    "Pal.ShutDownInput": 0,
    "Pal.InitCD": 0,
    "Pal.InitInput": 2,
    "Pal.delay1": 1,
    "Pal.wtime": 1,
    "Pal.killtimer": 0,
    "Pal.settimer": 0,
    "Pal.DrawString": 6,
    "Pal.rngput": 1,
    "Pal.popscr6a": 3,
    "Pal.popscr6": 2,
    "Pal.adpic": 4,
    "Pal.adpic0": 4,
    "Pal.rblk": 5,
    "Pal.rripafreeze": 0,
    "Pal.rripa": 3,
    "Pal.nipwseg": 1,
    "Pal.nipwb": 3,
    "Pal.nipwa": 3,
    "Pal.putipna": 6,
    "Pal.clripna": 7,
    "Pal.extf": 3,
    "Pal.rhrff": 1,
    "Pal.vmap": 6,
    "Pal.exmyll": 1,
    "Pal.cleartre": 0,
    "Pal.ntre": 2,
    "Pal.addtre": 4,
    "Pal.ffxy": 4,
    "Pal.exmap": 5,
    "Pal.exbb": 6,
    "Pal.exrij": 3,
    "Pal.exgm2": 6,
    "Pal.exgm1": 4,
    "Pal.exgop": 6,
    "Pal.corpate": 2,
    "Pal.fupate": 3,
    "Pal.cvpate": 2,
    "Pal.expate": 4,
    "Pal.intpate": 1,
    "Pal.getbin": 3,
    "Pal.pushscr": 1,
    "Pal.popscr": 1,
    "Pal.popscrb": 2,
    "Pal.putp": 6,
    "Pal.vwindow": 4,
    "Pal.arrayptr": 1,
    "Pal.clsmen": 2,
    "Pal.copymen": 3,
    "Pal.paksize": 1,
    "Pal.unpak": 2,
    "Pal.FlushDSound": 0,
    "Pal.PlayDSound": 2,
    "Pal.LoadDSound": 2,
    "Pal.ShutdownDSound": 0,
    "Pal.InitDSound": 1,
    "Pal.ClrScr": 0,
    "Pal.ResetMode": 0,
    "user32.SetMode": 1,
}
