"""VB4 header + GUI table + ProjectInfo2 parsing (port of modVB4.bas).

Layout notes (modVB4.bas VB4HEADERType), all offsets relative to the header:
  +0x00 sig              Long  (0xB6543581 observed; Semi expects 0xB4543581)
  +0x04 CompilerFileVersion Integer
  +0x06 .. +0x23         15x Integer (int1..int15)
  +0x24 LangID           Integer  (0x0409)
  +0x26 .. +0x2B         3x Integer (int16..int18)
  +0x2C aSubMain         Long
  +0x30 Address2         Long
  +0x34 .. +0x3F         6x Integer (i1..i6)
  +0x40 iExeNameLength   Integer
  +0x42 iProjectSavedNameLength Integer
  +0x44 iHelpFileLength  Integer
  +0x46 iProjectNameLength Integer
  +0x48 FormCount        Integer
  +0x4A int19            Integer
  +0x4C NumberOfExternalComponets Integer
  +0x4E int20            Integer  (176d)
  +0x50 aGuiTable        Long
  +0x54 Address4         Long
  +0x58 aExternalComponetTable Long
  +0x5C aProjectInfo2    Long

The header is followed by four null-terminated strings (gated by the length
fields): ExeName, SavedProjectName, HelpFile, ProjectTitle.
"""
import struct


class VB4Header:
    def __init__(self, pe, va):
        self.pe = pe
        self.va = va
        b = pe.bytes_at
        self.sig = pe.r32(va)
        self.compiler_file_version = pe.r16(va + 0x04)
        self.lang_id = pe.r16(va + 0x24)
        self.a_sub_main = pe.r32(va + 0x2C)
        self.address2 = pe.r32(va + 0x30)
        self.i_exe_name_len = pe.r16(va + 0x40)
        self.i_saved_name_len = pe.r16(va + 0x42)
        self.i_help_file_len = pe.r16(va + 0x44)
        self.i_project_name_len = pe.r16(va + 0x46)
        self.form_count = pe.r16(va + 0x48)
        self.num_external_components = pe.r16(va + 0x4C)
        self.a_gui_table = pe.r32(va + 0x50)
        self.address4 = pe.r32(va + 0x54)
        self.a_external_component_table = pe.r32(va + 0x58)
        self.a_project_info2 = pe.r32(va + 0x5C)
        self._read_strings()
        self._read_gui_tables()
        self._read_project_info2()

    def _read_until_null(self, va):
        return self.pe.cstr(va)

    def _read_strings(self):
        # The four strings immediately follow the 0x60-byte header.
        p = self.va + 0x60
        self.exe_name = ""
        self.saved_project_name = ""
        self.help_file = ""
        self.project_title = ""
        if self.i_exe_name_len != 0:
            self.exe_name = self._read_until_null(p)
            p += len(self.exe_name) + 1
        # modVB4 gates SavedProjectName on LangID<>0 (quirk preserved)
        if self.lang_id != 0:
            self.saved_project_name = self._read_until_null(p)
            p += len(self.saved_project_name) + 1
        if self.i_help_file_len != 0:
            self.help_file = self._read_until_null(p)
            p += len(self.help_file) + 1
        if self.i_project_name_len != 0:
            self.project_title = self._read_until_null(p)
            p += len(self.project_title) + 1

    def _read_gui_tables(self):
        """VB4GuiTableType: uuid(16) + bArray(28) + aFormPointer:Long = 48 bytes."""
        self.gui_tables = []
        if self.form_count > 0 and self.a_gui_table:
            for i in range(self.form_count):
                va = self.a_gui_table + i * 48
                a_form_pointer = self.pe.r32(va + 44)
                self.gui_tables.append({
                    "uuid": self.pe.bytes_at(va, 16),
                    "bArray": self.pe.bytes_at(va + 16, 28),
                    "aFormPointer": a_form_pointer,
                })

    def _read_project_info2(self):
        """ProjectInfo2Type: l1,l2,l3:Long oProjectName,oVBPath,oAppDescription:Long guid(16)."""
        self.pi2 = None
        if self.a_project_info2:
            va = self.a_project_info2
            self.pi2 = {
                "l1": self.pe.r32(va),
                "l2": self.pe.r32(va + 4),
                "l3": self.pe.r32(va + 8),
                "oProjectName": self.pe.r32(va + 12),
                "oVBPath": self.pe.r32(va + 16),
                "oAppDescription": self.pe.r32(va + 20),
                "guid": self.pe.bytes_at(va + 24, 16),
            }
            self.pi2_va = va
            self.project_name = ""
            self.vb_path = ""
            self.app_description = ""
            if self.pi2["oProjectName"]:
                self.project_name = self.pe.cstr(va + self.pi2["oProjectName"])
            if self.pi2["oVBPath"]:
                self.vb_path = self.pe.cstr(va + self.pi2["oVBPath"])
            if self.pi2["oAppDescription"]:
                self.app_description = self.pe.cstr(va + self.pi2["oAppDescription"])


def find_header_va(pe):
    """Locate the VB4 header VA from the entry point thunk.

    Entry stub: 68 <lAddress1> E8 <ThunderRTMain>.  Return the pushed VA,
    or None if the entry point is not the expected push-imm32 form.
    """
    ep_va = pe.base + pe.entry_point
    if pe.r8(ep_va) != 0x68:
        return None
    return pe.r32(ep_va + 1)
