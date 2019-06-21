import shutil, re, os, ConfigParser

import ida_hexrays
import ida_idaapi
import ida_kernwin as kw
import ida_lines as il
import ida_diskio

__author__ = "Dennis Elser"

XRAY_FILTER_AID = "xray:filter"
XRAY_LOADCFG_AID = "xray:loadcfg"
PATTERN_LIST = []
BGCOLOR = 0x000000
DOFILTER = False
PLUGIN_NAME = "xray"
CFG_FILENAME = "%s.cfg" % PLUGIN_NAME
DEFAULT_CFG = """[ui]
bgcolor=030303
[regex]
r1=strcpy
r2=malloc
r3=realloc
r4=free
r5=recv
r6=memcpy
r7=memmove
r8=sscanf.*,.*%s.*,
r9=^while
"""

# -----------------------------------------------------------------------------
def is_plugin():
    """returns True if this script is executed from within an IDA plugins
    directory, False otherwise."""
    return "__plugins__" in __name__

# -----------------------------------------------------------------------------
def get_target_filename():
    """returns destination path for plugin installation."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "plugins",
        "%s%s" % (PLUGIN_NAME, ".py"))

# -----------------------------------------------------------------------------
def is_installed():
    """checks whether script is present in designated plugins directory."""
    return os.path.isfile(get_target_filename())

# -----------------------------------------------------------------------------
def get_cfg_filename():
    """returns destination path."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "plugins",
        "%s" % CFG_FILENAME)

# -----------------------------------------------------------------------------
def is_ida_version(requested):
    """Checks minimum required IDA version."""
    rv = requested.split(".")
    kv = kw.get_kernel_version().split(".")

    count = min(len(rv), len(kv))
    if not count:
        return False

    for i in xrange(count):
        if int(kv[i]) < int(rv[i]):
            return False
    return True

# -----------------------------------------------------------------------------
def is_compatible():
    """Checks whether script is compatible with current IDA and
    decompiler versions."""
    min_ida_ver = "7.2"
    return is_ida_version(min_ida_ver) and ida_hexrays.init_hexrays_plugin()

# -----------------------------------------------------------------------------
SELF = __file__
def install_plugin():
    """Installs script to IDA userdir as a plugin."""
    dst = get_target_filename()
    src = SELF
    if is_installed():
        btnid = kw.ask_yn(kw.ASKBTN_NO,
            "File exists:\n\n%s\n\nReplace?" % dst)
        if btnid is not kw.ASKBTN_YES:
            return False
    else:
        btnid = kw.ask_yn(kw.ASKBTN_NO,
            "This plugin is about to be installed to:\n\n%s\n\nInstall now?" % dst)
        if btnid is not kw.ASKBTN_YES:
            return False

    usrdir = os.path.dirname(dst)
    kw.msg("Copying script from \"%s\" to \"%s\" ..." % (src, usrdir))
    if not os.path.exists(usrdir):
        try:
            os.path.makedirs(usrdir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                kw.msg("failed (mkdir)!\n")
                return False
    try:
        shutil.copy(src, dst)
    except:
        kw.msg("failed (copy)!\n")
        return False
    kw.msg(("done\n"
        "Plugin installed - please restart this instance of IDA.\n"))
    return True

# -----------------------------------------------------------------------------
def swapcol(x):
    """converts between RRGGBB and BBGGRR color encodings."""
    return (((x & 0x000000FF) << 16) |
             (x & 0x0000FF00) |
            ((x & 0x00FF0000) >> 16))

# -----------------------------------------------------------------------------
def load_cfg():
    """loads xray configuration from file or creates default config
    if none is present."""
    global PATTERN_LIST
    global BGCOLOR

    cfg_file = get_cfg_filename()
    kw.msg("%s: loading %s... " % (PLUGIN_NAME, cfg_file))
    if not os.path.isfile(cfg_file):
        kw.msg("failed!\n" 
            "> file does not exist: %s\n"
            "> creating default config... " % cfg_file)
        try:
            with open(cfg_file, "w") as f:
                f.write(DEFAULT_CFG)
                kw.msg("success!\n")
        except:
            kw.msg("failed!\n")
            return False
        return load_cfg()

    PATTERN_LIST = []

    # TODO: error-handling
    config = ConfigParser.ConfigParser()
    config.read(cfg_file)

    # read all regex expressions
    for _, v in config.items("regex"):
        PATTERN_LIST.append(v)

    # read bg color
    BGCOLOR = swapcol(int(config.get("ui", "bgcolor"), 16))

    if not len(PATTERN_LIST):
        kw.warning("Config file does not contain any regular expressions.")
    kw.msg("success!\n")
    return True

# -----------------------------------------------------------------------------
def remove_color_tags(l):
    """removes all color tags from a tagged simple_line_t object
    but COLOR_ADDR tags."""
    line = ""
    i = 0
    while i<len(l):
        if l[i] is il.COLOR_ON:
            n = il.tag_skipcode(l[i:])
            if l[i:].find(chr(il.COLOR_ADDR)) == 1:
                line += l[i:i+n]
            i += n
        elif l[i] in [il.COLOR_OFF, il.COLOR_ESC, il.COLOR_INV]:
            n = il.tag_skipcode(l[i:])
            i += n
        else:
            line += l[i]
            i += 1
    return line

# -----------------------------------------------------------------------------
class xray_hooks_t(ida_hexrays.Hexrays_Hooks):
    """class for handling decompiler events."""
    def _search(self, pattern, sl):
        line = il.tag_remove(sl.line).lstrip().rstrip()
        return re.search(pattern, line) is not None

    def _apply_xray_filter(self, cfunc):
        if DOFILTER and cfunc:
            pc = cfunc.get_pseudocode()

            #col = il.calc_bg_color(ida_idaapi.get_inf_structure().min_ea)
            #col = pc[0].bgcolor
            col = BGCOLOR
            for sl in pc:
                if any(self._search(pattern, sl) for pattern in PATTERN_LIST):
                    #sl.bgcolor = (col & 0xfefefe) >> 1
                    sl.bgcolor = col
                else:
                    sl.line = remove_color_tags(sl.line)

    def _build_hint(self, vu):
        if vu.refresh_cpos(ida_hexrays.USE_MOUSE):
            sl = vu.cfunc.get_pseudocode()[vu.cpos.lnnum]
            hint_lines = ["%s pattern(s):" % PLUGIN_NAME]
            delim_s = "%s" % "="*len(hint_lines[0])
            delim_e = "\n%s\n" % ("-"*len(hint_lines[0]))
            hint_lines.append(delim_s)
            hint = ""
            hint_created = False
            for pattern in PATTERN_LIST:
                if self._search(pattern, sl):
                    hint_lines.append("> \"%s\"" % pattern)
                    hint_created = True
            hint_lines.append(delim_e)
            hint = "\n".join(hint_lines)
            if hint_created:
                return (hint, len(hint_lines)+1)
        return None

    def text_ready(self, vu):
        self._apply_xray_filter(vu.cfunc)
        return 0

    def populating_popup(self, widget, phandle, vu):
        kw.attach_action_to_popup(vu.ct, None, XRAY_FILTER_AID)
        return 0

    def create_hint(self, vu):
        result = self._build_hint(vu)
        if result:
            hint, count = result
            return (2, hint, count)
        return (0, None)

# -----------------------------------------------------------------------------
class xray_action_handler_t(kw.action_handler_t):
    """action handler for turning xray on and off."""
    def __init__(self):
        kw.action_handler_t.__init__(self)

    def activate(self, ctx):
        global DOFILTER
        DOFILTER = not DOFILTER
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            vu.refresh_ctext()
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == kw.BWN_PSEUDOCODE else \
            kw.AST_DISABLE_FOR_WIDGET

# -----------------------------------------------------------------------------
class loadcfg_action_handler_t(kw.action_handler_t):
    """action handler for reloading xray cfg file."""
    def __init__(self):
        kw.action_handler_t.__init__(self)

    def activate(self, ctx):
        if load_cfg():
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu:
                vu.refresh_ctext()         
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == kw.BWN_PSEUDOCODE else \
            kw.AST_DISABLE_FOR_WIDGET

# -----------------------------------------------------------------------------
class xray_plugin_t(ida_idaapi.plugin_t):
    """plugin class."""
    flags = ida_idaapi.PLUGIN_HIDE
    comment = PLUGIN_NAME
    help = PLUGIN_NAME
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.xray_hooks = None
        if is_compatible():
            load_cfg()

            kw.register_action(
                kw.action_desc_t(
                    XRAY_LOADCFG_AID,
                    "%s: reload config" % PLUGIN_NAME,
                    loadcfg_action_handler_t(),
                    "Ctrl-r"))

            kw.register_action(
                kw.action_desc_t(
                    XRAY_FILTER_AID,
                    "%s: toggle" % PLUGIN_NAME,
                    xray_action_handler_t(),
                    "F3"))

            self.xray_hooks = xray_hooks_t()
            self.xray_hooks.hook()
            return ida_idaapi.PLUGIN_KEEP
        
        return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        return

    def term(self):
        if self.xray_hooks:
            self.xray_hooks.unhook()
            kw.unregister_action(XRAY_FILTER_AID)
            kw.unregister_action(XRAY_LOADCFG_AID)
        return

# -----------------------------------------------------------------------------
def PLUGIN_ENTRY():
    """plugin entry point."""
    return xray_plugin_t()

# -----------------------------------------------------------------------------
def SCRIPT_ENTRY():
    """script entry point."""
    if not is_plugin():
        (kw.info("Success!") if install_plugin() else
            kw.warning("Error! Plugin could not be installed!"))
    return

# -----------------------------------------------------------------------------
SCRIPT_ENTRY()