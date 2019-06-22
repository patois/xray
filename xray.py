import shutil, re, os, ConfigParser

import ida_hexrays
import ida_idaapi
import ida_kernwin as kw
import ida_lines as il
import ida_diskio

__author__ = "Dennis Elser"

PLUGIN_NAME = "xray"

XRAY_FILTER_ACTION_ID = "%s:filter" % PLUGIN_NAME
XRAY_LOADCFG_ACTION_ID = "%s:loadcfg" % PLUGIN_NAME

PATTERN_LIST = []
HIGH_CONTRAST = False

DO_FILTER = False

CFG_FILENAME = "%s.cfg" % PLUGIN_NAME
DEFAULT_CFG = """# configuration file for xray.py

[global]
# set to 1 for better contrast
high_contrast=0
# changing this setting to 1 enables
# xray by default 
auto_enable=0

# each group contains a list of regular
# expressions and a background color in
# RRGGBB format. priority is determined
# by order of appearance, first group
# gets assigned lowest priority.
# check out https://regex101.com/r

[group_01]
expr_01=^while\(
expr_02=^for\(
bgcolor=4c0037
hint=loop

[group_02]
expr_01=recv\(
expr_02=malloc\(
expr_03=realloc\(
expr_04=free\(
expr_05=memcpy\(
expr_06=memmove\(
expr_07=strcpy\(
expr_08=sscanf\(
expr_09=sprintf\(
expr_10=recvfrom\(
bgcolor=00374c
hint=function name

[group_03]
expr_01=sscanf\(.*,.*%%s.*,.*\)
expr_02=sprintf\(.*,.*%%s.*,.*\)
bgcolor=4c1500
hint=format strings

[group_04]
expr_01=malloc\(.*[\*\+\-\/%%][^>].*\)
expr_02=realloc\(([^,]+,){1}.*[\*\+\-\/%%][^>,].*\)
expr_03=memcpy\(([^,]+,){2}(.*[^,][\+\-\*\/%%][^>].*,)
expr_04=memmove\(([^,]+,){2}(.*[^,][\+\-\*\/%%][^>].*,)
expr_05=recv\(([^,]+,){2}(.*[^,][\+\-\*\/%%][^>].*,)
expr_06=recvfrom\(([^,]+,){2}(.*[^,][\+\-\*\/%%][^>].*,)
bgcolor=4c1500
hint=arithmetic"""

# -----------------------------------------------------------------------------
def is_plugin():
    """returns True if this script is executed from within an IDA plugins
    directory, False otherwise."""
    return "__plugins__" in __name__

# -----------------------------------------------------------------------------
def get_dest_filename():
    """returns destination path for plugin installation."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "plugins",
        "%s%s" % (PLUGIN_NAME, ".py"))

# -----------------------------------------------------------------------------
def is_installed():
    """checks whether script is present in designated plugins directory."""
    return os.path.isfile(get_dest_filename())

# -----------------------------------------------------------------------------
def get_cfg_filename():
    """returns full path for config file."""
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
    dst = get_dest_filename()
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
    kw.msg("%s: copying script from \"%s\" to \"%s\" ..." % (PLUGIN_NAME, src, usrdir))
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
def load_cfg(reload=False):
    """loads xray configuration from file. Creates and loads default config
    if none is present."""
    global PATTERN_LIST
    global HIGH_CONTRAST
    global DO_FILTER

    cfg_file = get_cfg_filename()
    kw.msg("%s: %sloading %s...\n" % (PLUGIN_NAME,
        "re" if reload else "",
        cfg_file))
    if not os.path.isfile(cfg_file):
        kw.msg("%s: %s does not exist! creating default config... " % (PLUGIN_NAME, cfg_file))
        try:
            with open(cfg_file, "w") as f:
                f.write(DEFAULT_CFG)
                kw.msg("success!\n")
        except:
            kw.msg("failed!\n")
            return False
        return load_cfg(reload=True)

    PATTERN_LIST = []

    config = ConfigParser.SafeConfigParser()
    config.readfp(open(cfg_file))

    # read all sections
    for section in config.sections():
        expr_list = []
        if section.startswith("group_"):
            for k,v in config.items(section):
                if k.startswith("expr_"):
                    expr_list.append(v)
            try:
                bgcolor = swapcol(int(config.get(section, "bgcolor"), 16))
            except:
                bgcolor = swapcol(0x000000)
            try:
                hint = config.get(section, "hint")
            except:
                hint = None
            PATTERN_LIST.append(RegexGroup(expr_list, bgcolor, hint))
        elif section == "global":
            try:
                HIGH_CONTRAST = config.getboolean(section, "high_contrast")
            except:
                HIGH_CONTRAST = False
            if not reload:
                try:
                    DO_FILTER = config.getboolean(section, "auto_enable")
                except:
                    DO_FILTER = False


    if not len(PATTERN_LIST):
        kw.warning("Config file does not contain any regular expressions.")
    return True

# -----------------------------------------------------------------------------
class RegexGroup():
    """class that represents a config file's "group" section."""
    def __init__(self, expr_list, bgcolor, hint):
        self.expr_list = expr_list
        self.bgcolor = bgcolor
        self.hint = hint

# -----------------------------------------------------------------------------
class xray_hooks_t(ida_hexrays.Hexrays_Hooks):
    """class for handling decompiler events."""

    def _remove_color_tags(self, l):
        """removes all color tags from a tagged simple_line_t object
        but preserves COLOR_ADDR tags."""
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

    def _search(self, regexp, sl):
        line = il.tag_remove(sl.line).lstrip().rstrip()
        return re.search(regexp, line) is not None

    def _apply_xray_filter(self, cfunc):
        if DO_FILTER and cfunc:
            pc = cfunc.get_pseudocode()

            #col = il.calc_bg_color(ida_idaapi.get_inf_structure().min_ea)
            #col = pc[0].bgcolor
            for sl in pc:
                match=False
                for group in PATTERN_LIST:
                    for expr in group.expr_list:
                        if self._search(expr, sl):
                            #sl.bgcolor = (col & 0xfefefe) >> 1
                            sl.bgcolor = group.bgcolor
                            match=True
                            break
                if not match and HIGH_CONTRAST:
                    sl.line = self._remove_color_tags(sl.line)
        return

    def _build_hint(self, vu):
        if vu.refresh_cpos(ida_hexrays.USE_MOUSE):
            sl = vu.cfunc.get_pseudocode()[vu.cpos.lnnum]
            hint_lines = ["%s pattern(s):" % PLUGIN_NAME]
            delim_s = "%s" % "="*len(hint_lines[0])
            delim_e = "\n%s\n" % ("-"*len(hint_lines[0]))
            hint_lines.append(delim_s)
            hint = ""
            hint_created = False
            for group in PATTERN_LIST:
                for expr in group.expr_list:
                    if self._search(expr, sl):
                        tmp = (" (%s)" % group.hint) if group.hint else ""
                        hint_lines.append("> \"%s\"%s" % (expr, tmp))
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
        kw.attach_action_to_popup(vu.ct, None, XRAY_FILTER_ACTION_ID)
        kw.attach_action_to_popup(vu.ct, None, XRAY_LOADCFG_ACTION_ID)
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
        global DO_FILTER
        DO_FILTER = not DO_FILTER
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
        if load_cfg(reload=True):
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
                    XRAY_LOADCFG_ACTION_ID,
                    "%s: reload config" % PLUGIN_NAME,
                    loadcfg_action_handler_t(),
                    "Ctrl-R"))

            kw.register_action(
                kw.action_desc_t(
                    XRAY_FILTER_ACTION_ID,
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
            kw.unregister_action(XRAY_FILTER_ACTION_ID)
            kw.unregister_action(XRAY_LOADCFG_ACTION_ID)
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