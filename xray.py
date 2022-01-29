import shutil, re, os, configparser, errno
from PyQt5.QtWidgets import QWidget, QSplitter

import ida_hexrays
import ida_idaapi
import ida_kernwin as kw
import ida_lines as il
import ida_diskio
from ida_pro import IDA_SDK_VERSION

__author__ = "Dennis Elser"

PLUGIN_NAME = "xray"

XRAY_FILTER_ACTION_ID = "%s:filter" % PLUGIN_NAME
XRAY_LOADCFG_ACTION_ID = "%s:loadcfg" % PLUGIN_NAME
XRAY_QUERY_ACTION_ID = "%s:query" % PLUGIN_NAME
PATTERN_LIST = []
HIGH_CONTRAST = False

IS_ACTIVATED = False
TEXT_INPUT_FORMS = {}

CFG_FILENAME = "%s.cfg" % PLUGIN_NAME
DEFAULT_CFG = """# configuration file for xray.py

[global]
# set to 1 for better contrast
high_contrast=0
# enable/disable xray when loading a database 
auto_enable=0

# each group contains a list of regular
# expressions, a background color in
# RRGGBB format and an optional hint field.
# priority is determined by order of
# appearance, first group gets assigned
# lowest priority.
# check out https://regex101.com/r and
# https://www.debuggex.com/

[group_01]
hint=loop
bgcolor=4c0037

expr_01=^while\(
expr_02=^for\(

[group_02]
hint=function name
bgcolor=00374c

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

[group_03]
hint=format strings
bgcolor=4c1500

expr_01=sscanf\(.*,.*%s.*,.*\)
expr_02=sprintf\(.*,.*%s.*,.*\)

[group_04]
hint=arithmetic
bgcolor=4c1500

expr_01=malloc\(.*[\*\+\-\/%][^>].*?\)
expr_02=realloc\(([^,]+,){1}(.*[^,][\+\-\*\/%][^>].*[^,])
expr_03=memcpy\(([^,]+,){2}(.*[^,][\+\-\*\/%][^>].*[^,])
expr_04=memmove\(([^,]+,){2}(.*[^,][\+\-\*\/%][^>].*[^,])
expr_05=recv\(([^,]+,){2}(.*[^,][\+\-\*\/%][^>].*[^,])
expr_06=recvfrom\(([^,]+,){2}(.*[^,][\+\-\*\/%][^>].*[^,])"""

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

# -----------------------------------------------------------------------
def is_ida_version(min_ver_required):
    return IDA_SDK_VERSION >= min_ver_required

# -----------------------------------------------------------------------------
def is_compatible():
    """Checks whether script is compatible with current IDA and
    decompiler versions."""
    min_ida_ver = 720
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
            os.makedirs(usrdir)
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
    global IS_ACTIVATED

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

    config = configparser.RawConfigParser()
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
            PATTERN_LIST.append(ConfigGroupSection(expr_list, bgcolor, hint))
        elif section == "global":
            try:
                HIGH_CONTRAST = config.getboolean(section, "high_contrast")
            except:
                HIGH_CONTRAST = False
            if not reload:
                try:
                    IS_ACTIVATED = config.getboolean(section, "auto_enable")
                except:
                    IS_ACTIVATED = False

    if not len(PATTERN_LIST):
        kw.warning("Config file does not contain any regular expressions.")
    return True

# -----------------------------------------------------------------------------
class TextInputForm(kw.Form):
    """Input form for regex search queries."""

    # flags
    SO_FIND_TEXT = 1
    SO_FIND_REGEX = 2
    SO_FILTER_TEXT = 4
    SO_FILTER_COLOR = 8
    SO_FIND_CASE = 16

    def __init__(self, parent_widget):
        self.parent_widget = parent_widget
        self.parent_title = kw.get_widget_title(self.parent_widget)
        i=1
        while kw.find_widget("%s-%d" % (PLUGIN_NAME, i)):
            i+=1
        self.idx = i
        __title = "%s-%s" % (PLUGIN_NAME, self.idx)
        self.options = (TEXT_INPUT_FORMS[self.parent_title].options
            if self.parent_title in TEXT_INPUT_FORMS.keys()
            else TextInputForm.SO_FILTER_TEXT | TextInputForm.SO_FIND_TEXT)
        self.query = (TEXT_INPUT_FORMS[self.parent_title].query
            if self.parent_title in TEXT_INPUT_FORMS.keys()
            else "")
        kw.Form.__init__(self,
("BUTTON YES NONE\n"
"BUTTON NO NONE\n"
"BUTTON CANCEL NONE\n"
"%s\n\n"
"{FormChangeCb}\n"
"<##Enter text##Filter:{cbEditable}>"
"|<##Search##Text:{rText}><Regex:{rRegex}>{cSearchMethod}>"
"|<##Filter##Lines:{rFilterLines}><Colors:{rFilterColors}>{cFilterType}>"
"|<##Options##Case sensitive:{rCase}>{cOptions}>\n") % (__title), {
    'FormChangeCb': kw.Form.FormChangeCb(self.OnFormChange),
    'cbEditable': kw.Form.StringInput(value = self.query),
    'cSearchMethod': kw.Form.RadGroupControl(("rText", "rRegex")),
    'cFilterType': kw.Form.RadGroupControl(("rFilterLines", "rFilterColors")),
    'cOptions': kw.Form.ChkGroupControl(("rCase",))})

    def init_controls(self):
        self.SetControlValue(self.cbEditable, self.query)
        self.SetControlValue(self.cSearchMethod, 0 if self.options & TextInputForm.SO_FIND_TEXT else 1)
        self.SetControlValue(self.cFilterType, 0 if self.options & TextInputForm.SO_FILTER_TEXT else 1)
        self.SetControlValue(self.cOptions, 1 if self.options & TextInputForm.SO_FIND_CASE else 0)
        self.SetFocusedField(self.cbEditable)
        return

    def _commit_changes(self):
        vu = ida_hexrays.get_widget_vdui(self.parent_widget)
        if vu:
            vu.refresh_ctext()
            # "refresh_ctext()" took away the focus, take it back
            kw.activate_widget(kw.find_widget(self.title), True)
            self.SetFocusedField(self.cbEditable)
            return True
        return False

    def OnFormChange(self, fid):
        if fid == self.cbEditable.id:
            self.query = self.GetControlValue(self.cbEditable)
        elif fid == self.rCase.id:
            if self.GetControlValue(self.cOptions):
                self.options |= TextInputForm.SO_FIND_CASE
            else:
                self.options &= ~TextInputForm.SO_FIND_CASE & 0xFFFFFFFF
        elif fid in [self.rFilterLines.id, self.rFilterColors.id]:
            filter_text = fid == self.rFilterLines.id
            filter_color = fid == self.rFilterColors.id

            if filter_text:
                self.options |= TextInputForm.SO_FILTER_TEXT
            else:
                self.options &= ~TextInputForm.SO_FILTER_TEXT & 0xFFFFFFFF

            if filter_color:
                self.options |= TextInputForm.SO_FILTER_COLOR
            else:
                self.options &= ~TextInputForm.SO_FILTER_COLOR & 0xFFFFFFFF
        elif fid in [self.rText.id, self.rRegex.id]:
            find_text = fid == self.rText.id
            find_regex = fid == self.rRegex.id

            if find_text:
                self.options |= TextInputForm.SO_FIND_TEXT
            else:
                self.options &= ~TextInputForm.SO_FIND_TEXT & 0xFFFFFFFF

            if find_regex:
                self.options |= TextInputForm.SO_FIND_REGEX
            else:
                self.options &= ~TextInputForm.SO_FIND_REGEX & 0xFFFFFFFF
        
        self._commit_changes()
        return 1

# -----------------------------------------------------------------------------
class ConfigGroupSection():
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

    def _search(self, regexp, sl, case_sensitive = False):
        line = il.tag_remove(sl.line).lstrip().rstrip()
        return re.search(regexp, line, flags=re.I if not case_sensitive else 0) is not None

    def _apply_xray_filter(self, vu, pc):
        if IS_ACTIVATED and pc:
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

    def _apply_query_filter(self, vu, pc):
        new_pc = []
        title = kw.get_widget_title(vu.ct)
        if title in TEXT_INPUT_FORMS.keys() and pc:
            sq = TEXT_INPUT_FORMS[title]
            query = sq.query
            options = sq.options
            case_sensitive = options & TextInputForm.SO_FIND_CASE

            # TODO
            if options & TextInputForm.SO_FIND_TEXT:
                kw.set_highlight(vu.ct, query, HL_FLAGS)
                tmpquery = query.lower() if not case_sensitive else query
                for sl in pc:
                    haystack = il.tag_remove(sl.line).lstrip().rstrip()
                    haystack = haystack.lower() if not case_sensitive else haystack
                    if tmpquery in haystack:
                        new_pc.append(sl.line)
                    else:
                        if options & TextInputForm.SO_FILTER_COLOR:
                            # add line but remove color
                            new_pc.append(self._remove_color_tags(sl.line))
                        elif options & TextInputForm.SO_FILTER_TEXT:
                            # do not add non-matching text
                            pass
            elif options & TextInputForm.SO_FIND_REGEX:
                kw.set_highlight(vu.ct, None, 0)
                for sl in pc:
                    try:
                        if self._search(query, sl, case_sensitive):
                            new_pc.append(sl.line)
                        else:
                            if options & TextInputForm.SO_FILTER_COLOR:
                                new_pc.append(self._remove_color_tags(sl.line))
                            elif options & TextInputForm.SO_FILTER_TEXT:
                                # do not add non-matching text
                                pass
                    except re.error as error:
                        kw.msg("%s: %s: \"%s\"" %
                            (PLUGIN_NAME, error, query))
                        return
            pc.clear()
            sl = kw.simpleline_t()
            for line in new_pc:
                sl.line = line
                pc.push_back(sl)
        return

    def _build_hint(self, vu):
        if IS_ACTIVATED and vu.refresh_cpos(ida_hexrays.USE_MOUSE):
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
        pc = vu.cfunc.get_pseudocode()
        self._apply_query_filter(vu, pc)
        self._apply_xray_filter(vu, pc)
        return 0

    def populating_popup(self, widget, phandle, vu):
        kw.attach_action_to_popup(vu.ct, None, XRAY_FILTER_ACTION_ID, PLUGIN_NAME+"/")
        kw.attach_action_to_popup(vu.ct, None, XRAY_LOADCFG_ACTION_ID, PLUGIN_NAME+"/")
        kw.attach_action_to_popup(vu.ct, None, XRAY_QUERY_ACTION_ID, PLUGIN_NAME+"/")
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
        global IS_ACTIVATED
        IS_ACTIVATED = not IS_ACTIVATED
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            vu.refresh_ctext()
        kw.msg("[%s] %sactivated.\n" % (PLUGIN_NAME, "" if IS_ACTIVATED else "de"))
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
class regexfilter_action_handler_t(kw.action_handler_t):
    """action handler for search queries."""
    def __init__(self):
        kw.action_handler_t.__init__(self)

    # TODO
    def _dirty_resize_hack(self, w, form):
        title = form.title
        widget = kw.find_widget(title)
        if not widget:
            return

        w1 = kw.PluginForm.TWidgetToPyQtWidget(widget)
        w2 = kw.PluginForm.TWidgetToPyQtWidget(w)
        if not w1 or not w2:
            return

        p1 = w1.parentWidget()
        p2 = w2.parentWidget()
        if not p1 or not p2:
            return

        splitter = p1.parentWidget()
        hr = p2.parentWidget()
        if not splitter or not hr:
            return

        if not type(splitter) is QSplitter or not type(hr) is QWidget:
            return

        sizes = splitter.sizes()
        if len(sizes) != 2:
            return

        idx = splitter.indexOf(p1)
        _min, _max = splitter.getRange(idx)
        sizes[idx] = _min

        idx = splitter.indexOf(hr)
        _min, _max = splitter.getRange(idx)
        sizes[idx] = _max

        splitter.setSizes(sizes)
        return

    def _open_search_form(self, widget):
        global TEXT_INPUT_FORMS

        title = kw.get_widget_title(widget)
        if title not in TEXT_INPUT_FORMS.keys():
            search_form = TextInputForm(widget)
            search_form.modal = False
            search_form.openform_flags = (kw.PluginForm.WOPN_DP_BOTTOM |
                kw.PluginForm.WOPN_PERSIST)
            search_form, _ = search_form.Compile()
            search_form.Open()
            TEXT_INPUT_FORMS[title] = search_form
            self._dirty_resize_hack(widget, search_form)
        else:
            search_form = TEXT_INPUT_FORMS[title]
            search_form.Open()
            search_form.init_controls()
            self._dirty_resize_hack(widget, search_form)
        return

    def activate(self, ctx):
        self._open_search_form(ctx.widget)
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
        if not is_compatible():
            kw.msg("%s: decompiler not available, skipping." % PLUGIN_NAME)
            return ida_idaapi.PLUGIN_SKIP

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

        kw.register_action(
            kw.action_desc_t(
                XRAY_QUERY_ACTION_ID,
                "%s: search" % PLUGIN_NAME,
                regexfilter_action_handler_t(),
                "Ctrl-F"))

        self.xray_hooks = xray_hooks_t()
        self.xray_hooks.hook()
        kw.msg("[%s] F3: toggle xray, Ctrl-F: filter, Ctrl-R: reload config." % PLUGIN_NAME)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        return

    def term(self):
        if self.xray_hooks:
            self.xray_hooks.unhook()
            kw.unregister_action(XRAY_FILTER_ACTION_ID)
            kw.unregister_action(XRAY_LOADCFG_ACTION_ID)
            kw.unregister_action(XRAY_QUERY_ACTION_ID)
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
HL_FLAGS = kw.HIF_LOCKED | kw.HIF_NOCASE if is_ida_version(740) else kw.HIF_LOCKED
SCRIPT_ENTRY()
