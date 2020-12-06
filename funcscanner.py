from idaapi import *
import pickle

__author__       =  "patois"

PLUGIN_NAME       =  "FuncScanner"
FUNC_CHOOSER = None
POPUP_ACTIONS = ["Rescan Database"]

class FunctionExtInfo():
    def __init__(self, ea, xref_count, loop_count, nodes, nodes_total):
        self.ea = ea
        self.xref_count = xref_count
        self.loop_count = loop_count
        self.nodes = nodes
        self.nodes_total = nodes_total

# ----------------------------------------------------------------------------
def get_preds(fc, node, nodeset = None):
    if nodeset is None:
        nodeset = []
    if node not in nodeset:
        nodeset.append(node)
        n = fc.npred(node)
        for i in range(n):
            get_preds(fc, fc.pred(node, i), nodeset)
    return nodeset

# ----------------------------------------------------------------------------
def get_succs(fc, node, nodeset = None):
    if nodeset is None:
        nodeset = []
    if node not in nodeset:
        nodeset.append(node)
        n = fc.nsucc(node)
        for i in range(n):
            get_succs(fc, fc.succ(node, i), nodeset)
    return nodeset

# ----------------------------------------------------------------------------
def ea_to_node(fc, ea):
    nid = None
    for i in range(fc.size()):
        if fc[i].contains(ea) and i < fc.size():
            nid = i
            break
    return nid

# ----------------------------------------------------------------------------
def get_loops(func, subset = None):
    loops = []
    node_count = 0

    if func:
        fc = qflow_chart_t()
        fc.create("", func, BADADDR, BADADDR, FC_NOEXT | FC_PREDS)
        nodes_total = fc.size()

        nids = {}
        s = subset
        if s is None:
            s = range(nodes_total)
        # collect every nid's parent and child nodes
        for nid in s:            
            preds = get_preds(fc, nid)
            succs = get_succs(fc, nid)
            nids[nid] = (preds, succs)

        # find all loops in a function
        for nid in nids:
            # skip nids that are already part of a loop
            #if nid in loop:
            #    continue
            
            loop = set()
            preds, succs = nids[nid]
            
            # detect loop
            for i in range(len(succs)):
                if succs[i] in preds:
                    loop.add(succs[i])

            # remove loops that do not xref themselves (FPs)
            if len(loop) == 1:
                found = False
                for j in range(fc.nsucc(nid)):
                    if nid == fc.succ(nid, j):
                        found = True
                if not found:
                    loop.clear()

            # remove duplicates
            elif len(loop) > 1:
                if sorted(loop) in loops:
                    # TODO: add code to check for nested loops
                    loop.clear()
                    
            if len(loop):
                loops.append(sorted(loop))

    return (loops, nodes_total)

# ----------------------------------------------------------------------------
def set_bb_color(func, nid, color):
    ea = func.start_ea
    p = node_info_t()
    p.frame_color = 0x000000FF
    #p.bg_color = color
    set_node_info(ea, nid, p, NIF_FRAME_COLOR) #NIF_BG_COLOR | NIF_FRAME_COLOR)

# ----------------------------------------------------------------------------
def color_nodes(ea, loops, color=0xD0FFFF):
    func = get_func(ea)
    if func:
        fc = qflow_chart_t()
        fc.create("", func, BADADDR, BADADDR, FC_NOEXT)
        for loop in loops:
            for node in loop:
                set_bb_color(func, node, color)

# ----------------------------------------------------------------------------
def get_xref_count(ea, flags=XREF_ALL):
    count = 0
    xref = xrefblk_t()
    if xref.first_to(ea, flags):
        count += 1
        while xref.next_to():
            count += 1
    return count

# ----------------------------------------------------------------------------
class chooser_handler_t(action_handler_t):
    def __init__(self, action):
        action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == POPUP_ACTIONS[0]:
            if ask_yn(ASKBTN_NO, "Rescanning the database will discard existing results. Are you sure?") == ASKBTN_YES:
                FUNC_CHOOSER.scan_idb()

    def update(self, ctx):
        return AST_ENABLE_FOR_WIDGET if is_chooser_widget(ctx.form_type) else AST_DISABLE_FOR_WIDGET

# ----------------------------------------------------------------------------
class FuncChooser(Choose):
    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose.__init__(
            self,
            title,
            [ ["Function", 25 | CHCOL_FNAME],
              ["Xrefs", 5 | CHCOL_DEC],
              ["Loops", 5 | CHCOL_DEC],
              ["Basic blocks", 6 | CHCOL_DEC] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.func_list = []
        self.items = []
        self.icon = 82
        self.modal = modal
        self.nodeid = 0x504F4F4C # "LOOP"
        self.nodename = "$ loopfinder"
        self.isFinalized = False
        self.savedResults = False

    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n):
        jumpto(self.func_list[n].ea)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnGetIcon(self, n):
        t = self.icon
        return t

    def update_chooser(self):
        self.n = 0
        self.items = [self.make_item() for x in range(len(self.func_list))]
        self.Refresh()
        return self.Show(self.modal) >= 0

    def make_item(self):
        r = [get_func_name(self.func_list[self.n].ea), # func name
             "%8d" % self.func_list[self.n].xref_count, # no of xrefs
             "%8d" % self.func_list[self.n].loop_count, # total no of loops in function
             "%8d" % self.func_list[self.n].nodes_total]# total nodes in func
        self.n += 1
        return r

    def color_loops(self, color=0xd0ffff):
        labelWaitBox = "Coloring loops"
        show_wait_box(labelWaitBox)
        ltotal = len(self.func_list)
        for i in range(ltotal):
            color_nodes(self.func_list[i].ea, self.func_list[i].nodes)
            if user_cancelled():
                break
        hide_wait_box()

    def scan_idb(self):
        finalized = self.scan_functions()
        self.update_chooser()
        if finalized and ask_yn(ASKBTN_NO, "Color all loops?") == ASKBTN_YES:
            self.color_loops()
        return finalized

    def scan_functions(self):
        self.set_finalized(False)
        self.set_saved(False)
        self.func_list = []
        self.items = []
        
        nfuncs = get_func_qty()
        x = nfuncs / 10 if nfuncs >= 10 else nfuncs
        total = 0
        interrupted = False
      
        show_wait_box("Scanning functions")
        for n in range(nfuncs):       
            f = getn_func(n)
            if f is not None:
                show_auto(f.start_ea, AU_CODE)
                bars = (int(round(n/(x), 0)))
                funcname = get_func_name(f.start_ea)
                funcname = funcname if len(funcname) < 20 else funcname[:20] + "..."
                progress = "[%s%s] : %3.2f%%" % (bars*'#', (10-bars)*'=', (float(n)/float(nfuncs))*100.0)
                replace_wait_box("Progress: %s\n\nScanning: %s\nLoops total: %d" % (progress,
                    funcname,
                    total))

                if user_cancelled():
                    interrupted = True
                    break

                loops, nc = get_loops(f)

                count = len(loops)
                total += count
                self.append_func(FunctionExtInfo(f.start_ea, get_xref_count(f.start_ea), count, loops, nc))

        hide_wait_box()
        self.set_finalized(not interrupted)
        return self.is_finalized()
        
    def append_func(self, lf):
        self.func_list.append(lf)

    def load_from_idb(self):
        node = netnode(self.nodeid)
        node.create(self.nodename)
        result = node.getblob(0, "L")
        if result:
            self.func_list = pickle.loads(result)
            self.set_finalized(True)
            self.set_saved(True)
        return result

    def save_to_idb(self):
        node = netnode(self.nodeid)
        node.create(self.nodename)
        node.delblob(0, "L")
        node.setblob(pickle.dumps(self.func_list, pickle.HIGHEST_PROTOCOL), 0, "L")
        self.set_saved(True)

    def set_finalized(self, flag):
        self.isFinalized = flag

    def is_finalized(self):
        return self.isFinalized

    def set_saved(self, saved):
        self.savedResults = saved

    def is_saved(self):
        return self.savedResults

# ----------------------------------------------------------------------------
class idb_hook(IDB_Hooks):
    def __init__(self):
        IDB_Hooks.__init__(self)

    def savebase(self):
        global FUNC_CHOOSER
        global PLUGIN_NAME
        if FUNC_CHOOSER is not None and not FUNC_CHOOSER.is_saved():
            print("\n%s: saving...\n" % PLUGIN_NAME)
            FUNC_CHOOSER.save_to_idb()
        return 0

# ----------------------------------------------------------------------------
class func_scanner_plugin_t(plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Shift-Ctrl-L"

    def init(self):
        self.hook = idb_hook()
        self.hook.hook()
        print("%s: plugin initialized." % PLUGIN_NAME)
        return PLUGIN_KEEP

    def run(self, arg):
        global FUNC_CHOOSER

        title = "Function Properties View"

        if not auto_is_ok():
            Warning("Please wait for auto analysis to finish")
            return

        if FUNC_CHOOSER is None:
            FUNC_CHOOSER = FuncChooser(title, nb=10, modal=False)

            if not FUNC_CHOOSER.is_finalized() and not FUNC_CHOOSER.load_from_idb():
                FUNC_CHOOSER.scan_idb()

            # Register actions
            for action in POPUP_ACTIONS:
                actname = "lf:act%s" % action
                register_action(
                    action_desc_t(
                        actname,
                        "%s" % action,
                        chooser_handler_t(action)))

        FUNC_CHOOSER.update_chooser()
        form = find_widget(title)
        if form:
            for action in POPUP_ACTIONS:
                attach_action_to_popup(form, None, "lf:act%s" % action)
                       
        return
            
    def term(self):
        if self.hook:
            self.hook.unhook()

# ----------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return func_scanner_plugin_t()