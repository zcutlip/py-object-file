from .mach_o import (
    int_to_hex32,
    address_range_to_str,
    address_to_str,
    Mach
)

import tkinter  # noqa: E402
# from Tkinter import *

from tkinter import (  # noqa: E402
    Text,
    NONE,
    VERTICAL,
    HORIZONTAL,
    NSEW,
    NS,
    EW,
    END,
    Y,
    BOTH,
    TOP,
    W,
    StringVar,
    Tk
)

from tkinter.ttk import (  # noqa: E402
    Frame,
    Scrollbar,
    Treeview,
    OptionMenu,
    Notebook,
    # String,
    Style
)

class ScrollText(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.createWidgets()

    def createWidgets(self):

        self.text = Text(self, wrap=NONE)

        # Create scroll bars and bind them to the text view
        self.v_scroll = Scrollbar(orient=VERTICAL, command=self.text.yview)
        self.h_scroll = Scrollbar(orient=HORIZONTAL, command= self.text.xview)
        self.text['yscroll'] = self.v_scroll.set
        self.text['xscroll'] = self.h_scroll.set

        # Place the text view and scroll bars into this frame
        self.columnconfigure(0, weight=1)  # Make sure the text view always resizes horizontally to take up all space
        self.rowconfigure(0, weight=1)  # Make sure the text view always resizes vertically to take up all space
        self.text.grid(in_=self, row=0, column=0, sticky=NSEW)
        self.v_scroll.grid(in_=self, row=0, column=1, rowspan=2, sticky=NS)
        self.h_scroll.grid(in_=self, row=1, column=0, sticky=EW)

    def setText(self, text):
        pass
        self.text.delete(1.0, END)
        self.text.insert(END, text)

class DelegateTree(Frame):

    def __init__(self, parent, column_dicts, delegate):
        Frame.__init__(self, parent)
        self.sort_column_id = None
        self.sort_type = 'string'
        self.sort_direction = 1  # 0 = None, 1 = Ascending, 2 = Descending
        self.pack(expand=Y, fill=BOTH)
        self.delegate = delegate
        self.column_dicts = column_dicts
        self.item_id_to_item_dict = dict()
        frame = Frame(self)
        frame.pack(side=TOP, fill=BOTH, expand=Y)
        self._create_treeview(frame)
        self._populate_root()

    def _heading_clicked(self, column_id):
        # Detect if we are clicking on the same column again?
        reclicked = self.sort_column_id == column_id
        self.sort_column_id = column_id
        if reclicked:
            self.sort_direction += 1
            if self.sort_direction > 2:
                self.sort_direction = 0
        else:
            self.sort_direction = 1

        matching_column_dict = None
        for column_dict in self.column_dicts:
            if column_dict['id'] == self.sort_column_id:
                matching_column_dict = column_dict
                break
        new_sort_type = None
        if matching_column_dict:
            new_heading_text = ' ' + column_dict['text']
            if self.sort_direction == 1:
                new_heading_text += ' ' + chr(0x25BC).encode('utf8')
            elif self.sort_direction == 2:
                new_heading_text += ' ' + chr(0x25B2).encode('utf8')
            self.tree.heading(column_id, text=new_heading_text)
            if 'sort_type' in matching_column_dict:
                new_sort_type = matching_column_dict['sort_type']

        if new_sort_type is None:
            new_sort_type = 'string'
        self.sort_type = new_sort_type
        self.reload()

    def _create_treeview(self, parent):
        frame = Frame(parent)
        frame.pack(side=TOP, fill=BOTH, expand=Y)

        column_ids = list()
        for i in range(1,len(self.column_dicts)):
            column_ids.append(self.column_dicts[i]['id'])
        # create the tree and scrollbars
        self.tree = Treeview(columns=column_ids)
        self.tree.tag_configure('monospace', font=('Menlo', '12'))
        scroll_bar_v = Scrollbar(orient=VERTICAL, command= self.tree.yview)
        scroll_bar_h = Scrollbar(orient=HORIZONTAL, command= self.tree.xview)
        self.tree['yscroll'] = scroll_bar_v.set
        self.tree['xscroll'] = scroll_bar_h.set

        # setup column headings and columns properties
        for column_dict in self.column_dicts:
            column_id = column_dict['id']
            self.tree.heading(column_id, text=' ' + column_dict['text'], anchor=column_dict['anchor'], command=lambda c=column_id: self._heading_clicked(c))
            if 'width' in column_dict:
                self.tree.column(column_id, stretch=column_dict['stretch'], width=column_dict['width'])
            else:
                self.tree.column(column_id, stretch=column_dict['stretch'])


        # add tree and scrollbars to frame
        self.tree.grid(in_=frame, row=0, column=0, sticky=NSEW)
        scroll_bar_v.grid(in_=frame, row=0, column=1, sticky=NS)
        scroll_bar_h.grid(in_=frame, row=1, column=0, sticky=EW)

        # set frame resizing priorities
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # action to perform when a node is expanded
        self.tree.bind('<<TreeviewOpen>>', self._update_tree)

    def insert_items(self, parent_id, item_dicts):
        for item_dict in item_dicts:
            name = None
            values = list()
            first = True
            for column_dict in self.column_dicts:
                column_key = column_dict['id']
                if column_key in item_dict:
                    column_value = item_dict[column_key]
                else:
                    column_value = ''
                if first:
                    name = column_value
                    first = False
                else:
                    values.append(column_value)
            item_id = self.tree.insert (parent_id,  # root item has an empty name
                                        END,
                                        text=name,
                                        values=values,
                                        tag='monospace')
            self.item_id_to_item_dict[item_id] = item_dict
            if 'children' in item_dict and item_dict['children']:
                self.tree.insert(item_id, END, text='dummy')

    def _sort_item_dicts(self, item_dicts):
        if self.sort_column_id is None or self.sort_direction == 0:
            return item_dicts  # No sorting needs to happen
        if self.sort_type == 'number':
            return sorted(item_dicts, reverse=self.sort_direction==2, key=lambda k, c=self.sort_column_id: int(k.get(c, 0), 0))
        else:
            return sorted(item_dicts, reverse=self.sort_direction==2, key=lambda k, c=self.sort_column_id: k.get(c, ''))

    def _populate_root(self):
        # use current directory as root node
        item_dicts = self._sort_item_dicts(self.delegate.get_child_item_dictionaries())
        self.insert_items('', item_dicts)

    def _update_tree(self, event):
        # user expanded a node - build the related directory
        item_id = self.tree.focus()      # the id of the expanded node
        children = self.tree.get_children (item_id)
        if len(children):
            first_child = children[0]
            # if the node only has a 'dummy' child, remove it and
            # build new directory skip if the node is already
            # populated
            if self.tree.item(first_child, option='text') == 'dummy':
                self.tree.delete(first_child)
                item_dict = self.item_id_to_item_dict[item_id]
                item_dicts = self._sort_item_dicts(item_dict['tree-item-delegate'].get_child_item_dictionaries())
                self.insert_items(item_id, item_dicts)

    def reload(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._populate_root()

class LoadCommandTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_item_dictionary(self):
        name = "Load Commands"
        return { '#0' : name,
                 'value': '',
                 'summary': '',
                 'children' : True,
                 'tree-item-delegate' : self }

    def get_child_item_dictionaries(self):
        item_dicts = list()
        load_commands = self.mach_frame.selected_mach.commands
        for idx, lc in enumerate(load_commands):
            item_dicts.append(lc.get_item_dictionary())
        return item_dicts

class SectionListTreeItemDelegate(object):
    def __init__(self, sections, flat):
        self.sections = sections
        self.flat = flat

    def get_item_dictionary(self):
        return { '#0' : 'sections',
                 'value': '',
                 'summary': '%u sections' % (len(self.sections)),
                 'children' : True,
                 'tree-item-delegate' : self }

    def get_child_item_dictionaries(self):
        item_dicts = list()
        for section in self.sections:
            if self.flat:
                item_dict = { '#0'         : str(section.index),
                              'offset'     : int_to_hex32(section.offset),
                              'align'      : int_to_hex32(section.align),
                              'reloff'     : int_to_hex32(section.reloff),
                              'nreloc'     : int_to_hex32(section.nreloc),
                              'flags'      : section.get_flags_as_string(),
                              'type'       : section.get_type_as_string(),
                              'attrs'      : section.get_attributes_as_string(),
                              'reserved1'  : int_to_hex32(section.reserved1),
                              'reserved2'  : int_to_hex32(section.reserved2) }
                if section.sectname:
                    item_dict['sectname'] = section.sectname
                if section.segname:
                    item_dict['segname'] = section.segname
                item_dict['range'] = address_range_to_str(section.addr, section.addr + section.size, section.is_64)
                item_dict['addr'] = address_to_str(section.addr, section.is_64)
                item_dict['size'] = address_to_str(section.size, section.is_64)
                if section.is_64:
                    item_dict['reserved3'] = int_to_hex32(section.reserved3)
                item_dicts.append(item_dict)
            else:
                item_dicts.append(section.get_item_dictionary())
        return item_dicts

class SymbolsTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_item_dictionary(self):
        return { '#0' : 'symbols',
                 'value': '',
                 'summary': '%u symbols' % (len(self.symbols)),
                 'children' : True,
                 'tree-item-delegate' : self }

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        symbols = mach.get_symtab()
        for nlist in symbols:
            item_dict = nlist.get_item_dictionary()
            sect_idx = item_dict['sect_idx']
            if nlist.sect_idx_is_section_index():
                section = self.mach_frame.selected_mach.sections[sect_idx]
                item_dict['sect'] = section.segname + '.' + section.sectname
            else:
                item_dict['sect'] = str(sect_idx)
            item_dicts.append(item_dict)
        return item_dicts

class DWARFDebugInfoTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            debug_info = dwarf.get_debug_info()
            cus = debug_info.get_compile_units()
            for cu in cus:
                item_dict = cu.get_die().get_item_dictionary()
                if item_dict:
                    item_dicts.append(item_dict)
        return item_dicts

class DWARFDebugLineTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            debug_info = dwarf.get_debug_info()
            cus = debug_info.get_compile_units()
            for cu in cus:
                line_table = cu.get_line_table()
                item_dict = line_table.get_item_dictionary()
                if item_dict:
                    item_dicts.append(item_dict)
        return item_dicts

class StringTableTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            data = dwarf.debug_str_data
            length = data.get_size()
            data.seek(0)
            while data.tell() < length:
                item_dicts.append({ '#0' : '0x%8.8x' % (data.tell()), 'string' : '"%s"' % (data.get_c_string()) })
        return item_dicts

class MachFrame(Frame):

    def __init__(self, parent, options, mach_files):
        Frame.__init__(self, parent)
        self.parent = parent
        self.options = options
        self.mach = None
        self.mach_files = mach_files
        self.mach_index = 0
        self.selected_mach = None
        self.lc_tree = None
        self.sections_tree = None
        self.symbols_tree = None
        self.selected_filepath = StringVar()
        self.selected_arch = StringVar()
        self.selected_arch.trace("w", self.arch_changed_callback)
        self.selected_filepath.set(self.mach_files[0])
        self.load_mach_file(self.mach_files[0])
        self.createWidgets()
        self.update_arch_option_menu()

    def load_mach_file (self, path):
        self.mach = Mach()
        self.mach.parse(path)
        self.selected_filepath.set(path)
        first_arch_name = str(self.mach.get_architecture(0))
        self.selected_mach = self.mach.get_architecture_slice(first_arch_name)
        self.selected_arch.set(first_arch_name)

    def update_arch_option_menu(self):
        # Update the architecture menu
        menu = self.arch_mb['menu']
        menu.delete(0,END)
        if self.mach:
            num_archs = self.mach.get_num_archs()
            for i in range(num_archs):
                arch_name = str(self.mach.get_architecture(i))
                menu.add_command(label=arch_name, command=tkinter._setit(self.selected_arch, arch_name))

    def refresh_frames(self):
        if self.lc_tree:
            self.lc_tree.reload()
        if self.sections_tree:
            self.sections_tree.delegate = SectionListTreeItemDelegate(self.selected_mach.sections[1:], True)
            self.sections_tree.reload()
        if self.symbols_tree:
            self.symbols_tree.reload()

    def file_changed_callback(self, *dummy):
        path = self.selected_filepath.get()
        if self.mach is None or self.mach.path != path:
            self.load_mach_file(path)
            self.refresh_frames()
        else:
            print('file did not change')

    def arch_changed_callback(self, *dummy):
        arch = self.selected_arch.get()
        self.selected_mach = self.mach.get_architecture_slice(arch)
        self.refresh_frames()

    def createWidgets(self):
        self.parent.title("Source")
        self.style = Style()
        self.style.theme_use("default")
        self.pack(fill=BOTH, expand=1)

        self.columnconfigure(0, pad=5, weight=1)
        self.columnconfigure(1, pad=5)
        self.rowconfigure(1, weight=1)

        files = list()
        for i, mach_file in enumerate(self.mach_files):
            files.append(mach_file)
            if i==0:
                files.append(files[0])
        self.mach_mb = OptionMenu(self, self.selected_filepath, *files, command=self.file_changed_callback)
        self.mach_mb.grid(row=0, column=0, stick=NSEW)

        self.arch_mb = OptionMenu(self, self.selected_arch, command=self.arch_changed_callback)
        self.arch_mb.grid(row=0, column=1, stick=NSEW)

        note = Notebook(self)

        lc_column_dicts = [{ 'id' : '#0'     , 'text' : 'Name'   , 'anchor' : W , 'stretch' : 0 },
                           { 'id' : 'value'  , 'text' : 'Value'  , 'anchor' : W , 'stretch' : 0 },
                           { 'id' : 'summary', 'text' : 'Summary', 'anchor' : W , 'stretch' : 1 }]

        sect_column_dicts = [{ 'id' : '#0'       , 'text' : 'Index'      , 'width' : 40  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number' },
                             { 'id' : 'segname'  , 'text' : 'Segment'    , 'width' : 80  , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'sectname' , 'text' : 'Section'    , 'width' : 120 , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'range'    , 'text' : 'Address Range', 'width' : 300 , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'size'     , 'text' : 'Size'       , 'width' : 140 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'offset'   , 'text' : 'File Offset', 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number' },
                             { 'id' : 'align'    , 'text' : 'Align'      , 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'reloff'   , 'text' : 'Rel Offset' , 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'nreloc'   , 'text' : 'Num Relocs' , 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'type'     , 'text' : 'Type'       , 'width' : 200 , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'attrs'    , 'text' : 'Attributes' , 'width' : 200 , 'anchor' : W , 'stretch' : 1 },
                             { 'id' : 'reserved1', 'text' : 'reserved1'  , 'width' : 100 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'reserved2', 'text' : 'reserved2'  , 'width' : 100 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'reserved3', 'text' : 'reserved3'  , 'width' : 100 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'}]

        symbol_column_dicts = [{ 'id' : '#0'    , 'text' : 'Index'     , 'width' : 50  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                               { 'id' : 'type'  , 'text' : 'Type'      , 'width' : 60  , 'anchor' : W , 'stretch' : 0 },
                               { 'id' : 'flags' , 'text' : 'Flags'     , 'width' : 60  , 'anchor' : W , 'stretch' : 0 },
                               { 'id' : 'sect'  , 'text' : 'Section'   , 'width' : 200 , 'anchor' : W , 'stretch' : 0 },
                               { 'id' : 'desc'  , 'text' : 'Descriptor', 'width' : 60  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                               { 'id' : 'value' , 'text' : 'Value'     , 'width' : 140 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                               { 'id' : 'name'  , 'text' : 'Name'      , 'width' : 80  , 'anchor' : W , 'stretch' : 1 }]

        debug_info_column_dicts = [
            { 'id' : '#0'   , 'text' : 'Offset', 'anchor' : W , 'stretch' : 0 },
            { 'id' : 'name' , 'text' : 'Name'  , 'anchor' : W , 'stretch' : 0 },
            { 'id' : 'value', 'text' : 'Value' , 'anchor' : W , 'stretch' : 1 }
        ]

        debug_line_column_dicts = [ { 'id' : '#0' , 'text' : 'Address', 'width' : 200, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'file' , 'text' : 'File'  , 'width' : 400, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'line' , 'text' : 'Line'  , 'width' : 40, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'column' , 'text' : 'Col', 'width' : 40, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'is_stmt' , 'text' : 'Stmt', 'width' : 40, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'end_sequence' , 'text' : 'End'  , 'width' : 10, 'anchor' : W , 'stretch' : 1 }]
        debug_str_column_dicts = [{ 'id' : '#0'   , 'width' : 100, 'text' : 'Offset', 'anchor' : W , 'stretch' : 0 },
                                  { 'id' : 'string', 'text' : 'String' , 'anchor' : W , 'stretch' : 1 }]

        self.lc_tree = DelegateTree(self, lc_column_dicts, LoadCommandTreeItemDelegate(self))
        self.sections_tree = DelegateTree(self, sect_column_dicts, SectionListTreeItemDelegate(self.selected_mach.sections[1:], True))
        self.symbols_tree = DelegateTree(self, symbol_column_dicts, SymbolsTreeItemDelegate(self))
        self.debug_info_tree = DelegateTree(self, debug_info_column_dicts, DWARFDebugInfoTreeItemDelegate(self))
        self.debug_line_tree = DelegateTree(self, debug_line_column_dicts, DWARFDebugLineTreeItemDelegate(self))
        self.debug_str_tree = DelegateTree(self, debug_str_column_dicts, StringTableTreeItemDelegate(self))
        note.add(self.lc_tree, text = "Load Commands", compound=TOP)
        note.add(self.sections_tree, text = "Sections")
        note.add(self.symbols_tree, text = "Symbols")
        note.add(self.debug_info_tree, text = ".debug_info")
        note.add(self.debug_line_tree, text = ".debug_line")
        note.add(self.debug_str_tree, text = ".debug_str")
        note.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky= NSEW)
        #
        # self.info_text = ScrollText(self)
        # self.info_text.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky= NSEW)





def tk_gui(options, mach_files):
    root = Tk()
    root.geometry("800x600+300+300")
    # TODO: why are we assigning "app" but not using it?
    # app = MachFrame(root, options, mach_files)
    MachFrame(root, options, mach_files)
    root.mainloop()
