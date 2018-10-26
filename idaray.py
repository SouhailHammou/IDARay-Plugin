'''
IDARay - A simple IDA plugin that matches the database against multiple YARA files.
Author : Souhail Hammou

Plugin tested under IDA Pro 6.8
Feel free to copy or edit plugin.
'''
from idc import *
from idaapi import *
import yara
import os

class YARAScan() :
	def __init__(self, directory) :
		self.directory = directory
		self.rules_dict = self.compile_all_rules()
		self.matches = {}
	
	def compile_all_rules(self) :
		rules = {}
		try :
			for filename in os.listdir(self.directory) :
				try :
					#We can't just use filepaths with yara.compile because we're also interested
					#in the filename. As a result, we'll match file by file.
					rules.update( { filename : yara.compile(os.path.join(self.directory, filename)) })
				except :
					print "IDARay : Compilation Error ! Please make sure your directory only contains YARA files."
		except :
			print "IDARay : Error while accessing directory."
		return rules
		
	def scan(self) :
		if not self.rules_dict :
			return 0
		
		#Join all segments
		data = ''
		prev_seg = 0
		for seg in Segments() :
			if prev_seg and SegEnd(prev_seg) < seg :
				data += chr(0xFF) * (seg - SegEnd(prev_seg))
			for ea in range(seg, SegEnd(seg)):
					data += chr(Byte(ea))
			prev_seg = seg
		
		#Match
		for entry in self.rules_dict :
			rule = self.rules_dict[entry]
			filename = entry
			m = rule.match(data=data)
			
			if m :
				self.matches.update( { filename : m } )
		
		#Display the results
		FilesChooserView(self.matches)
		return 1

class SingleDetailsView(idaapi.Choose2) :
	def __init__(self, rule) :
		idaapi.Choose2.__init__(self,
		"Matched strings for rule : %s" % rule.rule,
		[ ["Offset (double-click to follow)", 20 | Choose2.CHCOL_HEX], ["Matched String", 50 | Choose2.CHCOL_PLAIN] ],
		Choose2.CH_MODAL)
		
		self.strings = rule.strings
		self.Show()
	
	def OnClose(self):
		return

	def OnGetLine(self, n):
		return [ str(hex(self.strings[n][0])).strip('L').upper().replace('X','x'), self.strings[n][2] ]

	def OnGetSize(self):
		return len(self.strings)
		
	def OnSelectLine(self, n) :
		idc.Jump(FirstSeg() + self.strings[n][0])

		
class MultipleDetailsView(idaapi.Choose2) :
	def __init__(self, filename ,yara_matches) :
		idaapi.Choose2.__init__(self,
		"Matches for %s" % filename,
		[ ["Matched Rules (double-click for details)", 30 | Choose2.CHCOL_PLAIN]],
		Choose2.CH_MODAL)
		
		self.yara_matches = yara_matches
		self.Show()
	
	def OnClose(self):
		return

	def OnGetLine(self, n):
		match = self.yara_matches[n]
		line = [match.rule]
		return line

	def OnGetSize(self):
		return len(self.yara_matches)
	
	def OnSelectLine(self, n) :
		#Go to the single details view
		SingleDetailsView(self.yara_matches[n])
	
		
class FilesChooserView(idaapi.Choose2) :
	def __init__(self, matches) :
		idaapi.Choose2.__init__(self,
		"Matched YARA Files",
		[ ["Filename (Double-click for details)", 30 | Choose2.CHCOL_PLAIN], ["Number of matched rules", 30 | Choose2.CHCOL_PLAIN] ],
		Choose2.CH_MODAL)
		
		self.matches = matches
		self.Show()
			
	def OnClose(self):
		return

	def OnGetLine(self, n):
		filename = key = list(self.matches)[n]
		
		#Filename || Number of matched rules from the file
		return [filename, str(len(self.matches[key]))]

	def OnGetSize(self):
		return len(self.matches)
	
	def OnSelectLine(self, n) :
		filename = key = list(self.matches)[n]
		
		if len(self.matches[key]) > 1 :
			#If rules within multiple files match, display this view
			MultipleDetailsView(filename, self.matches[key])
		else :
			#If the matched rules are within a single file, skip the file selection view
			SingleDetailsView(self.matches[key][0])
		return 1
		
class ChooseFiles(idaapi.Form) :
	def __init__(self) :
		Form.__init__(self, 
		r"""Choose a directory containing YARA files

		Welcome to IDARay !
		IDARay matches the database against multiple 
		YARA files, which themselves may contain multiple rules.
		
		Please select a directory containing YARA files only.
		YARA Directory		<:{dir}>
		""",
		{
		'dir' : Form.DirInput(swidth=50),
		})
		
		self.Compile()

class idaray_handler(idaapi.action_handler_t):
	#http://www.hexblog.com/?p=886
	def __init__(self) :
		idaapi.action_handler_t.__init__(self)
	
	def activate(self, ctx) :
		#Open the choose file dialog
		form = ChooseFiles()
		res = form.Execute()
		
		if res == 1 :
			if form.dir.value :
				directory = form.dir.value
				yara_scan = YARAScan(directory)
				yara_scan.scan()
			else :
				print "IDARay : Please choose a directory !"
		return 1
		
	def update(self, ctx) :
		return idaapi.AST_ENABLE_ALWAYS	

		
class idaray_plugin_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "Scan database with multiple YARA files"
	wanted_name = "IDARay Plugin"
	help = "help"
	wanted_hotkey = ""
	
	def init(self):
		global idaray
		
		if 'idaray' not in globals() :
			idaray = 1
			self.initialize_menu()
		
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		idaray_handler().activate(None)

	def term(self):
		pass

	def initialize_menu(self):
		print '''------------------------------------------------------
IDARay plugin - Souhail Hammou (2018)
------------------------------------------------------'''
		
def PLUGIN_ENTRY():
    return idaray_plugin_t()