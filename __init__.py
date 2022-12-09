import binaryninja as binja
from binaryninja.plugin import PluginCommand

DEBUG = True

def fix_analysis(bv, func):
	# Binja may have skipped analysis of the function
	# force analysis so we can use llil/mlil
	if func is not None and func.analysis_skipped:
		func.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
		bv.update_analysis_and_wait()


def build_string_table(bv, db=None):
	# for storing all xrefs
	# will be a dict of namedtuple with the string offset as the key
	# all xrefs will be added to the namedtuple field xrefs
	all_strings = {}
	for func in bv.functions:
		fix_analysis(bv, func)
		for block in func.low_level_il.basic_blocks:
			for instr in block
				# if isinstance(instr, LowLevelILInstruction):
				#    if instr.operation != binja.LowLevelILOperation.LLIL_SET_REG:
				#        continue
				if instr.operation == binja.LowLevelILOperation.LLIL_CALL:
					continue
				# traverse operands looking for xrefs to string
				for oper in instr.operands:
					if isinstance(oper, binja.LowLevelILInstruction):
						# if oper.operation != binja.LowLevelILOperation.LLIL_CONST_PTR:
						#    continue
						string_offset = oper.value.value
						ss = bv.get_string_at(string_offset)
						if ss:
							# check if string is printable 
							if not ss.value.replace("\x00", "").isprintable():
								continue
							if bv.is_offset_code_semantics(string_offset):
									continue 
							if string_offset not in all_strings:
								all_strings[string_offset] = {"string": "", "type": "", "offset": "", "xrefs": []}
							# get string value
							all_strings[string_offset]["string"] = ss.value
							# get string type
							all_strings[string_offset]["type"] = ss.type
							# yes the data is duplicated but looping through all the keys
							# be easier to read
							all_strings[string_offset]["offset"] = string_offset
							all_strings[string_offset]["xrefs"].append(instr.address)
							if DEBUG:
								if not string_offset:
									string_offset = ""
								print("%s %s" % (ss.value, ss.type))
	return all_strings


def format_row(row):
	addr = "[0x{:08x}](binaryninja://?expr=0x{:08x})".format(row["offset"], row["offset"])
	offsets = " ".join("[0x{:08x}](binaryninja://?expr=0x{:08x})".format(x, x) for x in row["xrefs"])
	# str_clean = row["string"].replace("\n", "\\n").replace("|", "\|")
	str_clean = "```%s```" % row["string"]
	print(str_clean,  row["string"])
	format_row = "| %s | %s | %s   | %s   |\n" % (addr, str_clean, row["type"], offsets)

	return format_row


def create_markdow(data):
	rows = f"""| String Offset   | String | Type |Cross-References |
    | ----------- | ----------- |----------- |----------- |
    """
	for strstr in data:
		rows += format_row(data[strstr])
	return rows


def strings_strings(bv):
	bv.add_analysis_option("linearsweep")
	# bv.update_analysis_and_wait()
	try:
		tt = build_string_table(bv)
	except Exception as e:
		print("ERROR: Make sure the primary binary view is selected, not the strings tab: %s" % e)
		return

	rows = create_markdow(tt)
	bv.show_markdown_report("Strings", rows, rows)

PluginCommand.register("String Xrefs", "Find xrefs to strings", strings_strings)
