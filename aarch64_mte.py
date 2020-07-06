# AArch64 8.5 Memory Tagging Extension

# Copyright (c) 2020 Stefan Esser - Antid0te
from __future__ import print_function

import ida_idp
import ida_ua
import ida_bytes
import ida_idaapi

aux_cond = 0x0001
aux_wback = 0x0020
aux_postidx = 0x0080

MTE_ADDG  = ida_idp.CUSTOM_INSN_ITYPE + 1000
MTE_GMI   = MTE_ADDG + 1
MTE_IRG   = MTE_GMI + 1
MTE_LDG   = MTE_IRG + 1
MTE_LDGM  = MTE_LDG + 1
MTE_SUBG  = MTE_LDGM + 1
MTE_SUBP  = MTE_SUBG + 1
MTE_STG   = MTE_SUBP + 1
MTE_STZG  = MTE_STG + 1
MTE_ST2G  = MTE_STZG + 1
MTE_STZ2G = MTE_ST2G + 1
MTE_STGP  = MTE_STZ2G + 1
MTE_STGM  = MTE_STGP + 1
MTE_STZGM = MTE_STGM + 1

MNEM_WIDTH = 16

MNEM_NAMES = {
	MTE_ADDG:   "ADDG",
	MTE_GMI:    "GMI",
	MTE_IRG:    "IRG",
	MTE_LDG:    "LDG",
	MTE_LDGM:   "LDGM",
	MTE_SUBG:   "SUBG",
	MTE_SUBP:   "SUBP",
	MTE_STG:    "STG",
	MTE_STZG:   "STZG",
	MTE_ST2G:   "ST2G",
	MTE_STZ2G:  "STZ2G",
	MTE_STGP:   "STGP",
	MTE_STGM:   "STGM",
	MTE_STZGM:  "STZGM"
}

def decode_MTE(code, insn):
	if (code & 0xffc0c000) == 0x91800000:
		Xn = (code >>5) & 0x1f
		Xd = code & 0x1f
		uimm4 = (code >> 10) & 0xf
		uimm6 = (code >> 16) & 0x3f

		if Xd == 31:
			Xd += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_ADDG
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op3.type = ida_ua.o_imm
		insn.Op3.value = uimm6
		insn.Op3.dtype = ida_ua.dt_qword
		insn.Op4.type = ida_ua.o_imm
		insn.Op4.value = uimm4
		insn.Op4.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xffc0c000) == 0xD1800000:
		Xn = (code >>5) & 0x1f
		Xd = code & 0x1f
		uimm4 = (code >> 10) & 0xf
		uimm6 = (code >> 16) & 0x3f

		if Xd == 31:
			Xd += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_SUBG
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op3.type = ida_ua.o_imm
		insn.Op3.value = uimm6
		insn.Op3.dtype = ida_ua.dt_qword
		insn.Op4.type = ida_ua.o_imm
		insn.Op4.value = uimm4
		insn.Op4.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xffe0fc00) == 0x9ac01000:
		Xn = (code >>5) & 0x1f
		Xd = code & 0x1f
		Xm = (code >> 16) & 0x1f

		if Xd == 31:
			Xd += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_IRG
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		if Xm != 31:
			insn.Op3.type = ida_ua.o_reg
			insn.Op3.reg = Xm + 129
			insn.Op3.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xffe0fc00) == 0x9ac01400:
		Xn = (code >>5) & 0x1f
		Xd = code & 0x1f
		Xm = (code >> 16) & 0x1f

		if Xn == 31:
			Xn += 1

		insn.itype = MTE_GMI
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op3.type = ida_ua.o_reg
		insn.Op3.reg = Xm + 129
		insn.Op3.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xffe0fc00) == 0x9ac00000:
		Xn = (code >>5) & 0x1f
		Xd = code & 0x1f
		Xm = (code >> 16) & 0x1f

		if Xn == 31:
			Xn += 1

		if Xm == 31:
			Xm += 1

		insn.itype = MTE_SUBP
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op3.type = ida_ua.o_reg
		insn.Op3.reg = Xm + 129
		insn.Op3.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xffe0fc00) == 0xbac00000:
		Xn = (code >>5) & 0x1f
		Xd = code & 0x1f
		Xm = (code >> 16) & 0x1f

		if Xn == 31:
			Xn += 1

		if Xm == 31:
			Xm += 1

		insn.itype = MTE_SUBP
		insn.size = 4
		insn.cond = 14
		insn.auxpref = aux_cond
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op3.type = ida_ua.o_reg
		insn.Op3.reg = Xm + 129
		insn.Op3.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xFFE00000) == 0xD9200000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f
		mode = (code >> 10) & 3
		imm9 = (code >> 12) & 0x1ff

		if imm9 & 0x100:
			tmp = -1
			tmp &= ~0x1ff
			imm9 = tmp | imm9

		simm = imm9 * 16

		if Xt == 31:
			Xt += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_STG
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_displ
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op2.addr = simm
		if mode == 1: 
			insn.Op2.auxpref = aux_postidx|aux_wback
		elif mode == 3:
			insn.Op2.auxpref = aux_wback
		elif mode == 2:
			insn.Op2.auxpref = 0
		elif mode == 0:
			return False
		return True	
	elif (code & 0xFFE00000) == 0xD9A00000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f
		mode = (code >> 10) & 3
		imm9 = (code >> 12) & 0x1ff

		if imm9 & 0x100:
			tmp = -1
			tmp &= ~0x1ff
			imm9 = tmp | imm9

		simm = imm9 * 16

		if Xt == 31:
			Xt += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_ST2G
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_displ
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op2.addr = simm
		if mode == 1: 
			insn.Op2.auxpref = aux_postidx|aux_wback
		elif mode == 3:
			insn.Op2.auxpref = aux_wback
		elif mode == 2:
			insn.Op2.auxpref = 0
		elif mode == 0:
			return False
		return True
	elif (code & 0xFFE00000) == 0xD9E00000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f
		mode = (code >> 10) & 3
		imm9 = (code >> 12) & 0x1ff

		if imm9 & 0x100:
			tmp = -1
			tmp &= ~0x1ff
			imm9 = tmp | imm9

		simm = imm9 * 16

		if Xt == 31:
			Xt += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_STZ2G
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_displ
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op2.addr = simm
		if mode == 1: 
			insn.Op2.auxpref = aux_postidx|aux_wback
		elif mode == 3:
			insn.Op2.auxpref = aux_wback
		elif mode == 2:
			insn.Op2.auxpref = 0
		elif mode == 0:
			return False
		return True
	elif (code & 0xFFE00000) == 0xD9600000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f
		mode = (code >> 10) & 3
		imm9 = (code >> 12) & 0x1ff

		if imm9 & 0x100:
			tmp = -1
			tmp &= ~0x1ff
			imm9 = tmp | imm9

		simm = imm9 * 16

		if Xt == 31:
			Xt += 1
		if Xn == 31:
			Xn += 1

		insn.itype = MTE_STZG
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_displ
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op2.addr = simm
		if mode == 1: 
			insn.Op2.auxpref = aux_postidx|aux_wback
		elif mode == 3:
			insn.Op2.auxpref = aux_wback
		elif mode == 2:
			insn.Op2.auxpref = 0
		elif mode == 0:
			return False
		return True
	elif (code & 0xFFC00000) == 0x68800000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f
		Xt2 = (code >>10) & 0x1f
		mode = (code >> 10) & 3
		imm7= (code >> 15) & 0x7f

		if imm7 & 0x40:
			tmp = -1
			tmp &= ~0x7f
			imm7 = tmp | imm7

		simm = imm7 * 16

		if Xn == 31:
			Xn += 1

		insn.itype = MTE_STGP
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xt2 + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op3.type = ida_ua.o_displ
		insn.Op3.reg = Xn + 129
		insn.Op3.dtype = ida_ua.dt_qword
		insn.Op3.addr = simm
		if mode == 1: 
			insn.Op3.auxpref = aux_postidx|aux_wback
		elif mode == 3:
			insn.Op3.auxpref = aux_wback
		elif mode == 2:
			insn.Op3.auxpref = 0
		elif mode == 0:
			return False
		return True
	elif (code & 0xFFE00c00) == 0xD9600000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f
		imm9 = (code >> 12) & 0x1ff

		if imm9 & 0x100:
			tmp = -1
			tmp &= ~0x1ff
			imm9 = tmp | imm9

		simm = imm9 * 16

		if Xn == 31:
			Xn += 1

		insn.itype = MTE_LDG
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_displ
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		insn.Op2.addr = simm
		return True	
	elif (code & 0xFFFFFC00) == 0xD9A00000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f

		if Xn == 31:
			Xn += 1

		insn.itype = MTE_STGM
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xFFFFFC00) == 0xD9200000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f

		if Xn == 31:
			Xn += 1

		insn.itype = MTE_STZGM
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		return True
	elif (code & 0xFFFFFC00) == 0xD9E00000:
		Xn = (code >>5) & 0x1f
		Xt = code & 0x1f

		if Xn == 31:
			Xn += 1

		insn.itype = MTE_LDGM
		insn.size = 4
		insn.cond = 14
		insn.Op1.type = ida_ua.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = ida_ua.dt_qword
		insn.Op2.type = ida_ua.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = ida_ua.dt_qword
		return True

	return False

class Aarch64_MTE_hooks_t(ida_idp.IDP_Hooks):
	def ev_ana_insn(self, insn):
		code = ida_bytes.get_dword(insn.ea)
		r = decode_MTE(code, insn)
		if r:
			return insn.size
		return 0

	def ev_emu_insn(self, insn):
		return 0

	def ev_out_mnem(self, outctx):
		if (outctx.insn.itype >= MTE_ADDG) and (outctx.insn.itype <= MTE_STZGM):
			mnem = MNEM_NAMES[outctx.insn.itype]
			outctx.out_custom_mnem(mnem, MNEM_WIDTH)
			return 1
		return 0

class Aarch64_MTE_t(ida_idaapi.plugin_t):
	flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
	wanted_name = "Aarch64 MTE"
	wanted_hotkey = ""
	comment = "ARM v8.5 Memory Tagging Extension"
	help = "Runs transparently"

	def init(self):
		self.hook = None
		if ida_idp.ph_get_id() != ida_idp.PLFM_ARM: # TODO: we only want to run in 64bit context
			return ida_idaapi.PLUGIN_SKIP
		print ("%s init" % self.comment)
		self.hook = Aarch64_MTE_hooks_t()
		self.hook.hook()
		return ida_idaapi.PLUGIN_KEEP

	def run():
		pass

	def term(self):
		if self.hook is not None:
			self.hook.unhook()
		print ("%s term" % self.comment)

def PLUGIN_ENTRY():
	return Aarch64_MTE_t()
