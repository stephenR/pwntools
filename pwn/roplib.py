import pwn


class roplib:
    ''' Lib to find ROP-gadgets

'''
    def __init__(self, path):
        if isinstance(path, pwn.ELF):
            self.elf = path
        else:
            self.elf = pwn.elf.load(path)

        self.segments = self.elf.segments
        self.sections = dict()
        for k, v in self.elf.sections.items():
            self.sections[k] = v['addr']
        self.symbols = dict()
        for k, v in self.elf.symbols.items():
            self.symbols[k] = v['addr']
        self.plt = self.elf.plt
        self.got = self.elf.got

        self._gadgets = {}
        self._load_gadgets()

    def load_library(self, file, addr, relative_to = None):
        import os
        syms = {}

        if not os.path.exists(file):
            if file in self.elf.libs:
                file = self.elf.libs[file]
            else:
                pwn.die('Could not load library, file %s does not exist.' % file)

        for k, v in pwn.elf.symbols(file).items():
            if '@@' in k:
                k = k[:k.find('@@')]
            syms[k] = v
        offset = addr
        if relative_to:
            if relative_to not in syms:
                pwn.die('Could not load library relative to "%s" -- no such symbol', relative_to)
            offset -= syms[relative_to]['addr']
        for k, v in syms.items():
            self.symbols[k] = v['addr'] + offset


    def add_symbol(self, symbol, addr):
        self.symbols[symbol] = addr



    def _load_gadgets(self):
        if self.elf.elfclass == 'ELF32':
            pwn.context('i386')
            self._load32_popret()
            self._load32_gadget('\xc3') # ret
            self._load32_gadget('\xc9\xc3') # leave ; ret
            call_leave_ret = map(lambda x : '\xff'+chr(x)+'\xc9\xc3',
                                 [0xd0, 0xd1, 0xd2, 0xd3, 0xd3, 0xd5, 0xd6, 0xd7])
            for c in call_leave_ret:
                self._load32_gadget(c)

            call_ret = map(lambda x : '\xff'+chr(x)+'\xc3',
                           [0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7])
            for c in call_ret:
                self._load32_gadget(c)

            add_ret = map(lambda x : '\x01'+chr(x)+'\xc3',
                          [0xc0, 0xc8, 0xd0, 0xd8])

            self._load32_mov()

        elif self.elf.elfclass == 'ARMELF32':
            pwn.context('i386', 'arm')
            # self._load32_arm_all()
        elif self.elf.elfclass == 'ELF64':
            pwn.context('amd64')



    # def _load32_ret(self, ret = '\xc3'):
    #     for data, addr in self.elf.executable_segments():
    #         i = 0
    #         while True:
    #             idx = data.find(ret, i)
    #             if idx == -1: break
    #             gaddr = addr + idx
    #             if data[idx] == ret:
    #                 self._gadgets[gaddr] = 'ret'
    #             i += 1

    # def _load32_call(self, ret = '\xc3'):
    #     from collections import defaultdict
    #     call = '\xff'
    #     bytes = {}
    #     bytes[1] = map(pwn.p8, [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]) # call e*x/esp/ebp

    #     for data, addr in self.elf.executable_segments():
    #         i = 0
    #         while True:
    #             idx = data.find(ret, i)
    #             if idx == -1: break
    #             gaddr = addr + idx
    #             for off in xrange(2,3):
    #                 if data[idx-off] == call and data[idx-(off-1):idx] in bytes[off-1]:
    #                     gadget = data[idx-off:idx] + ret
    #                     name = ' '.join(pwn.disasm(gadget).split('\n')[0].split('\t')[2].split())
    #                     self._gadgets[gaddr-off] = name
    #             i += 1

    def _load32_mov(self, ret='\xc3'):
        mov = '\x8b'
        bytes = {}
        bytes[1] = map(pwn.p8, [0x00, 0x01, 0x02, 0x03, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x0a, 0x0b, 0x0f, 0x18, 0x19, 0x1a, 0x1b, 0x1f]) # combos of mov e*x, [e*x]
        bytes[2] = map(pwn.p16b, [0x1c24, 0x4500])
        for data, addr in self.elf.executable_segments():
            i = 0
            while True:
                idx = data.find(ret, i)
                if idx == -1: break
                gaddr = addr + idx
                for off in xrange(2,4):
                    if data[idx-off] == mov and data[idx-(off-1):idx] in bytes[off-1]:
                        gadget = data[idx-off:idx+1]
                        name = ' '.join(pwn.disasm(gadget).split('\n')[0].split('\t')[2].split())
                        self._gadgets[gaddr-off] = name + ' ; ret'
                i += 1


    def _load32_popret(self, ret='\xc3'):
        addesp = '\x83\xc4'
        popr = map(chr, [0x58, 0x59, 0x5a, 0x5b, 0x5d, 0x5e, 0x5f])
        popa = '\x61'
        for data, addr in self.elf.executable_segments():
            i = 0
            while True:
                i = data.find(ret, i)
                if i == -1: break
                s = [(i, 0)]
                while len(s) > 0:
                    off, size = s.pop(0)
                    gaddr = addr + off
                    gadget = data[off : off+size]
                    try:
                        newname = []
                        name = pwn.disasm(gadget+ret)
                        for n in name.split('\n'):
                            newname.append(' '.join(n.split('\t')[2].split()))
                        name = ' ; '.join(newname)
                        self._gadgets[gaddr] = name
                    except:
                        pass

                    if data[off - 1] in popr:
                        s.append((off - 1, size + 1))
                    if data[off - 1] == popa:
                        s.append((off - 1, size + 7))
                    if data[off - 3:off - 1] == addesp:
                        x = pwn.u8(data[off - 1])
                        if x % 4 == 0:
                            s.append((off - 3, size + x // 4))

                i += 1

    def _load32_gadget(self, combination='\xc9\xc3'):
        for data, addr in self.elf.executable_segments():
            idxs = pwn.findall(data, combination)
            for i in idxs:
                newname = []
                gadget = data[i : i+len(combination)]
                name = pwn.disasm(gadget)
                for n in name.split('\n'):
                    newname.append(' '.join(n.split('\t')[2].split()))
                name = ' ; '.join(newname)
                self._gadgets[i+addr] = name

    # def _load32_arm_all(self):
    #     for data, addr in self.elf.executable_segments():
    #         for i in xrange(len(data), step=2):
    #             try:
    #                 gadget = data[i-4:i]
    #                 name = pwn.disasm(gadget)
    #                 newname = []
    #                 for n in name.split('\n'):
    #                     newname.append(' '.join(n.split('\t')[2].split()))
    #                 name = ' ; '.join(newname)
    #                 gaddr = i+addr
    #                 self._gadgets[gaddr] = name
    #             except:
    #                 pass


    def _resolve(self, x):
        if x is None or pwn.isint(x):
            return x
        for y in [self.symbols, self.plt, self.sections]:
            if x in y:
                return y[x]
        return False

    def find(self, search, amount=5):
        count = 0
        for v in self._gadgets.keys():
            if count == amount:
                return
            i = self._gadgets[v]
            if i.startswith(search):
                print "%s     %s" % (hex(v), i)
                count += 1

