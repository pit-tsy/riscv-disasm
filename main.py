import sys

register_names = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
]

def printf(format, file, *values):
    file.write(format % values)

def bytes_str_to_array(bytes_str):
    result = []
    for i in range(0, len(bytes_str), 2):
        result.append(bytes_str[i : i + 2])
    return result

def to_uint(hexes):
    result = 0
    for i in range(len(hexes) - 1, -1, -1):
        result = (result << 8) + int(hexes[i], 16)
    return result
    
def read_header(elf):
    ident       =     elf[:0x10]
    type        =     to_uint(elf[0x10:0x12])
    machine     =     to_uint(elf[0x12:0x14])
    version     =     to_uint(elf[0x14:0x18])
    entry       =     to_uint(elf[0x18:0x1C])
    phoff       =     to_uint(elf[0x1C:0x20])
    shoff       =     to_uint(elf[0x20:0x24])
    flags       =     elf[0x24:0x30]
    ehsize      =     to_uint(elf[0x28:0x2A])
    phentsize   =     to_uint(elf[0x2A:0x2C])
    phnum       =     to_uint(elf[0x2C:0x2E])
    shentsize   =     to_uint(elf[0x2E:0x30])
    shnum       =     to_uint(elf[0x30:0x32])
    shstrndx    =     to_uint(elf[0x32:0x34])

    return {
        'ident'     : ident,
        'entry'     : entry,
        'phoff'     : phoff,
        'shoff'     : shoff,
        'flags'     : flags,
        'ehsize'    : ehsize,
        'phentsize' : phentsize,
        'phnum'     : phnum,
        'shentsize' : shentsize,
        'shnum'     : shnum,
        'shstrndx'  : shstrndx
    }
    
def get_section_info(elf, start):
    section = elf[start:start + 0x28]
    return {
        'name'      : to_uint(section[0x00:0x04]),
        'type'      : to_uint(section[0x04:0x08]),
        'flags'     : to_uint(section[0x08:0x0C]),
        'addr'      : to_uint(section[0x0C:0x10]),
        'offset'    : to_uint(section[0x10:0x14]),
        'size'      : to_uint(section[0x14:0x18]),
        'link'      : to_uint(section[0x18:0x1C]),
        'info'      : to_uint(section[0x1C:0x20]),
        'addrallign': to_uint(section[0x20:0x24]),
        'entsize'   : to_uint(section[0x24:0x28]),
    }

def get_sections(elf, header):
    start_data = header["shoff"]
    sections = []
    for _ in range(header['shnum']):
        section_info = get_section_info(elf, start_data);
        sections.append(section_info)

        start_data += header['shentsize']
    return sections


def get_section_name(sh_name):
    global elf, header, sections

    shstrndx = header['shstrndx']
    ptr = sections[shstrndx]['offset'] + sh_name

    name = ''
    while elf[ptr] != '00':
        name += chr(int(elf[ptr], 16))
        ptr += 1
    return name

def get_sections_names():
    names = []
    for section in sections:
        names.append(get_section_name(section['name']))
    return names

def get_sym_name(st_name):
    strtab_index = names.index('.strtab')
    strtab = sections[strtab_index]

    ptr = strtab['offset'] + st_name

    name = ''
    while elf[ptr] != '00':
        name += chr(int(elf[ptr], 16))
        ptr += 1
    return name

def get_symtab_entry(start, entsize):
    entry = elf[start:start + entsize]
    return {
        'name'      : get_sym_name(to_uint(entry[0:4])),
        'value'     : to_uint(entry[4:8]),
        'size'      : to_uint(entry[8:12]),
        'info'      : to_uint(entry[12:13]),
        'other'     : to_uint(entry[13:14]),
        'shndx'     : to_uint(entry[14:18]),
    }

def parse_symtab():
    global sections

    symtab_index = names.index('.symtab')
    symtab = sections[symtab_index]

    entsize = symtab['entsize']
    start = symtab['offset']
    end = start + symtab['size']

    table = []
    while start < end:
        entry = get_symtab_entry(start, entsize)
        table.append(entry)

        start += entsize
    return table


def get_opcode(entry):
    opcode = entry & ((1 << 7) - 1)
    return opcode

def get_optype(opcode):
    if opcode == 0b0110111 or opcode == 0b0010111:
        return 'U'
    elif opcode == 0b1101111:
        return 'J'
    elif opcode in (0b1100111, 0b0000011, 0b0010011):
        return 'I'
    elif opcode == 0b1100011:
        return 'B'
    elif opcode == 0b0100011:
        return 'S'
    elif opcode == 0b0110011:
        return 'R'

def get_register_name(register_number):
    global register_names

    if 0 <= register_number < len(register_names):
        return register_names[register_number]
    else:
        return register_number
            

def parse_r_type(inst):
    opcode = get_opcode(inst)
    rd = get_register_name((inst >> 7) & ((1 << 5) - 1))
    funct3 = (inst >> 12) & ((1 << 3) - 1)
    rs1 = get_register_name((inst >> 15) & ((1 << 5) - 1))
    rs2 = get_register_name((inst >> 20) & ((1 << 5) - 1))
    funct7 = (inst >> 25) & ((1 << 7) - 1)

    name = "invalid_instruction"
    if funct3 == 0b000 and funct7 == 0b0000000:
        name = "add"
    elif funct3 == 0b000 and funct7 == 0b0100000:
        name = "sub"
    elif funct3 == 0b001 and funct7 == 0b0000000:
        name = "sll"
    elif funct3 == 0b010 and funct7 == 0b0000000:
        name = "slt"
    elif funct3 == 0b011 and funct7 == 0b0000000:
        name = "sltu"
    elif funct3 == 0b100 and funct7 == 0b0000000:
        name = "xor"
    elif funct3 == 0b101 and funct7 == 0b0000000:
        name = "srl"
    elif funct3 == 0b101 and funct7 == 0b0100000:
        name = "sra"
    elif funct3 == 0b110 and funct7 == 0b0000000:
        name = "or"
    elif funct3 == 0b111 and funct7 == 0b0000000:
        name = "and"
    elif funct3 == 0b000 and funct7 == 0b0000001:
        name = 'mul'
    elif funct3 == 0b001 and funct7 == 0b0000001:
        name = 'mulh'
    elif funct3 == 0b010 and funct7 == 0b0000001:
        name = 'mulhsu'
    elif funct3 == 0b011 and funct7 == 0b0000001:
        name = 'mulhu'
    elif funct3 == 0b100 and funct7 == 0b0000001:
        name = 'div'
    elif funct3 == 0b101 and funct7 == 0b0000001:
        name = 'divu'
    elif funct3 == 0b110 and funct7 == 0b0000001:
        name = 'rem'
    elif funct3 == 0b111 and funct7 == 0b0000001:
        name = 'remu'

    return 'R', name, rd, rs1, rs2

    
def parse_i_type(inst):
    opcode = get_opcode(inst)
    rd = get_register_name((inst >> 7) & 0x1F)
    funct3 = (inst >> 12) & 0x7
    rs1 = get_register_name((inst >> 15) & 0x1F)
    imm_i = (inst >> 20) & 0xFFF
    imm_i = imm_i if (imm_i & 0x800) == 0 else imm_i - 0x1000

    name = 'invalid_instruction'
    optype = 'I'
    if opcode == 0b1100111:
        name = "jalr"
        optype = 'jalr'
    elif opcode == 0b0000011:
        if funct3 == 0b000:
            name = 'lb'
        elif funct3 == 0b001:
            name = 'lh'
        elif funct3 == 0b010:
            name = 'lw'
        elif funct3 == 0b100:
            name = 'lbu'
        elif funct3 == 0b101:
            name = 'lhu'
        optype = 'load'
    elif opcode == 0b0010011:
        if funct3 == 0b000:
            name = 'addi'
        if funct3 == 0b010:
            name = 'slti'
        if funct3 == 0b011:
            name = 'sltiu'
        if funct3 == 0b100:
            name = 'xori'
        if funct3 == 0b110:
            name = 'ori'
        if funct3 == 0b111:
            name = 'andi'
        elif funct3 == 0b001 and (inst >> 25) == 0:
            imm_i = (inst & ((1 << 25) - (1 << 20))) >> 20
            name = "slli"
        elif funct3 == 0b101 and (inst >> 25) == 0:
            imm_i = (inst & ((1 << 25) - (1 << 20))) >> 20
            name = "srli"
        elif funct3 == 0b101 and (inst >> 25) == 0b0100000:
            imm_i = (inst & ((1 << 25) - (1 << 20))) >> 20
            name = "srai"

    return optype, name, rd, rs1, imm_i

def parse_s_type(inst):
    opcode = inst & 0x7F
    funct3 = (inst >> 12) & 0x7
    rs1 = get_register_name((inst >> 15) & 0x1F)
    rs2 = get_register_name((inst >> 20) & 0x1F)

    a = (inst >> 31)
    t1 = (a << 32) - (a << 11)
    t2 = ((inst >> 7) & 0x1F)
    t3 = ((inst >> 25) & 0x3F) << 5
    imm_s = t1 | t2 | t3
    imm_s -= 2 * (a << 31)

    name = 'invalid_instruction'
    if opcode == 0b0100011:
        if funct3 == 0b000:
            name = "sb"
        elif funct3 == 0b001:
            name = "sh"
        elif funct3 == 0b010:
            name = "sw"

    return 'S', name, rs2, rs1, imm_s

def parse_b_type(inst):
    opcode = inst & 0x7F
    funct3 = (inst >> 12) & 0x7
    rs1 = get_register_name((inst >> 15) & 0x1F)
    rs2 = get_register_name((inst >> 20) & 0x1F)
    
    # start calc imm
    a = (inst >> 31)
    t1 = (1 << 32) - (1 << 12) if a == 1 else 0
    t2 = (((inst >> 8) & 0xF) << 1)
    t3 = (((inst >> 25) & 0x3F) << 5)
    t4 = (((inst >> 7) & 0x1) << 11)
    imm_b = t1 | t2 | t3 | t4
    imm_b -= 2 * ((imm_b >> 31) << 31)
    # end

    name = 'invalid_instruction'
    if opcode == 0b1100011:
        if funct3 == 0b000:
            name = 'beq'
        elif funct3 == 0b001:
            name = 'bne'
        elif funct3 == 0b100:
            name = 'blt'
        elif funct3 == 0b101:
            name = 'bge'
        elif funct3 == 0b110:
            name = 'bltu'
        elif funct3 == 0b111:
            name = 'bgeu'

    return 'B', name, rs1, imm_b, rs2

def parse_u_type(inst):
    opcode = inst & 0x7F
    rd = get_register_name((inst >> 7) & 0x1F)
    imm = (inst & ~((1 << 12) - 1))
    a = imm >> 31
    imm = ((a << 32) - (a << 20)) + (imm >> 12)

    name = 'invalid_instruction'
    if opcode == 0b0110111:
        name = 'lui'
    elif opcode == 0b0010111:
        name = 'auipc'

    return 'U', name, rd, imm

def parse_j_type(inst):
    opcode = inst & 0x7F
    rd = get_register_name((inst >> 7) & 0x1F)

    # imm calc
    a = inst >> 31
    t1 = (0 if a == 0 else ((1 << 12) - 1)<< 20)  # 31-20
    t2 = ((inst >> 21) & 0x3FF) << 1  
    t3 = (((inst >> 20) & 0x1) << 11)
    t4 = (((inst >> 12) & 0xFF) << 12)
    imm = t1 | t2 | t3 | t4
    imm -= 2 * ((imm >> 31) << 31)
    # end

    name = 'invalid_instruction'
    if opcode == 0b1101111:  # J-type
        name = "jal"

    return 'J', name, rd, imm

def get_text_entry(entry):
    inst = to_uint(entry)
    opcode = get_opcode(inst)
    optype = get_optype(opcode)
    if optype == 'R':
        return parse_r_type(inst)
    elif optype == 'I':
        return parse_i_type(inst)
    elif optype == 'S':
        return parse_s_type(inst)
    elif optype == 'B':
        return parse_b_type(inst)
    elif optype == 'U':
        return parse_u_type(inst)
    elif optype == 'J':
        return parse_j_type(inst)
    else:
        if opcode == 0b1110011:
            if (inst >> 20) == 0:
                return 'single', 'ecall'
            elif (inst >> 20) == 1:
                return 'single', 'ebreak'
            else:
                return 'single', 'invalid_instruction'
        elif opcode == 0b0001111:
            if (inst >> 7) == 0b1000001100110000000000000:
                return 'single', 'fense.tso'
            elif (inst >> 7) == 0b0000000100000000000000000:
                return 'single', 'pause'
            else:
                pred = pred_succ((inst >> 24) & 0b1111)
                succ = pred_succ((inst >> 20) & 0b1111)
                return 'fence', 'fence', pred, succ

def pred_succ(xxx):
    ans = ''
    if xxx & 0b1000:
        ans += 'i'
    if xxx & 0b0100:
        ans += 'o'
    if xxx & 0b0010:
        ans += 'r'
    if xxx & 0b0001:
        ans += 'w'
    return ans

def parse_text():
    global sections, elf

    text_index = names.index('.text')
    text = sections[text_index]

    start = text['offset']
    end = start + text['size']


    table = []
    while start < end:
        entry = elf[start:start + 4]
        # get_text_entry(entry)
        cmd = [start + (1 << 16), to_uint(entry)] + list(get_text_entry(entry))
        table.append(cmd)

        start += 4
    return table


def get_st_type(entry):
    type = ((entry['info']) & 0xf)
    return {
        0   :   'NOTYPE',
        1   :   'OBJECT',
        2   :   'FUNC',
        3   :   'SECTION',
        4   :   'FILE',
        5   :   'COMMON',
        6   :   'TLS',
        10  :   'LOOS',
        12  :   'HIOS',
        13  :   'LOPROC',
        15  :   'HIPROC'
    }.get(type, type)

def get_st_bind(entry):
    bind = ((entry['info']) >> 4)
    return {
        0   :   'LOCAL',
        1   :   'GLOBAL',
        2   :   'WEAK',
        10  :   'LOOS',
        12  :   'HIOS',
        13  :   'LOPROC',
        15  :   'HIPROC'
    }[bind]


def get_st_vis(entry):
    other = entry['other']
    vis = ((other)&0x3)
    return {
        0   :   'DEFAULT',
        1   :   'INTERNAL',
        2   :   'HIDDEN',
        3   :   'PROTECTED',
        4   :   'EXPORTED',
        5   :   'SINGLETON',
        6   :   'ELIMINATE'
    }[vis]

def get_st_index(entry):
    shndx = entry['shndx']
    return {
        0       :   'UNDEF',
        0xff00  :   'LORESERVE',
        0xff00  :   'LOPROC',
        0xff00  :   'BEFORE',
        0xff01  :   'AFTER',
        0xff02  :   'AMD64_LCOMMON',
        0xff1f  :   'HIPROC',
        0xff20  :   'LOOS',
        0xff3f  :   'LOSUNW',
        0xff3f  :   'SUNW_IGNORE',
        0xff3f  :   'HISUNW',
        0xff3f  :   'HIOS',
        0xfff1  :   'ABS',
        0xfff2  :   'COMMON',
        0xffff  :   'XINDEX',
        0xffff  :   'HIRESERVE'
    }.get(shndx, shndx)

def print_ans(labels, text, symtab, out):
    with open(out, "w") as file:
        printf('.text\n', file)
        for cmd in text:
            if cmd[0] in labels:
                printf("\n%08x \t<%s>:\n", file, cmd[0], labels[cmd[0]])

            if len(cmd) <= 2 or cmd[3] == 'invalid_instruction':
                printf("   %05x:\t%08x\t%-7s\n", file,
                        cmd[0], cmd[1], cmd[3])
            elif len(cmd) == 4:
                printf("   %05x:\t%08x\t%7s\n", file,
                       cmd[0], cmd[1], cmd[3])
            elif cmd[2] == 'fence':
                printf("   %05x:\t%08x\t%7s\t%s, %s\n", file,
                       cmd[0], cmd[1], cmd[2], cmd[4], cmd[5])
            elif cmd[2] == 'S' or cmd[2] == 'jalr' or cmd[2] == 'load':
                printf("   %05x:\t%08x\t%7s\t%s, %d(%s)\n", file,
                       cmd[0], cmd[1], cmd[3], cmd[4], cmd[6], cmd[5])
            elif cmd[2] == 'J':
                printf("   %05x:\t%08x\t%7s\t%s, 0x%x <%s>\n", file,
                       cmd[0], cmd[1], cmd[3], cmd[4], cmd[0] + cmd[5], labels.get(cmd[0] + cmd[5])) 
            elif cmd[2] == 'B':
                printf("   %05x:\t%08x\t%7s\t%s, %s, 0x%x, <%s>\n", file,
                      cmd[0], cmd[1], cmd[3], cmd[4], cmd[6],
                      cmd[0] + cmd[5], labels.get(cmd[0] + cmd[5]))
            elif len(cmd) == 6:
                printf("   %05x:\t%08x\t%7s\t%s, %s\n", file,
                        cmd[0], cmd[1], cmd[3], cmd[4], hex(cmd[5]))
            elif len(cmd) == 7:
                printf("   %05x:\t%08x\t%7s\t%s, %s, %s\n", file,
                        cmd[0], cmd[1], cmd[3], cmd[4], cmd[5], cmd[6])
                

        printf('\n\n.symtab\n', file)
        printf("\nSymbol Value              Size Type     Bind     Vis       Index Name\n", file)
        for i in range(len(symtab)):
            entry = symtab[i]
            printf("[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n", file,
                   i, entry['value'], entry['size'],
                   get_st_type(entry), get_st_bind(entry),
                   get_st_vis(entry), get_st_index(entry), 
                   entry['name'],
                )

def get_labels(text, symtab):
    labels = dict()
    for entry in symtab:
        if get_st_type(entry) == 'FUNC':
            labels[entry['value']] = entry['name']
    
    cnt = 0
    for cmd in text:
        if cmd[2] == 'J' or cmd[2] == 'B':
            value = cmd[0] + cmd[5]
            if value not in labels:
                labels[value] = 'L' + str(cnt)
                cnt += 1
    return labels


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python script <input_file> <output_file>")
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, 'rb') as file:
        elf = bytes_str_to_array(file.read().hex())
        
    header = read_header(elf)
    sections = get_sections(elf, header)
    names = get_sections_names()
    symtab = parse_symtab()
    text = parse_text()
    labels = get_labels(text, symtab)

    print_ans(labels, text, symtab, output_file)