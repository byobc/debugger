import sys
from serial import Serial
import serial.tools.list_ports
import serial_asyncio
import asyncio
import struct
from dataclasses import dataclass
from typing import Optional
from enum import Enum
import time
from disasm import AddrMode, DecodeError
import disasm
import dasm
import copy
import argparse

def update_crc(crc_accum: int, data: bytes) -> int:
    crc_table = [
        0x0000, 0x8005, 0x800F, 0x000A, 0x801B, 0x001E, 0x0014, 0x8011,
        0x8033, 0x0036, 0x003C, 0x8039, 0x0028, 0x802D, 0x8027, 0x0022,
        0x8063, 0x0066, 0x006C, 0x8069, 0x0078, 0x807D, 0x8077, 0x0072,
        0x0050, 0x8055, 0x805F, 0x005A, 0x804B, 0x004E, 0x0044, 0x8041,
        0x80C3, 0x00C6, 0x00CC, 0x80C9, 0x00D8, 0x80DD, 0x80D7, 0x00D2,
        0x00F0, 0x80F5, 0x80FF, 0x00FA, 0x80EB, 0x00EE, 0x00E4, 0x80E1,
        0x00A0, 0x80A5, 0x80AF, 0x00AA, 0x80BB, 0x00BE, 0x00B4, 0x80B1,
        0x8093, 0x0096, 0x009C, 0x8099, 0x0088, 0x808D, 0x8087, 0x0082,
        0x8183, 0x0186, 0x018C, 0x8189, 0x0198, 0x819D, 0x8197, 0x0192,
        0x01B0, 0x81B5, 0x81BF, 0x01BA, 0x81AB, 0x01AE, 0x01A4, 0x81A1,
        0x01E0, 0x81E5, 0x81EF, 0x01EA, 0x81FB, 0x01FE, 0x01F4, 0x81F1,
        0x81D3, 0x01D6, 0x01DC, 0x81D9, 0x01C8, 0x81CD, 0x81C7, 0x01C2,
        0x0140, 0x8145, 0x814F, 0x014A, 0x815B, 0x015E, 0x0154, 0x8151,
        0x8173, 0x0176, 0x017C, 0x8179, 0x0168, 0x816D, 0x8167, 0x0162,
        0x8123, 0x0126, 0x012C, 0x8129, 0x0138, 0x813D, 0x8137, 0x0132,
        0x0110, 0x8115, 0x811F, 0x011A, 0x810B, 0x010E, 0x0104, 0x8101,
        0x8303, 0x0306, 0x030C, 0x8309, 0x0318, 0x831D, 0x8317, 0x0312,
        0x0330, 0x8335, 0x833F, 0x033A, 0x832B, 0x032E, 0x0324, 0x8321,
        0x0360, 0x8365, 0x836F, 0x036A, 0x837B, 0x037E, 0x0374, 0x8371,
        0x8353, 0x0356, 0x035C, 0x8359, 0x0348, 0x834D, 0x8347, 0x0342,
        0x03C0, 0x83C5, 0x83CF, 0x03CA, 0x83DB, 0x03DE, 0x03D4, 0x83D1,
        0x83F3, 0x03F6, 0x03FC, 0x83F9, 0x03E8, 0x83ED, 0x83E7, 0x03E2,
        0x83A3, 0x03A6, 0x03AC, 0x83A9, 0x03B8, 0x83BD, 0x83B7, 0x03B2,
        0x0390, 0x8395, 0x839F, 0x039A, 0x838B, 0x038E, 0x0384, 0x8381,
        0x0280, 0x8285, 0x828F, 0x028A, 0x829B, 0x029E, 0x0294, 0x8291,
        0x82B3, 0x02B6, 0x02BC, 0x82B9, 0x02A8, 0x82AD, 0x82A7, 0x02A2,
        0x82E3, 0x02E6, 0x02EC, 0x82E9, 0x02F8, 0x82FD, 0x82F7, 0x02F2,
        0x02D0, 0x82D5, 0x82DF, 0x02DA, 0x82CB, 0x02CE, 0x02C4, 0x82C1,
        0x8243, 0x0246, 0x024C, 0x8249, 0x0258, 0x825D, 0x8257, 0x0252,
        0x0270, 0x8275, 0x827F, 0x027A, 0x826B, 0x026E, 0x0264, 0x8261,
        0x0220, 0x8225, 0x822F, 0x022A, 0x823B, 0x023E, 0x0234, 0x8231,
        0x8213, 0x0216, 0x021C, 0x8219, 0x0208, 0x820D, 0x8207, 0x0202
    ]

    for b in data:
        i = ((crc_accum >> 8) ^ b) & 0xFF;
        i %= 256
        crc_accum = ((crc_accum << 8) & 0xFF00) ^ crc_table[i];

    return crc_accum

CMD_PING = b'\x01'
CMD_WRITE_EEPROM = b'\x02'
CMD_READ_MEMORY = b'\x03'
CMD_SET_BREAKPOINT = b'\x04'
CMD_RESET_CPU = b'\x05'
CMD_GET_BUS_STATE = b'\x06'
CMD_STEP = b'\x07'
CMD_STEP_CYCLE = b'\x08'
CMD_STEP_HALF_CYCLE = b'\x09'
CMD_CONTINUE = b'\x0A'
CMD_HIT_BREAKPOINT = b'\x0B'
CMD_PRINT_INFO = b'\x0C'
CMD_GET_CPU_STATE = b'\x0D'
CMD_ENTER_FAST_MODE = b'\x0E'
CMD_DEBUGGER_RESET = b'\x0F'
CMD_SECTOR_ERASE = b'\x10'
CMD_ACK = b'\x11'
CMD_ERROR = b'\x12'
CMD_PRINT = b'\x13'

@dataclass
class CpuState:
    addr: int
    data: int

    pc: int
    a:  int
    x:  int
    y:  int
    s:  int
    p:  int

    rwb:  bool
    sync: bool
    vpb:  bool
    phi2: bool

    in_rst: bool
    in_nmi: bool
    in_irq: bool

    error: bool

    mode: int
    oper: int
    seq_cycle: int

    @classmethod
    def from_bytes(cls, b: bytes):
        assert(len(b) == 16)

        addr = int.from_bytes(b[ 0: 2], 'little')
        pc   = int.from_bytes(b[ 2: 4], 'little')
        data = int.from_bytes(b[ 4: 5], 'little')
        a    = int.from_bytes(b[ 5: 6], 'little')
        x    = int.from_bytes(b[ 6: 7], 'little')
        y    = int.from_bytes(b[ 7: 8], 'little')
        s    = int.from_bytes(b[ 8: 9], 'little')
        p    = int.from_bytes(b[ 9:10], 'little')

        status = int.from_bytes(b[10:11], 'little')

        rwb    = (status & (1 << 0)) != 0
        sync   = (status & (1 << 1)) != 0
        vpb    = (status & (1 << 2)) != 0
        phi2   = (status & (1 << 3)) != 0
        in_rst = (status & (1 << 4)) != 0
        in_nmi = (status & (1 << 5)) != 0
        in_irq = (status & (1 << 6)) != 0
        error  = (status & (1 << 7)) != 0

        mode = int.from_bytes(b[13:14], 'little')
        oper = int.from_bytes(b[14:15], 'little')
        seq_cycle = int.from_bytes(b[15:16], 'little')

        return cls(addr, data, pc, a, x, y, s, p, rwb, sync, vpb, phi2, in_rst, in_nmi, in_irq, error, mode, oper, seq_cycle)

@dataclass
class BusState:
    addr: int
    data: int

    mlb:   bool
    irqb:  bool
    rdy:   bool
    vpb:   bool
    gpio1: bool
    we:    bool
    rwb:   bool
    be:    bool
    phi2:  bool
    resb:  bool
    sync:  bool
    nmib:  bool

    @classmethod
    def from_bytes(cls, b: bytes):
        assert(len(b) == 6)

        addr = int.from_bytes(b[0:2], 'little')
        status = int.from_bytes(b[2:4], 'little')
        data = int.from_bytes(b[4:5], 'little')

        return cls(
            addr=addr,
            data=data,

            mlb  =(status & 0x8000) != 0,
            irqb =(status & 0x4000) != 0,
            rdy  =(status & 0x2000) != 0,
            vpb  =(status & 0x1000) != 0,
            gpio1=(status & 0x0200) != 0,
            we   =(status & 0x0100) != 0,
            rwb  =(status & 0x0020) != 0,
            be   =(status & 0x0010) != 0,
            phi2 =(status & 0x0008) != 0,
            resb =(status & 0x0004) != 0,
            sync =(status & 0x0002) != 0,
            nmib =(status & 0x0001) != 0,
        )

class InvalidHeader(Exception):
    pass

class PortWrapper:
    def __init__(self, port: Serial, timeout: float):
        self.port = port
        self.timeout = timeout

        assert(self.port.timeout == 0.0)

    def read_nonblocking(self, count: int):
        return self.port.read(count)
    
    def read(self, count: int):
        assert(count >= 0)

        result = b''

        start_time = time.monotonic()
        while time.monotonic() - start_time < self.timeout and len(result) != count:
            result += self.read_nonblocking(count)

        return result
    
    def read_exact(self, count: int):
        result = self.read(count)
        if len(result) != count:
            raise TimeoutError
        return result
    
    def write(self, data: bytes):
        self.port.write(data)

class DebuggerIo:
    def __init__(self):
        self.h2d_queue = asyncio.Queue()
        self.d2h_queue = asyncio.Queue()

        self.acks = asyncio.Semaphore(value=0)
    
    async def begin(self, port):
        self.reader, self.writer = await serial_asyncio.open_serial_connection(url=port, baudrate=115200)

        async with asyncio.TaskGroup() as tg:
            tx = tg.create_task(self._tx_handler())
            rx = tg.create_task(self._rx_handler())
    
    async def run_cmd(self, ty, cmd):
        await self.d2h_queue.put((ty, cmd))
        reply_ty, reply_body = await self.h2d_queue.get()
        if reply_ty == CMD_ERROR:
            raise Exception(f'error {ty} {cmd} -> {reply_ty} {reply_body}')
        elif reply_ty != ty:
            raise Exception(f'mismatch {ty} {cmd} -> {reply_ty} {reply_body}')
        return reply_body
    
    async def _tx_handler(self):
        ty, body = await self.h2d_queue.get()
        self.writer.write(struct.pack('<ccH', b'%', ty, len(body)))
        await self.acks.acquire()
        if len(body) > 0:
            self.writer.write(body)
            await self.acks.acquire()

    async def _rx_handler(self):
        while True:
            magic = await self.reader.read(1)
            if magic == b'%':
                break
        ty = await self.reader.readexactly(1)
        length = int.from_bytes(await self.reader.readexactly(2), 'little')
        body = await self.reader.readexactly(length)
        if ty == CMD_ACK:
            self.acks.release()
        elif ty == CMD_PRINT:
            print('DEBUGGER MSG: ', body)
        elif ty == CMD_HIT_BREAKPOINT:
            print('HIT BREAKPOINT: ', body)
        else:
            await self.d2h_queue.put((ty, body))


EEPROM_PAGE_BITS = 6
EEPROM_PAGE_SIZE = (1 << EEPROM_PAGE_BITS)
EEPROM_PAGE_MASK = (EEPROM_PAGE_SIZE - 1)

EEPROM_SECTOR_BITS = 12
EEPROM_SECTOR_SIZE = (1 << EEPROM_SECTOR_BITS)
EEPROM_SECTOR_MASK = (EEPROM_SECTOR_SIZE - 1)

@dataclass
class VersionInfo:
    year: int
    month: int
    day: int

    def __str__(self):
        return f'{self.year:04}-{self.month:02}-{self.day:02}'

class Debugger:
    def __init__(self):
        self.io = DebuggerIo()
    
    async def begin(self, port):
        await self.io.begin(port)
    
    async def ping(self) -> bytes:
        return await self.io.run_cmd(CMD_PING, b'')
    
    async def print_info(self) -> VersionInfo:
        data = await self.io.run_cmd(CMD_PRINT_INFO, b'')
        year  = int.from_bytes(data[0:2], 'little')
        month = int.from_bytes(data[2:3], 'little')
        day   = int.from_bytes(data[3:4], 'little')
        return VersionInfo(year, month, day)

    async def _raw_page_write(self, page: int, data: bytes):
        assert page & EEPROM_PAGE_MASK == 0, f'misaligned page {page:04X}'
        assert len(data) == EEPROM_PAGE_SIZE

        data = page.to_bytes(2, 'little') + data
        checksum = update_crc(0, data)
        data = data + checksum.to_bytes(2, 'little')

        await self.io.run_cmd(CMD_WRITE_EEPROM, data)

    async def page_write(self, page: int, data: bytes):
        await self._raw_page_write(page, data)
        await asyncio.sleep(0.015)
        written = await self.read(page, len(data))
        if data != written:
            print('Data mismatch')

            print('(first 32 bytes)')
            print('tried to write: ', end='')
            for d in data[:32]:
                print(f'{d:02X} ', end='')
            print()
            print('but read back:  ', end='')
            for d in written[:32]:
                print(f'{d:02X} ', end='')
            print()
            print('                ', end='')
            for d, w in zip(data[:32], written[:32]):
                if d != w:
                    print('^^ ', end='')
                else:
                    print('   ', end='')
            print()
            print()
            
            print('(last 32 bytes)')
            print('tried to write: ', end='')
            for d in data[32:][:32]:
                print(f'{d:02X} ', end='')
            print()
            print('but read back:  ', end='')
            for d in written[32:][:32]:
                print(f'{d:02X} ', end='')
            print()
            print('                ', end='')
            for d, w in zip(data[32:][:32], written[32:][:32]):
                if d != w:
                    print('^^ ', end='')
                else:
                    print('   ', end='')
            print()
            raise Exception('data mismatch')

    async def sector_erase(self, sector: int):
        await self.io.run_cmd(CMD_SECTOR_ERASE, struct.pack('<H', sector))
    
    async def read(self, addr: int, length: int):
        return await self.io.run_cmd(CMD_READ_MEMORY, struct.pack('<HH', addr, length))
    
    async def set_breakpoint(self, addr: int):
        assert(addr <= 0xFFFF)

        bkpt_num = await self.io.run_cmd(CMD_SET_BREAKPOINT, struct.pack(b'<H', addr))
        if bkpt_num == b'\xFF':
            raise Exception('Too many breakpoints')
        print(f'Set breakpoint {bkpt_num - 1} at address ${addr:04X}')
    
    async def enter_fast_mode(self):
        await self.io.run_cmd(CMD_ENTER_FAST_MODE, b'')

    async def reset_cpu(self):
        await self.io.run_cmd(CMD_RESET_CPU, b'')
    
    async def self_reset(self):
        await self.io.run_cmd(CMD_DEBUGGER_RESET, b'')
    
    async def get_bus_state(self) -> BusState:
        return BusState.from_bytes(await self.io.run_cmd(CMD_GET_BUS_STATE, b''))
    
    async def get_cpu_state(self) -> CpuState:
        return CpuState.from_bytes(await self.io.run_cmd(CMD_GET_CPU_STATE, b''))
    
    def poll_breakpoint(self):
        # TODO:
        return None
    
    async def step(self):
        while True:
            self.poll_breakpoint()
            await self.step_half_cycle()
            self.poll_breakpoint()
            state = await self.get_cpu_state()
            if state.sync and state.phi2:
                break
        
    async def step_half_cycle(self):
        await self.io.run_cmd(CMD_STEP_HALF_CYCLE, b'')
    
    async def step_cycle(self):
        await self.step_half_cycle()
        state = await self.get_cpu_state()
        if state.phi2:
            return
        await self.step_half_cycle()
    
    async def cont(self):
        await self.io.run_cmd(CMD_CONTINUE, b'')

def are_different_or_none(lhs, rhs):
    if lhs is None:
        return False
    if rhs is None:
        return False
    return lhs != rhs

def byte_to_signed(b: int):
    return int.from_bytes(b.to_bytes(1, 'little'), 'little', signed=True)

def infer_port(default):
    if default is not None:
        print(f'Using explicit serial port {default}')
        return default
        
    for port in serial.tools.list_ports.comports():
        if port.vid == 0x1A86 and port.pid == 0x55D2:
            if sys.platform.startswith('win'):
                # I don't know why this is the case either
                if port.location is None:
                    print(f'Using serial port {port.device}')
                    return port.device
            elif sys.platform.startswith('darwin'):
                # First port ends in 1, second port ends in 3
                if port.device.endswith('1'):
                    print(f'Using serial port {port.device}')
                    return port.device
            else:
                print('Cannot guess port on Linux, too bad')
                break
    
    raise Exception('Failed to find serial port, try specifying with --port')
    


def do_deploy_bin(args):
    return do_deploy(args, is_bin=True)
    
async def do_deploy(args, is_bin=False):
    if is_bin:
        if args.file.lower().endswith('.s'):
            print('Warning: .S files usually are text, not binary, and should not be used with --bin!')
            response = input("Are you sure you want to flash this file? (y/n): ")
            response = response.strip().lower()
            if response != 'y':
                print('Canceled')
                return

        with open(args.file, 'rb') as f:
            bin_data = f.read()
        chunks = dasm.get_chunks(bin_data)
    else:
        try:
            output = dasm.AssembledFile.from_src(args.dasm, args.file, args.out_dir)
            chunks = output.chunks
        except dasm.AssemblerError:
            print(f'Encountered errors while assembling file')
            sys.exit(1)

    print('Connecting to debugger')
    dbg = Debugger()
    await dbg.open(infer_port(args.port))
    try:
        print(f'Firmware version: {dbg.print_info()}')
        print('Successfully connected to debugger!')
    except TimeoutError:
        try:
            print(f'Firmware version: {dbg.print_info()}')
            print('Successfully connected to debugger')
        except TimeoutError:
            print('Timed out while trying to connect to debugger')
            return

    bad_chunks = []
    for chunk in chunks:
        if not (0 <= chunk.base_addr <= 0xFFFF):
            raise Exception(f'Invalid chunk address {chunk.base_addr}')
        if chunk.base_addr < 0x8000:
            bad_chunks.append(chunk)

    if len(bad_chunks) != 0:
        print('Warning: found chunks that were outside of the normal EEPROM range!')
        for chunk in bad_chunks:
            print(f'  {chunk.base_addr:04X}')

        print("This normally means you're trying to flash something that isn't a binary,")
        print("or you've accidentally included your variables in the output.")
        response = input("Do you want to continue? (y/n): ")
        response = response.strip().lower()
        if response != 'y':
            print('Canceled')
            return

    print('Flashing EEPROM')
    total_pages = sum((len(c.data) + EEPROM_PAGE_SIZE - 1) // EEPROM_PAGE_SIZE for c in chunks)
    print(f'Need to flash {total_pages} pages')

    for i, chunk1 in enumerate(chunks):
        for chunk2 in chunks[i + 1:]:
            c1_start = chunk1.base_addr // EEPROM_PAGE_SIZE
            c1_end = (chunk1.base_addr + len(chunk1.data) + EEPROM_PAGE_SIZE - 1) // EEPROM_PAGE_SIZE

            c2_start = chunk2.base_addr // EEPROM_PAGE_SIZE
            c2_end = (chunk2.base_addr + len(chunk2.data) + EEPROM_PAGE_SIZE - 1) // EEPROM_PAGE_SIZE

            if max(c1_start, c2_start) <= min(c1_end, c2_end):
                raise Exception('TODO: Overlapping chunks')
    
    print('Erasing')

    sectors = dict()
    for chunk in chunks:
        base_sector_addr = chunk.base_addr // EEPROM_SECTOR_SIZE 
        end_sector_addr = (chunk.base_addr + len(chunk.data) + EEPROM_SECTOR_SIZE - 1) // EEPROM_SECTOR_SIZE
        if base_sector_addr not in sectors or end_sector_addr > sectors[base_sector_addr]:
            sectors[base_sector_addr] = end_sector_addr
    
    for base, end in sectors.items():
        for i in range(base, end):
            await dbg.sector_erase(base * EEPROM_SECTOR_SIZE)
            await asyncio.sleep(0.1)
            print('.', end='', flush=True)
    print()

    print('Flashing')
    
    for chunk in chunks:
        base_addr = chunk.base_addr & ~EEPROM_PAGE_MASK
        data = copy.copy(chunk.data)
        if chunk.base_addr & EEPROM_PAGE_MASK != 0:
            data = b'\xFF' * (chunk.base_addr & EEPROM_PAGE_MASK) + data
        while len(data) & EEPROM_PAGE_MASK != 0:
            data = data + b'\xFF'
        
        for page in range(0, len(data), EEPROM_PAGE_SIZE):
            await dbg.page_write(base_addr + page, data[page:][:EEPROM_PAGE_SIZE])
            print('.', end='', flush=True)
    print()

    print('Resetting debugger...')
    
    await dbg.self_reset()

    print('Done!')


    pass

async def do_debug(args):
    try:
        with open('asm.lst', 'r') as f:
            lst_data = f.read()
        listing = dasm.Listing(lst_data)
    except Exception:
        listing = None
        print('Could not open listing file asm.lst')
    
    try:
        with open('asm.sym', 'r') as f:
            sym_data = f.read()
        symbol_table = dasm.SymbolTable(sym_data)
    except Exception:
        symbol_table = None
        print('Could not open symbol table asm.sym')
    
    if listing is not None and symbol_table is not None:
        print(f'Loaded debug info for file {listing.file_name}')

    print('Connecting to debugger')
    dbg = Debugger.open(infer_port(args.port))
    try:
        print(f'Firmware version: {await dbg.print_info()}')
        print('Successfully connected to debugger!')
    except TimeoutError:
        try:
            print(f'Firmware version: {await dbg.print_info()}')
            print('Successfully connected to debugger')
        except TimeoutError:
            print('Timed out while trying to connect to debugger')
            return

    await dbg.reset_cpu()

    last_cmd = ''

    free_running = False
    walking = False
    while True:
        if free_running:
            try:
                while True:
                    if walking:
                        await dbg.step_half_cycle()

                    which_breakpoint = dbg.poll_breakpoint()

                    if which_breakpoint is not None:
                        if which_breakpoint == 0xFF:
                            print(f'CPU encountered error, stopping')
                        else:
                            print(f'Hit breakpoint {which_breakpoint}, stopping')
                        break
                    
                    await asyncio.sleep(0.1)
            except KeyboardInterrupt:
                print('Keyboard interrupt, stopping')
                await dbg.step_half_cycle()
            
            free_running = False
            walking = False

        state = await dbg.get_bus_state()
        cpu_state = await dbg.get_cpu_state()

        if cpu_state.pc is not None and listing is not None:
            for line in listing.neighborhood(cpu_state.pc):
                print(f'${line.address:04X} {line.line_number:6}: ', end='')
                if cpu_state.pc == line.address:
                    print(' -> ', end='')
                else:
                    print('    ', end='')
                print(line.source)


        print()
        if cpu_state.in_rst:
            print('RST')
        elif cpu_state.in_nmi:
            print('NMI')
        elif cpu_state.in_irq:
            print('IRQ')

        print(f'PC: {cpu_state.pc:04X}  A: {cpu_state.a:02X} X: {cpu_state.x:02X} Y: {cpu_state.y:02X} P: {cpu_state.p:02X} S: {cpu_state.s:02X} seq_cycle: {cpu_state.seq_cycle}')
        print(f'ADDR: {cpu_state.addr:04X}')
        print(f'DATA:   {cpu_state.data:02X}')
        print(f'STATUS: ', end='')
        print('SYNC:1 ' if cpu_state.sync else 'sync:0 ', end='')
        print('rwb:1 (R) ' if cpu_state.rwb else 'RWB:0 (W)', end='')
        print('resb:1 ' if state.resb else 'RESB:0 ', end='')
        print('nmib:1 ' if state.nmib else 'NMIB:0 ', end='')
        print('irqb:1 ' if state.irqb else 'IRQB:0 ', end='')
        print('vpb:1 ' if cpu_state.vpb  else 'VPB:0 ', end='')
        print('   |   ', end='')
        print(f'PHI2: {+cpu_state.phi2}')
        print()

        if cpu_state.error:
            print('ERROR')

        '''
        print()
        print(dbg.cpu.display())
        print(f'ADDR: {state.addr:04X}')
        print(f'DATA:   {state.data:02X}')
        print(f'STATUS: ', end='')
        print('SYNC:1 ' if state.sync else 'sync:0 ', end='')
        print('rwb:1 (R) ' if state.rwb else 'RWB:0 (W)', end='')
        print('resb:1 ' if state.resb else 'RESB:0 ', end='')
        print('nmib:1 ' if state.nmib else 'NMIB:0 ', end='')
        print('irqb:1 ' if state.irqb else 'IRQB:0 ', end='')
        print('vpb:1 ' if state.vpb  else 'VPB:0 ', end='')
        print('   |   ', end='')
        print(f'PHI2: {+state.phi2}')
        print()
        '''

        input_queue = asyncio.Queue()

        def get_input():
            while True:
                input_queue.put_nowait(input(''))
        
        await asyncio.to_thread(get_input)

        print('> ', end='')
        cmd = await input_queue.get()
        if cmd != '':
            last_cmd = cmd

        try:
            cmd, *args = last_cmd.split()
        except ValueError:
            print('empty command')
            continue

        try:
            if cmd in ('reload_cpu_state', ):
                pass
            elif cmd in ('s', 'step'):
                free_running = False
                dbg.poll_breakpoint()
                await dbg.step()
            elif cmd in ('h', 'stephalf'):
                free_running = False
                dbg.poll_breakpoint()
                await dbg.step_half_cycle()
            elif cmd in ('y', 'stepcycle'):
                free_running = False
                dbg.poll_breakpoint()
                await dbg.step_cycle()
            elif cmd in ('c', 'continue'):
                free_running = True
                await dbg.cont()
            elif cmd in ('w', 'walk'):
                free_running = True
                walking = True
            elif cmd in ('q'):
                break
            elif cmd in ('r', 'reset'):
                await dbg.reset_cpu()
            elif cmd in ('b', 'break'):
                if len(args) > 1:
                    print('Too many arguments')
                elif len(args) == 0:
                    print('Must specify a line number, symbol, or address to set a breakpoint at')
                else:
                    loc = args[0]
                    if loc.startswith('$'):
                        addr = int(loc[1:], base=16)
                        await dbg.set_breakpoint(addr)
                    elif listing is not None:
                        assert(symbol_table is not None)
                        if loc in symbol_table.symbols:
                            addr = symbol_table.symbols[loc]
                        else:
                            line_number = int(loc)
                            addr = listing.line_to_addr(line_number)
                        if addr is not None:
                            await dbg.set_breakpoint(addr)
                        else:
                            print('No such line or symbol in file')
                    else:
                        print('Cannot set breakpoint on line without source info (provide a listing file)')
            elif cmd in ('f', 'fast'):
                await dbg.enter_fast_mode()
                print('Entered fast mode, press reset button to debug again')
                break
            else:
                print(f'Unknown command {repr(cmd)}')
        except ValueError as e:
            print(f'Error while executing command: {e}')
    
    print('Debugger exited')

def main():
    parser = argparse.ArgumentParser(
        prog='debugger.py',
        description='Connects to an external 98-341 debugger',
    )

    subparsers = parser.add_subparsers(help='Action to take', required=True)

    parser_deploy = subparsers.add_parser('deploy', help='Assemble and upload a new program')
    parser_deploy.add_argument('--port', help='Path to the debugger port')
    parser_deploy.add_argument('--dasm', help='Path to the dasm executable', default='dasm/dasm')
    parser_deploy.add_argument('file', help='Path to the assembly file')
    parser_deploy.add_argument('--out-dir', help='Path to place the assembled files', default='./')
    parser_deploy.set_defaults(func=do_deploy)

    parser_deploy_bin = subparsers.add_parser('deploy-bin', help='Upload an already-assembled program')
    parser_deploy_bin.add_argument('--port', help='Path to the debugger port')
    parser_deploy_bin.add_argument('file', help='Path to the binary file')
    parser_deploy_bin.set_defaults(func=do_deploy_bin)

    parser_debug = subparsers.add_parser('debug', help='Run and debug code')
    parser_debug.add_argument('--port', help='Path to the debugger port')
    parser_debug.set_defaults(func=do_debug)

    args = parser.parse_args()

    asyncio.run(args.func(args))

    return

if __name__ == '__main__':
    main()