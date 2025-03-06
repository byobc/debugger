#pragma once

#include "sim.h"
#include <stdint.h>

struct BusState {
	uint16_t addr;
	bus_status_t status;
	uint8_t data;
	uint8_t _padding;
};

struct CpuState {
	uint16_t addr;
	uint16_t pc;
	uint8_t data;
	uint8_t a;
	uint8_t x;
	uint8_t y;
	uint8_t s;
	uint8_t p;
	uint8_t status; // from LSB to MSB: rwb, sync, vpb, phi2
	uint8_t _padding[2];
	uint8_t mode;
	uint8_t oper;
	uint8_t seq_cycle;
};

enum class CommandType : uint8_t {
	Ping = 0x1,
	WriteEEPROM = 0x2,
	ReadMemory = 0x3,
	SetBreakpoint = 0x4,
	ResetCpu = 0x5,
	GetBusState = 0x6,
	Step = 0x7,
	StepCycle = 0x8,
	StepHalfCycle = 0x9,
	Continue = 0xA,
	HitBreakpoint = 0xB,
	PrintInfo = 0xC,
	GetCpuState = 0xD,
	EnterFastMode = 0xE,
	DebuggerReset = 0xF,
	SectorErase = 0x10,
	Ack = 0x11,
	Error = 0x12,
	Print = 0x13,
	MAX_CMD
};

struct WriteEEPROMCmd {
	uint16_t addr;
	uint8_t data[64];
	uint16_t checksum;
};

struct ReadMemoryCmd {
	uint16_t addr;
	uint16_t len;
};

struct SetBreakpointCmd {
	uint16_t addr;
};

struct HitBreakpointCmd {
	uint8_t which;
};

struct SectorEraseCmd {
	uint16_t addr;
};

union Command {
	WriteEEPROMCmd write_eeprom;
	ReadMemoryCmd read_memory;
	SetBreakpointCmd set_breakpoint;
	SectorEraseCmd sector_erase;
} body;

#define ERR_NO_CMD -1
#define ERR_BAD_CMD -2
#define ERR_BAD_ADDR -3
#define ERR_BAD_CHECKSUM -4
#define ERR_NAK -5

void send_header(CommandType ty, uint16_t len);

inline void send_packet(CommandType ty) {
	send_header(ty, 0);
}

void send_packet(CommandType ty, const uint8_t *body, uint16_t len);

template< typename T >
void send_packet(CommandType ty, const T& body) {
	send_packet(ty, (const uint8_t *)body, sizeof(T));
}

int recv_packet(CommandType &ty, uint8_t *buf, uint16_t *len);

void print_debug(const char *s, size_t len);

void hit_breakpoint(uint8_t which);

#define print_lit(STR) print_debug("" STR "", sizeof(STR)-1)