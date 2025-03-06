#include "pins.h"
#include "led.h"
#include "i2c.h"
#include "uart.h"
#include "message.h"
#include "gpio.h"
#include "version.h"
#include "programmer.h"

#include "physicalw65c02.h"

#include <Arduino.h>

// LedDriver LED_DRIVER;

using gpio::status_t;

static void delay_loop(int amount) {
  volatile int i = 0;
  for (i = 0; i < amount; ++i);
}

void delay_millis(int millis) {
  delay_loop(millis * 12);
}

#define USED_PINS (8 + 8 + 4 + 4 + 6)

int8_t test_bridged_pins() {
  PORT_t* BASE_PORTS[5] = { &PORTA, &PORTD, &PORTE, &PORTF, &PORTB };
  int8_t NUM_BITS[5] = { 8, 8, 4, 4, 6 };

  PORT_t* PORTS[USED_PINS];
  int8_t  BITS[USED_PINS];

  int8_t port_idx = 0;
  int8_t bit = 0;
  for (int8_t i = 0; i < USED_PINS; ++i) {
    PORTS[i] = BASE_PORTS[port_idx];
    BITS[i] = bit;

    ++bit;
    if (bit == NUM_BITS[port_idx]) {
      ++port_idx;
      bit = 0;
    }
  }

  // Ensure all pins have pullups
  for (int8_t i = 0; i < USED_PINS; ++i) {
    *(register8_t*)(((intptr_t)&PORTS[i]->PIN0CTRL) + BITS[i]) |= 0b1000;
  }
  
  int8_t bad_pin = -1;

  for (int8_t i = 0; i < USED_PINS; ++i) {
    // First, ensure all other pins are outputs driving low 
    PORTA.DIRSET = 0xFF;
    PORTD.DIRSET = 0xFF;
    PORTE.DIRSET = 0x0F;
    PORTF.DIRSET = 0x0F;
    PORTB.DIRSET = 0x1F;

    PORTA.OUTCLR = 0xFF;
    PORTD.OUTCLR = 0xFF;
    PORTE.OUTCLR = 0x0F;
    PORTF.OUTCLR = 0x0F;
    PORTB.OUTCLR = 0xFF;
    
    // Now set exactly one pin to an input with a pullup
    PORTS[i]->DIRCLR = (1 << BITS[i]);

    // Wait for the voltage to stabilize...
    delay_loop(10000);

    // Make sure the pin isn't being pulled low by being bridged to another pin
    bool ok = (PORTS[i]->IN >> BITS[i]) & 0x1;

    if (!ok) {
      bad_pin = i;
      break;
    }
  }

  // Set all pins to be inputs again
  PORTA.DIRCLR = 0xFF;
  PORTD.DIRCLR = 0xFF;
  PORTE.DIRCLR = 0xFF;
  PORTB.DIRCLR = 0x1F;

  // Disable pullups for all pins again
  for (int8_t i = 0; i < USED_PINS; ++i) {
    *(register8_t*)(((intptr_t)&PORTS[i]->PIN0CTRL) + BITS[i]) |= 0b1000;
  }

  return bad_pin;

  // PORTA pins (all)
  // PORTD pins (all)
  // PORTE pins (all)
  // PORTB pins 0..=5
}

void setup_pin_directions() {
  NMIB_PORT.OUTSET = NMIB_PIN_MASK;
  RESB_PORT.OUTCLR = RESB_PIN_MASK;
  PHI2_PORT.OUTCLR = PHI2_PIN_MASK;
  BE_PORT.OUTSET = BE_PIN_MASK;
  WE_PORT.OUTSET = WE_PIN_MASK;

  NMIB_PORT.DIRSET = NMIB_PIN_MASK;
  RESB_PORT.DIRSET = RESB_PIN_MASK;
  PHI2_PORT.DIRSET = PHI2_PIN_MASK;
  BE_PORT.DIRSET = BE_PIN_MASK;
  WE_PORT.DIRSET = WE_PIN_MASK;

  // Enable pull-up on RDY
  RDY_PORT.PIN5CTRL |= 0b1000;

  IRQB_PORT.PIN6CTRL |= 0b1000;

  PORTA.PIN2CTRL |= 0b1000;
  PORTA.PIN3CTRL |= 0b1000;
}

#define TEST_PINS false


#define MAX_BREAKPOINTS 16

struct Breakpoint {
  uint16_t addr;
  bool enabled;
};

static Breakpoint BREAKPOINTS[MAX_BREAKPOINTS];
static int8_t NUM_BREAKPOINTS = 0;

// Returns the index of the breakpoint we hit, or -1 if no breakpoint was hit.
int has_hit_enabled_breakpoint(uint16_t addr) {
  for (int8_t i = 0; i < NUM_BREAKPOINTS; ++i) {
    if (BREAKPOINTS[i].addr == addr && BREAKPOINTS[i].enabled) {
      return i;
    }
  }

  return -1;
}

#define STEP

int update_cnt = 0;

void sw_reset() {
  CCP = 0xD8;
  RSTCTRL.SWRR = 1;
}

enum class Action {
  None,
  StepHalfCycle,
  StepCycle,
  Step,
  Continue,
  EnterFastMode,
  Stop,
};

enum class Wait {
  None,
  HalfCycle,
  Cycle,
  Sync
};

static Wait WAIT = Wait::HalfCycle;

Action handle_commands(PhysicalW65C02 &cpu, bool phi2) {
  CommandType ty;
  Command cmd;
  while (true) {
    uint16_t msg_len = sizeof(cmd);
    int result = recv_packet(ty, (uint8_t *)&cmd, &msg_len);
    if (result == ERR_NO_CMD) {
      return Action::None;
    } else if (result != 0) {
      send_packet(CommandType::Error);
      continue;
    }

    switch (ty) {
    case CommandType::Ping:
      send_packet(CommandType::Ping, (const uint8_t *)"Pong!", 5);
      break;
    case CommandType::WriteEEPROM:
      gpio::set_addr_bus_mode(gpio::AddressBusMode::DebuggerDriven);
      gpio::set_data_bus_dir(gpio::Direction::Output);

      for (int i = 0; i < 64; ++i) {
        programmer::byte_program(cmd.write_eeprom.addr + i, cmd.write_eeprom.data[i]);
      }

      send_packet(CommandType::WriteEEPROM);
      return Action::Stop;
    case CommandType::SectorErase:
      gpio::set_addr_bus_mode(gpio::AddressBusMode::DebuggerDriven);
      gpio::set_data_bus_dir(gpio::Direction::Output);

      programmer::sector_erase(cmd.sector_erase.addr);

      send_packet(CommandType::SectorErase, nullptr, 0);
      break;
    case CommandType::ReadMemory:
      gpio::write_we(true);
      gpio::set_addr_bus_mode(gpio::AddressBusMode::DebuggerDriven);
      gpio::set_data_bus_dir(gpio::Direction::Input);

      delay_loop(5);

      send_header(CommandType::ReadMemory, cmd.read_memory.len);
      for (uint16_t i = 0; i < cmd.read_memory.len; ++i) {
        uint16_t addr = i + cmd.read_memory.addr;

        gpio::write_addr_bus(addr);
        delay_loop(5);
        uint8_t data = gpio::read_data_bus();
        uart::put(data);
      }

      gpio::set_data_bus_dir(gpio::Direction::Input);
      gpio::set_addr_bus_mode(gpio::AddressBusMode::CpuDriven);
      break;
    case CommandType::SetBreakpoint:
      if (NUM_BREAKPOINTS == MAX_BREAKPOINTS) {
        const uint8_t err = 0xFF;
        send_packet(CommandType::SetBreakpoint, &err, 1);
        break;
      }

      BREAKPOINTS[NUM_BREAKPOINTS].addr = cmd.set_breakpoint.addr;
      BREAKPOINTS[NUM_BREAKPOINTS].enabled = true;
      ++NUM_BREAKPOINTS;
      send_packet(CommandType::SetBreakpoint, (const uint8_t *)&NUM_BREAKPOINTS, 1);
      break;
    case CommandType::ResetCpu:
      RESB_PORT.OUTCLR = RESB_PIN_MASK;
      WAIT = Wait::HalfCycle;
      cpu.error = false;
      cpu.mode = physicalw65c02::Mode::IMPLIED;
      cpu.oper = physicalw65c02::Oper::W65C02S_OPER_NOP;
      send_packet(CommandType::ResetCpu);
      break;
    case CommandType::GetBusState: {
      BusState state = {
        gpio::read_addr_bus(),
        gpio::read_status(),
        gpio::read_data_bus(),
        0
      };

      send_packet(CommandType::GetBusState, state);
      break;
    }
    case CommandType::StepHalfCycle: {
      send_packet(CommandType::StepHalfCycle);
      return Action::StepHalfCycle;
    }
    case CommandType::StepCycle: {
      send_packet(CommandType::StepCycle);
      return Action::StepCycle;
    }
    case CommandType::Step: {
      send_packet(CommandType::Step);
      return Action::Step;
    }
    case CommandType::Continue: {
      send_packet(CommandType::Continue);
      return Action::Continue;
    }
    case CommandType::PrintInfo: {
      send_packet(CommandType::PrintInfo, VERSION);
      break;
    }
    case CommandType::GetCpuState: {
      physicalw65c02::BusState bus_state;
      cpu.get_bus_state(bus_state);

      CpuState state;
      state.addr = bus_state.addr;
      state.data = (bus_state.rwb ? gpio::read_data_bus() : bus_state.data);
      state.status =
        (bus_state.rwb << 0) | (bus_state.sync << 1) | (bus_state.vpb << 2) | (phi2 << 3) |
        (cpu.in_rst << 4) | (cpu.in_nmi << 5) | (cpu.in_rst << 6) | (bus_state.error << 7);

      state.pc = cpu.pc;
      state.a = cpu.a;
      state.x = cpu.x;
      state.y = cpu.y;
      state.s = cpu.s;
      state.p = cpu.p;

      state.mode = (uint8_t)cpu.mode;
      state.oper = (uint8_t)cpu.oper;
      state.seq_cycle = cpu.seq_cycle;

      send_packet(CommandType::GetCpuState, state);
      break;
    }
    case CommandType::EnterFastMode: {
      send_packet(CommandType::EnterFastMode);
      return Action::EnterFastMode;
    }
    case CommandType::DebuggerReset: {
      // Wait for TX data register empty
      send_packet(CommandType::DebuggerReset);
      delay_millis(100);
      sw_reset();
      break;
    }
    default:
      send_packet(CommandType::Error);
      break;
    }

    break;
  }

  return Action::None;
}

inline void delay_microsecond() {
  asm volatile ("nop");
  asm volatile ("nop");
  asm volatile ("nop");
  asm volatile ("nop");
}

void run();

void phi2_fast();

#define LED_DATA_LEN 36


template<int I>
struct UnrollFold {
  void operator() (uint8_t data[LED_DATA_LEN]) {
    while ((SPI0.INTFLAGS & (1 << 5)) == 0) {}
    SPI0.DATA = data[LED_DATA_LEN - I];
    UnrollFold<I-1> {}(data);
  }
};

template<>
struct UnrollFold<0> {
  void operator() (uint8_t data[LED_DATA_LEN]) {}
};

void write_hot_loop(uint8_t data[LED_DATA_LEN]) {
  UnrollFold<LED_DATA_LEN> {}(data);
}

void setup() {
  setup_pin_directions();

  uart::init();

  // Default is CLK_MAIN / 6
  // New is CLK_MAIN / 16

  /*uint8_t value = (CLKCTRL.MCLKCTRLB & ~0x1F) | 0xB;
  CCP = 0xD8;
  CLKCTRL.MCLKCTRLB = value;*/

#if 0
  VPB_PORT.DIRSET = VPB_PIN_MASK;
  PORTA.PIN4CTRL |= (1 << 7);


  SPI0.CTRLA |= (1 << 5); // Host mode

  // Set clock frequency to 2.5MHz
  SPI0.CTRLA = (SPI0.CTRLA & ~0b110) | (0x0 << 1); // Prescaler TODO
  SPI0.CTRLA |= (1 << 4); // CLK2X

  SPI0.CTRLB |= (1 << 7); // Enable buffer mode
  SPI0.CTRLB |= (1 << 6); // First write goes directly to shift register
  SPI0.CTRLB |= (1 << 2); // Disable select thingy

  SPI0.CTRLA |= 0x1; // Enable

  uint8_t a = 17;

  uart::put('b');

  //uint32_t r = 0x01, g = 0x51, b = 0x22;
  uint32_t r = 0x00, g = 0x51, b = 0x00;

  while (1) {
    uint8_t data[36] = { 0 };
    unsigned bit_index = 0;

    b = (b + 1) & 0xFF;

    uint32_t rgb = (g << 16) | (r << 8) | (b << 0);
    for (int j = 0; j < 1; ++j) {
      for (int i = 0; i < 24; ++i) {
        bool bit = (rgb >> (23 - i)) & 1;

        if (bit) {
          for (int k = 0; k < 6; ++k) {
            data[bit_index / 8] |= (0    << (7 - (bit_index % 8)));
            ++bit_index;
          }
          for (int k = 0; k < 6; ++k) {
            data[bit_index / 8] |= (1    << (7 - (bit_index % 8)));
            ++bit_index;
          }
        } else {
          for (int k = 0; k < 3; ++k) {
            data[bit_index / 8] |= (0    << (7 - (bit_index % 8)));
            ++bit_index;
          }
          for (int k = 0; k < 6; ++k) {
            data[bit_index / 8] |= (1    << (7 - (bit_index % 8)));
            ++bit_index;
          }
        }

        /*
        data[bit_index / 8] |= (0    << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (!bit << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (1    << (7 - (bit_index % 8)));
        ++bit_index;
        */

        /*
        data[bit_index / 8] |= (0    << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (0    << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (0    << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (!bit << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (!bit << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (!bit << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (1    << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (1    << (7 - (bit_index % 8)));
        ++bit_index;
        data[bit_index / 8] |= (1    << (7 - (bit_index % 8)));
        ++bit_index;
        */
     }
    }

    while (bit_index < sizeof(data) * 8) {
      data[bit_index / 8] |= (1 << (7 - (bit_index % 8)));
      ++bit_index;
    }

    write_hot_loop(data);

    delay_millis(100);
  }

#endif

  gpio::set_data_bus_dir(gpio::Direction::Output);
  gpio::write_data_bus(0xEA);

  gpio::set_phi2_dir(gpio::Direction::Output);
  gpio::write_phi2(false);

  // Enable slew rate control
  PORTD.PORTCTRL |= 0x1;
  PORTE.PORTCTRL |= 0x1;
  PORTF.PORTCTRL |= 0x1;
  PORTC.PORTCTRL |= 0x1;


  if (TEST_PINS) {
    uint8_t result = test_bridged_pins();

    uart::put(result);

    while (1) { asm volatile ("nop"); }
  }

  gpio::set_progb_dir(gpio::Direction::Output);

  gpio::write_progb(true); // enable the EEPROM outputs
  gpio::write_we(true);

  gpio::write_be(false); // disable the 6502 buses

  gpio::set_addr_bus_dir(gpio::Direction::Output);
  gpio::set_data_bus_dir(gpio::Direction::Input);

  delay_loop(1000);

  RESB_PORT.OUTCLR = RESB_PIN_MASK;

  gpio::set_rwb_dir(gpio::Direction::Output);
  gpio::set_sync_dir(gpio::Direction::Output);
  gpio::set_vpb_dir(gpio::Direction::Output);

  // Do a single clock cycle with RESB held low to make sure all devices acknowledge it.
  gpio::write_phi2(false);
  delay_loop(50);
  gpio::write_phi2(true);
  delay_loop(50);

  run();

  // This function returned so we need to enter fast mode

  gpio::set_addr_bus_dir(gpio::Direction::Input);
  gpio::set_data_bus_dir(gpio::Direction::Input);

  gpio::set_rwb_dir(gpio::Direction::Input);
  gpio::set_sync_dir(gpio::Direction::Input);
  gpio::set_vpb_dir(gpio::Direction::Input);

  gpio::write_be(true); // enable the 6502 buses

  RESB_PORT.OUTCLR = RESB_PIN_MASK;

  // Do a single clock cycle with RESB held low to make sure all devices acknowledge it.
  gpio::write_phi2(false);
  delay_loop(50);
  gpio::write_phi2(true);
  delay_loop(50);
  gpio::write_phi2(false);
  delay_loop(50);
  gpio::write_phi2(true);
  delay_loop(50);

  RESB_PORT.OUTSET = RESB_PIN_MASK;

  NMIB_PORT.DIRSET = NMIB_PIN_MASK;

  // TCA0 pins on PB[5:0]
  PORTMUX.TCAROUTEA = (PORTMUX.TCAROUTEA & ~0b111) | 0x1;

  TCA0.SINGLE.CTRLA &= ~1; // Disable
  TCA0.SINGLE.CTRLD |= 1; // Split mode
  TCA0.SINGLE.CTRLESET = 0b1100; // RESET

  TCA0.SPLIT.CTRLA = (TCA0.SINGLE.CTRLA & ~0b1110); // No prescaler

  TCA0.SPLIT.LCMP0 = 1;
  TCA0.SPLIT.LPER = 1;

  TCA0.SPLIT.HCMP0 = 1;
  TCA0.SPLIT.HPER = 1;

  TCA0.SPLIT.CTRLB |= (1 << 0); // LCMP0EN
  TCA0.SPLIT.CTRLB |= (1 << 4); // HCMP0EN

  TCA0.SPLIT.CTRLA |= 1;

  /*TCA0.SINGLE.CMP0 = 1;
  TCA0.SINGLE.PER = 1;

  TCA0.SINGLE.CMP2 = 1;
  TCA0.SINGLE.CMP0 = 1;
  TCA0.SINGLE.PER = 1;

  TCA0.SINGLE.CTRLB = TCA0.SINGLE.CTRLB & ~0x7F; // Clear all bits
  TCA0.SINGLE.CTRLB |= (1 << 4); // 
  TCA0.SINGLE.CTRLB |= 0x1; // FRQ mode

  TCA0.SINGLE.CTRLA |= 1; // Enable*/

  while (1) {
    asm volatile ("nop");
  }

  //phi2_fast();
}

__attribute__((noinline))
void phi2_fast() {
  while (1) {
    PHI2_PORT.OUTTGL = PHI2_PIN_MASK;
  }
}

void run() {
  uint32_t cycle = 0;
  
  PhysicalW65C02 cpu = {};

  while (1) {
    uint8_t data;

    // Interrupt signals (IRQB, NMIB, RESB, RDY) are latched on the falling edge.
    
    status_t status = gpio::read_status();

    ++cycle;

    cpu.tick_cycle({ gpio::read_data_bus(), status.resb(), status.irqb(), status.nmib() });

    gpio::write_phi2(false);

    /* ---- PHI2 is low ---- */

    gpio::set_data_bus_dir(gpio::Direction::Input);

    delay_microsecond();

    RESB_PORT.OUTSET = RESB_PIN_MASK;

    physicalw65c02::BusState cpu_bus_state;
    cpu.get_bus_state(cpu_bus_state);

    if (cpu_bus_state.error) {
      WAIT = Wait::HalfCycle;
      hit_breakpoint(0xFF);
    }

    // Address and control lines change immediately after the falling edge of PHI2.
    gpio::write_addr_bus(cpu_bus_state.addr);
    gpio::write_rwb(cpu_bus_state.rwb);
    gpio::write_sync(cpu_bus_state.sync);
    gpio::write_vpb(cpu_bus_state.vpb);

    if (int8_t i = has_hit_enabled_breakpoint(cpu.pc); i != -1 && cpu_bus_state.sync) {
    //if (int8_t i = has_hit_enabled_breakpoint(cpu_bus_state.addr); i != -1) {
      WAIT = Wait::HalfCycle;
      hit_breakpoint(i);
    }

    Action action;
    do {
      action = handle_commands(cpu, false);
      if (action == Action::Continue) {
        WAIT = Wait::None;
        break;
      } else if (action == Action::StepHalfCycle) {
        WAIT = Wait::HalfCycle;
        break;
      } else if (action == Action::StepCycle) {
        WAIT = Wait::Cycle;
        break;
      } else if (action == Action::Step) {
        WAIT = Wait::Sync;
        break;
      } else if (action == Action::EnterFastMode) {
        return;
      } else if (action == Action::Stop) {
        WAIT = Wait::HalfCycle;
      }
    } while (WAIT == Wait::HalfCycle);

    delay_microsecond();

    gpio::write_phi2(true);

    if (!cpu_bus_state.rwb) {
      gpio::write_data_bus(cpu_bus_state.data);
      gpio::set_data_bus_dir(gpio::Direction::Output);
    }

    /* ---- PHI2 is high ---- */

    //delay_loop(20);

    do {
      action = handle_commands(cpu, true);
      if (action == Action::Continue) {
        WAIT = Wait::None;
        break;
      } else if (action == Action::StepHalfCycle) {
        WAIT = Wait::HalfCycle;
        break;
      } else if (action == Action::StepCycle) {
        WAIT = Wait::Cycle;
        break;
      } else if (action == Action::Step) {
        WAIT = Wait::Sync;
        break;
      } else if (action == Action::EnterFastMode) {
        return;
      } else if (action == Action::Stop) {
        WAIT = Wait::HalfCycle;
      }
    } while (WAIT == Wait::HalfCycle || WAIT == Wait::Cycle || (!cpu_bus_state.sync && WAIT == Wait::Sync));

    delay_microsecond();
  }
}

#if 0

void run_cpu_controlled_loop() {
  while (1) {
    uint16_t addr;
    uint8_t data;
    status_t status;

    // Interrupt signals (IRQB, NMIB, RESB, RDY) are latched on the falling edge.

    gpio::write_phi2(false);

    /* ---- PHI2 is low ---- */

    delay_microsecond();

    RESB_PORT.OUTSET = RESB_PIN_MASK;

    addr = gpio::read_addr_bus();
    for (int8_t i = 0; i < NUM_BREAKPOINTS; ++i) {
      if (BREAKPOINTS[i].addr == addr) {
        WAIT = Wait::HalfCycle;
        hit_breakpoint(i);
        break;
      }
    }

    if (WAIT != Wait::None) {
      data = gpio::read_data_bus();
      status = gpio::read_status();
      LED_DRIVER.show_addr(addr);
      LED_DRIVER.show_data(data);
      LED_DRIVER.show_status(status);
    }

    uint16_t keyscan;
    Action action;
    do {
      action = handle_commands(cpu);
      if (action == Action::Continue) {
        WAIT = Wait::None;
        break;
      } else if (action == Action::StepHalfCycle) {
        WAIT = Wait::HalfCycle;
        break;
      } else if (action == Action::StepCycle) {
        WAIT = Wait::Cycle;
        break;
      } else if (action == Action::Step) {
        WAIT = Wait::Sync;
        break;
      }
    } while (WAIT == Wait::HalfCycle);

    delay_microsecond();

    gpio::write_phi2(true);

    /* ---- PHI2 is high ---- */

    delay_microsecond();

    if (WAIT != Wait::None) {
      addr = gpio::read_addr_bus();
      data = gpio::read_data_bus();
      status = gpio::read_status();
      LED_DRIVER.show_addr(addr);
      LED_DRIVER.show_data(data);
      LED_DRIVER.show_status(status);
    }

    do {
      status = gpio::read_status();

      action = handle_commands(cpu);
      if (action == Action::Continue) {
        WAIT = Wait::None;
        break;
      } else if (action == Action::StepHalfCycle) {
        WAIT = Wait::HalfCycle;
        break;
      } else if (action == Action::StepCycle) {
        WAIT = Wait::Cycle;
        break;
      } else if (action == Action::Step) {
        WAIT = Wait::Sync;
        break;
      }
    } while (WAIT == Wait::HalfCycle || WAIT == Wait::Cycle || (!status.sync() && WAIT == Wait::Sync));

    delay_microsecond();
  }
}

#endif

void loop() {}