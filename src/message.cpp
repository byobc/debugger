#include "message.h"
#include "uart.h"
#include "crc.h"

const uint8_t PKT_MAGIC = '%';

void send_header(CommandType ty, uint16_t len) {
	uart::put(PKT_MAGIC);
	uart::put((uint8_t)ty);
	uart::put(len);
	uart::put(len >> 8);
}

static void send_ack() {
	send_header(CommandType::Ack, 0);
}

// returns negative on failure
static int recv_header(CommandType &ty, uint16_t &len) {
	uint8_t magic;
	do {
		magic = uart::get_nonblocking();
		if (magic < 0) {
			return ERR_NO_CMD;
		}
	} while (magic != PKT_MAGIC);

	ty = static_cast< CommandType >(uart::get());
	len  = uart::get();
	len |= uart::get() << 8;
	return 0;
}

// TODO: Do I even need acks in this direction?
static int recv_ack() {
	CommandType ty;
	uint16_t len;
	while (recv_header(ty, len) < 0) {}
	if (ty == CommandType::Ack) {
		return 0;
	} else {
		return 0;
	}
}

void send_packet(CommandType ty, const uint8_t *body, uint16_t len) {
	send_header(ty, len);
	uart::put_bytes(body, len);
}

int recv_packet(CommandType &ty, uint8_t *buf, uint16_t *len) {
	uint16_t buf_len = *len;
	uint16_t msg_len;
	int err;

	if ((err = recv_header(ty, msg_len)) < 0) {
		return err;
	}
	send_ack();

	if (msg_len > 0) {
		if (msg_len > buf_len) {
			// can't possibly be valid, just read and discard
			for (uint16_t i = 0; i < msg_len; ++i) {
				uart::get();
				send_ack();
			}
			return ERR_BAD_CMD;
		} else {
			for (uint16_t i = 0; i < msg_len; ++i) {
				buf[i] = uart::get();
			}
			send_ack();
		}
	}

	*len = msg_len;
	return 0;
}

void hit_breakpoint(uint8_t which) {
	(void)send_packet(CommandType::HitBreakpoint, &which, 1);
}

void print_debug(const char *s, size_t len) {
	send_packet(CommandType::Print, (const uint8_t *)s, len);
}