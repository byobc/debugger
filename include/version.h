#pragma once

#define VERSION_YEAR  2025
#define VERSION_MONTH 3
#define VERSION_DAY   5

#define BOARD_REV 2

struct VersionInfo {
	uint16_t year;
	uint8_t  month;
	uint8_t  day;
};

const VersionInfo VERSION = { VERSION_YEAR, VERSION_MONTH, VERSION_DAY };