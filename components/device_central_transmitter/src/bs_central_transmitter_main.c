/*
 * Copyright (c) 2026 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "bs_tracing.h"
#include "bs_oswrap.h"
#include "bs_cmd_line.h"
#include "bs_cmd_line_typical.h"
#include "bs_pc_base.h"
#include "bs_pc_2G4.h"
#include "bs_pc_2G4_types.h"
#include "bs_pc_2G4_utils.h"
#include "bs_pc_2G4_modulations.h"
#include "bs_rand_main.h"

/* Fuzz ranges (increase or decrease the ranges to change the fuzzing intensity) */
#define FUZZ_FREQ_OFFSET_MAX_MHZ  0.01   /* ±0.01 MHz center frequency */
#define FUZZ_POWER_OFFSET_MAX_DB  3   /* ±3 dB power */
#define FUZZ_START_JITTER_US      100 /* ±100 us TX start jitter */

/* BLE LL PDU header (1 byte): LLID(2) NESN(1) SN(1) MD(1) RFU(1) Length(5) - Core Spec 4.2 Vol 6 B.2.1 */
#define BLE_LL_HEADER_SIZE 1
#define BLE_LL_MAX_PAYLOAD 27
#define BLE_LL_PDU_MAX (BLE_LL_HEADER_SIZE + BLE_LL_MAX_PAYLOAD)
#define BLE_LLID_DATA_CONTINUE 0u
#define BLE_LLID_DATA_START 1u
#define BLE_LLID_CTRL 2u
#define BLE_LLID_RESERVED 3u
#define BLE_LL_LENGTH_BITS 5u
#define BLE_LL_LENGTH_MASK ((1u << BLE_LL_LENGTH_BITS) - 1)

/* Simple state for state-machine fuzz: receiver is "idle" or "connected" */
typedef enum { BLE_FUZZ_STATE_IDLE, BLE_FUZZ_STATE_CONNECTED } ble_fuzz_state_t;

/* Struct to store the the most recent fuzz parameters */
typedef struct {
  uint32_t seed;
  bs_time_t tx_time;
  uint8_t llid;
  uint8_t reported_len;
  uint16_t packet_len;
  ble_fuzz_state_t state;
  double freq_offset;
  double power_db;
  uint8_t mutation_flags;
} fuzz_case_t;

static fuzz_case_t last_case;
static int last_case_valid = 0;

/* Creates a BLE LL PDU header, as a starting point for the fuzzing */
static inline uint8_t ble_ll_header(uint8_t llid, uint8_t length)
{
  return (uint8_t)((llid & 3u) | ((length & BLE_LL_LENGTH_MASK) << 3));
}

/* Get the length of the BLE LL PDU from the header, used when intentinonally violating the length */
static inline uint8_t ble_ll_header_get_length(uint8_t h) { return (h >> 3) & BLE_LL_LENGTH_MASK; }

typedef bs_basic_dev_args_t empty_args_t;

char executable_name[] = "bs_device_central_transmitter";

void component_print_post_help(){
  fprintf(stdout,"\n"
          "This device connects to the PHY and transmits packets with fuzzed parameters.\n"
          "Use -rs=<seed> or --rand_seed=<seed> for reproducible fuzz runs.\n");
}

empty_args_t args;

void cmd_trace_lvl_found(char * argv, int offset){
  bs_trace_set_level(args.verb);
}

void cmd_gdev_nbr_found(char * argv, int offset){
  bs_trace_set_prefix_dev(args.global_device_nbr);
}

/*
 * Check the arguments provided in the command line: set args based on it or
 * defaults, and check they are correct
 */
void bs_empty_argparse(int argc, char *argv[], empty_args_t *args)
{
  bs_args_struct_t args_struct[] = {
      BS_BASIC_DEVICE_2G4_TYPICAL_OPTIONS_ARG_STRUCT,
      ARG_TABLE_ENDMARKER
  };

  bs_args_typical_dev_set_defaults((bs_basic_dev_args_t *)args, args_struct);
  static char default_phy[] ="2G4";

  bs_args_parse_cmd_line(argc, argv, args_struct);

  bs_args_typical_dev_post_check((bs_basic_dev_args_t *)args, args_struct, default_phy);
}

static uint8_t clean_up() {
  bs_trace_raw(8,"Cleaning up transmitter\n");
  p2G4_dev_disconnect_c();
  return 0;
}

/**
 * HELLO
 * Handler for SIGTERM and SIGINT
 * We do not need to do anything in this empty device
 * The signal will cause any blocking libPhyCom op to return an error
 */
static void signal_end_handler(int sig)
{
  bs_trace_raw(2,"Signal \"%s\" received\n", strsignal(sig));
}

/**
 * This device connects to the PHY and transmits a 5 byte datapacket every 1 seconds.
 */
int main(int argc, char *argv[]) {
  bs_trace_register_cleanup_function(clean_up);
  bs_set_sig_term_handler(signal_end_handler, (int[]){SIGTERM, SIGINT}, 2);

  bs_empty_argparse(argc, argv, &args);

  /* Seed RNG for reproducible fuzz; same seed => same parameter sequence */
  bs_random_init(args.rseed);
  bs_trace_info(1, "Device starting up (verbosity level: %u, fuzz seed: %u)\n", args.verb, args.rseed);
  bs_trace_raw(2, "Reproduce this run with: -rs=%u\n", args.rseed);
  bs_trace_raw(3, "Connecting to PHY (sim_id=%s, phy_id=%s, device_nbr=%u)\n", 
               args.s_id, args.p_id, args.device_nbr);

  // Initialize 2G4 PHY communication (with callbacks, with memory)
  if (p2G4_dev_initcom_c(args.device_nbr, args.s_id, args.p_id, NULL) != 0) {
    bs_trace_error_line("Failed to connect to PHY\n");
    return -1;
  }

  bs_trace_raw(4, "Connected successfully\n");

  pb_wait_t wait_s;
  // Wait until a very large time to ensure we stay connected until sim_length
  // Use 100 seconds (100e6 microseconds) as a safe upper bound
  bs_time_t target_time = 100e6;
  bs_time_t time = 1000000; // Start at 1 second, use 1 second increments
  bs_time_t wait_increment = 1000000; // 1 second increments

  bs_trace_raw(5, "Starting wait loop (target_time=%"PRItime"us, increment=%"PRItime"us)\n", 
               target_time, wait_increment);

  /* BLE LL PDU buffer: 1 byte header + up to 27 bytes payload */
  uint8_t packet[BLE_LL_PDU_MAX];
  uint16_t packet_len;
  p2G4_tx_t tx_s;
  p2G4_tx_done_t tx_done_s;
  bs_time_t next_tx_time = 1000000; // Transmit every 1 seconds
  ble_fuzz_state_t ble_state = BLE_FUZZ_STATE_CONNECTED;

  /* Last transmitted packet (for crash reporting when receiver dies) */
  uint8_t last_tx_packet[BLE_LL_PDU_MAX];
  uint16_t last_tx_packet_len = 0;
  bs_time_t last_tx_time = 0;
  int phy_disconnected = 0;  /* set when we get -1 from wait or TX (PHY/receiver died); skip terminate */

  // Main loop: request waits and transmit packets
  // This will continue until the PHY disconnects (when sim_length is reached or another device crashes)
  while (time < target_time) {
    wait_s.end = time;
    bs_trace_raw(6, "Requesting wait until %"PRItime"us\n", time);
    
    // Use blocking wait - this will block until the wait completes or we're disconnected
    if (p2G4_dev_req_wait_c_b(&wait_s) == -1) {
      phy_disconnected = 1;
      // We've been disconnected (e.g. receiver crashed)
      bs_trace_raw(3, "Wait failed - PHY disconnected\n");
      if (time < target_time) {
        if (last_case_valid) {
          bs_trace_warning_line(
              "Receiver may have crashed. Last fuzz case (packet that may have caused it):\n"
              "Seed: %u\n"
              "TX time: %"PRItime" us\n"
              "LLID: %u\n"
              "Reported_len: %u\n"
              "PDU_len: %u\n"
              "State: %s\n"
              "Freq_offset: %.4f MHz\n"
              "Power: %.1f dB\n",
              last_case.seed, last_case.tx_time, last_case.llid, last_case.reported_len,
              last_case.packet_len, last_case.state == BLE_FUZZ_STATE_IDLE ? "IDLE" : "CONN",
              last_case.freq_offset, last_case.power_db);
        }
        if (last_tx_packet_len > 0) {
          bs_trace_warning_line("Last packet bytes (%u):", last_tx_packet_len);
          for (uint16_t i = 0; i < last_tx_packet_len; i++) {
            bs_trace_raw(1, " %02X", last_tx_packet[i]);
          }
          bs_trace_raw(1, "\n");
        }
      }
      break;
    }
    bs_trace_raw(7, "Wait completed, reached %"PRItime"us\n", time);
    
    // Transmit a packet every 1 seconds
    if (time % next_tx_time == 0) {
      /* --- Base BLE LL PDU: [header][payload] --- */
      const uint8_t payload_len = 5;
      packet[0] = ble_ll_header(BLE_LLID_DATA_CONTINUE, payload_len);
      packet[1] = 0x01;
      packet[2] = 0x02;
      packet[3] = 0x03;
      packet[4] = 0x04;
      packet[5] = 0x05;
      packet_len = BLE_LL_HEADER_SIZE + payload_len;

      /* --- 1) BLE protocol semantics: LLID (incl. reserved 3), RFU bit --- */
      uint8_t llid = (uint8_t)bs_random_uniformRi(0, 4);
      if (llid > 3) llid = 3;
      uint8_t hdr = packet[0];
      hdr = (uint8_t)((hdr & 0xF8) | (llid & 3));
      if (bs_random_uniform() < 0.2) hdr |= (1u << 5);
      packet[0] = hdr;

      /* --- 2) Malformed PDU: wrong length in header, bit flip in payload --- */
      uint8_t reported_len = payload_len;
      if (bs_random_uniform() < 0.25) {
        reported_len = (uint8_t)bs_random_uniformRi(0, BLE_LL_MAX_PAYLOAD);
        packet[0] = (uint8_t)((packet[0] & 0x07) | (reported_len << 3));
      }
      if (bs_random_uniform() < 0.2) {
        uint8_t idx = (uint8_t)bs_random_uniformRi(1, BLE_LL_HEADER_SIZE + payload_len - 1);
        packet[idx] ^= (1u << (uint8_t)bs_random_uniformRi(0, 7));
      }

      /* --- 3) Length/header violations: inconsistent length vs size --- */
      if (bs_random_uniform() < 0.2) {
        packet_len = BLE_LL_HEADER_SIZE + (reported_len > payload_len ? reported_len : payload_len);
        if (packet_len > BLE_LL_PDU_MAX) packet_len = BLE_LL_PDU_MAX;
      } else {
        packet_len = BLE_LL_HEADER_SIZE + payload_len;
      }

      /* --- 4) State-machine: invalid PDU type for state (e.g. CONTROL in IDLE) --- */
      if (bs_random_uniform() < 0.15) {
        ble_state = (ble_fuzz_state_t)bs_random_uniformRi(0, 1);
      }
      if (ble_state == BLE_FUZZ_STATE_IDLE && bs_random_uniform() < 0.3) {
        packet[0] = (uint8_t)((packet[0] & 0xFC) | BLE_LLID_CTRL);
      }

      /* RF fuzz */
      bs_time_t base_start = time + 1000;
      bs_time_t base_duration = 10000;
      uint32_t base_phy_addr = 0x8E89BED6;
      double freq_offset_MHz = bs_random_uniformR(-FUZZ_FREQ_OFFSET_MAX_MHZ, FUZZ_FREQ_OFFSET_MAX_MHZ);
      int16_t freq_offset_8_8 = (int16_t)(freq_offset_MHz * 256.0);
      double power_dB = (double)bs_random_uniformRi(-FUZZ_POWER_OFFSET_MAX_DB * 10, FUZZ_POWER_OFFSET_MAX_DB * 10) / 10.0;
      bs_time_t start_jitter = (bs_time_t)bs_random_uniformRi(-FUZZ_START_JITTER_US, FUZZ_START_JITTER_US);

      tx_s.start_time = base_start + start_jitter;
      tx_s.end_time = tx_s.start_time + base_duration;
      tx_s.phy_address = base_phy_addr;
      tx_s.radio_params.modulation = P2G4_MOD_BLE;
      tx_s.radio_params.center_freq = freq_offset_8_8;
      tx_s.power_level = p2G4_power_from_d(power_dB);
      tx_s.packet_size = packet_len;
      tx_s.abort.abort_time = TIME_NEVER;
      tx_s.abort.recheck_time = TIME_NEVER;





      /* Testing storing the last fuzzed parameters before crash */
      last_case.seed = args.rseed;
      last_case.tx_time = tx_s.start_time;
      last_case.llid = llid;
      last_case.reported_len = reported_len;
      last_case.packet_len = packet_len;
      last_case.state = ble_state;
      last_case.freq_offset = freq_offset_MHz;
      last_case.power_db = power_dB;
      //last_case.mutation_flags =
      //    (bad_len ? 1<<0 : 0) |
      //    (bitflip ? 1<<1 : 0) |
      //    (rfu_bit ? 1<<2 : 0);
      last_case_valid = 1;






      bs_trace_raw(2, "TX at %"PRItime"us BLE llid=%u len=%u pdu_len=%u %s freq=%.4f power=%.1f\n",
                   tx_s.start_time, llid, reported_len, (unsigned)packet_len,
                   ble_state == BLE_FUZZ_STATE_IDLE ? "IDLE" : "CONN", freq_offset_MHz, power_dB);

      if (p2G4_dev_req_tx_c_b(&tx_s, packet, &tx_done_s) == 0) {
        memcpy(last_tx_packet, packet, (size_t)packet_len);
        last_tx_packet_len = packet_len;
        last_tx_time = tx_s.start_time;
        bs_trace_raw(2, "Packet transmitted successfully, ended at %"PRItime"us\n", tx_done_s.end_time);
      } else {
        phy_disconnected = 1;
        bs_trace_warning_line("Packet transmission failed (PHY may have disconnected us)\n");
        /* We set last_case before TX; the packet that caused the crash is this one (never stored in last_tx_packet) */
        if (last_case_valid) {
          bs_trace_warning_line(
              "Fuzz case that likely caused the crash (TX in progress when receiver died):\n"
              "Seed: %u\n"
              "TX time: %"PRItime" us\n"
              "LLID: %u\n"
              "reported_len: %u\n"
              "pdu_len: %u\n"
              "State: %s\n"
              "freq_offset: %.4f MHz\n"
              "power: %.1f dB\n",
              last_case.seed, last_case.tx_time, last_case.llid, last_case.reported_len,
              last_case.packet_len, last_case.state == BLE_FUZZ_STATE_IDLE ? "IDLE" : "CONN",
              last_case.freq_offset, last_case.power_db);
        }
        if (last_tx_packet_len > 0) {
          bs_trace_warning_line("Previous packet bytes (%u):", last_tx_packet_len);
          for (uint16_t i = 0; i < last_tx_packet_len; i++) {
            bs_trace_raw(1, " %02X", last_tx_packet[i]);
          }
          bs_trace_raw(1, "\n");
        }
        break;
      }
    }

    time += wait_increment;
  }

  bs_trace_raw(2, "Simulation ended, terminating and disconnecting from PHY\n");
  /* When PHY already disconnected us (e.g. receiver crashed), the device layer already cleaned up;
   * do not call terminate or we may block writing to a dead pipe. */
  if (!phy_disconnected) {
    p2G4_dev_terminate_c();
  }
  bs_trace_info(1, "Device finished successfully\n");
  return 0;
}
