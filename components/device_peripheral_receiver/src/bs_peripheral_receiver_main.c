/*
 * Copyright (c) 2026 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <stdlib.h>
#include <stdio.h>
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

typedef bs_basic_dev_args_t empty_args_t;

char executable_name[] = "bs_device_peripheral_receiver";
void component_print_post_help(){
  fprintf(stdout,"\n"
          "This device connects to the PHY and receives packets from device_central_transmitter.\n");
}

empty_args_t args;

void cmd_trace_lvl_found(char * argv, int offset){
  bs_trace_set_level(args.verb);
}

void cmd_gdev_nbr_found(char * argv, int offset){
  bs_trace_set_prefix_dev(args.global_device_nbr);
}

/**
 * Check the arguments provided in the command line: set args based on it or
 * defaults, and check they are correct
 */
void bs_empty_argparse(int argc, char *argv[], empty_args_t *args)
{
  bs_args_struct_t args_struct[] = {
      BS_BASIC_DEVICE_2G4_FAKE_OPTIONS_ARG_STRUCT,
      ARG_TABLE_ENDMARKER
  };

  bs_args_typical_dev_set_defaults((bs_basic_dev_args_t *)args, args_struct);
  static char default_phy[] ="2G4";

  bs_args_parse_cmd_line(argc, argv, args_struct);

  bs_args_typical_dev_post_check((bs_basic_dev_args_t *)args, args_struct, default_phy);
}

static uint8_t clean_up() {
  bs_trace_raw(8,"Cleaning up receiver\n");
  p2G4_dev_disconnect_c();
  return 0;
}

/**
 * Handler for SIGTERM and SIGINT
 * We do not need to do anything in this empty device
 * The signal will cause any blocking libPhyCom op to return an error
 */
static void signal_end_handler(int sig)
{
  bs_trace_raw(2,"Signal \"%s\" received\n", strsignal(sig));
}

uint8_t hdr;
uint8_t llid;
uint8_t len;

static void simulate_crash(p2G4_rx_done_t rx_done_s, uint8_t *packet_ptr) {
  if (rx_done_s.status == P2G4_RXSTATUS_OK && packet_ptr != NULL) {
    hdr = packet_ptr[0];
    llid = hdr & 0x03;
    len  = (hdr >> 3) & 0x1F;

    if (llid == 2 && len > 20) {
      /* Print without bs_trace_error_line so we don't trigger cleanup (which sends DISCONNECT
       * and prevents the PHY from detecting a crash and disconnecting the central). */
      fprintf(stderr, "FATAL: CTRL PDU with len=%u (>20) — crashing intentionally\n", len);
      _Exit(1);  /* Terminate without atexit/cleanup so PHY sees broken pipe and disconnects all */
    }
  }
}

/**
 * This device connects to the PHY and listens for a BLE-modulated packet
 * with a specific access address, then prints the received payload.
 */
int main(int argc, char *argv[]) {
  bs_trace_register_cleanup_function(clean_up);
  bs_set_sig_term_handler(signal_end_handler, (int[]){SIGTERM, SIGINT}, 2);

  bs_empty_argparse(argc, argv, &args);

  bs_trace_info(1, "HELLO WORLD!\n");
  bs_trace_info(1, "Device starting up (verbosity level: %u)\n", args.verb);
  bs_trace_raw(3, "Connecting to PHY (sim_id=%s, phy_id=%s, device_nbr=%u)\n", 
               args.s_id, args.p_id, args.device_nbr);

  // Initialize 2G4 PHY communication (with callbacks, with memory)
  if (p2G4_dev_initcom_c(args.device_nbr, args.s_id, args.p_id, NULL) != 0) {
    bs_trace_error_line("Failed to connect to PHY\n");
    return -1;
  }

  bs_trace_raw(4, "Connected successfully\n");

  // Match the transmitter's parameters (see device_central_transmitter)
  const uint32_t access_address = 0x8E89BED6;

  p2G4_rx_t rx_s = {0};
  rx_s.start_time = 1000000;  // Start scanning at the start of the simulation (1 second)
  rx_s.scan_duration = 100000000U;   // 100s window (us) per listen
  rx_s.phy_address = access_address;
  rx_s.radio_params.modulation = P2G4_MOD_BLE;
  rx_s.radio_params.center_freq = 0; // 2400 MHz (0 offset), must match TX
  rx_s.antenna_gain = p2G4_power_from_d(0.0);

  // BLE 1M timings (in microseconds)
  rx_s.pream_and_addr_duration = 40; // 1B preamble (8us) + 4B access addr (32us)
  rx_s.header_duration = 16;         // 2B LL header at 1Mbps
  rx_s.bps = 1000000;

  // Error tolerances
  rx_s.sync_threshold = 3;
  rx_s.header_threshold = 3;

  rx_s.abort.abort_time = TIME_NEVER;
  rx_s.abort.recheck_time = TIME_NEVER;

  p2G4_rx_done_t rx_done_s;
  uint8_t *packet_ptr = NULL;
  bs_time_t last_rx_ts = 0;  /* track gaps to detect missed packets */
  const bs_time_t expected_interval_us = 1000000;  /* TX every 1s; warn if gap > ~1.25s */
  const bs_time_t listen_start_time = 1000000;    /* when we started listening (same as initial rx_s.start_time) */

  bs_trace_raw(2, "Listening for packets (access_address=0x%08X) for the whole simulation\n", access_address);

  while (1) {
    int rx_ret = p2G4_dev_req_rx_c_b(&rx_s, &rx_done_s, &packet_ptr, 0, NULL);
    if (rx_ret == -1) {
      bs_trace_raw(3, "RX request failed - PHY disconnected us\n");
      break;
    }
    /* Possible missed packet(s): no successful RX for a long time */
    if (rx_done_s.status == P2G4_RXSTATUS_OK) {
      if (last_rx_ts == 0) {
        /* First successful RX: warn if it arrived more than one TX interval after we started (e.g. first packet missed) */
        if ((rx_done_s.rx_time_stamp - listen_start_time) > expected_interval_us) {
          bs_trace_warning_line("Possible missed packet(s) before first RX - first RX at %"PRItime"us (listening since %"PRItime"us, %.1f s)\n",
                                rx_done_s.rx_time_stamp, listen_start_time,
                                (double)(rx_done_s.rx_time_stamp - listen_start_time) / 1e6);
        }
      } else if ((rx_done_s.rx_time_stamp - last_rx_ts) > expected_interval_us + 10000) {
        bs_trace_warning_line("Possible missed packet(s) - no RX for %.1f s (last at %"PRItime"us, this at %"PRItime"us)\n",
                              (double)(rx_done_s.rx_time_stamp - last_rx_ts) / 1e6, last_rx_ts, rx_done_s.rx_time_stamp);
      }
      last_rx_ts = rx_done_s.rx_time_stamp;
    }

    /* Simulate crash */
    simulate_crash(rx_done_s, packet_ptr);

    bs_trace_raw(2, "RX done: status=%u, size=%u, rx_ts=%"PRItime"us, end=%"PRItime"us\n",
                 rx_done_s.status, rx_done_s.packet_size, rx_done_s.rx_time_stamp, rx_done_s.end_time);
    if (rx_done_s.status == P2G4_RXSTATUS_OK && packet_ptr != NULL) {
      bs_trace_raw(1, "Packet received OK - payload (%u bytes):", rx_done_s.packet_size);
      for (uint16_t i = 0; i < rx_done_s.packet_size; i++) {
        bs_trace_raw(1, " %02X", packet_ptr[i]);
      }
      bs_trace_raw(1, "\n");
    } else {
      const char *status_str = "unknown";
      switch (rx_done_s.status) {
        case P2G4_RXSTATUS_CRC_ERROR:       status_str = "CRC/payload error"; break;
        case P2G4_RXSTATUS_HEADER_ERROR:    status_str = "header error"; break;
        case P2G4_RXSTATUS_NOSYNC:          status_str = "no sync"; break;
        case P2G4_RXSTATUS_INPROGRESS:      status_str = "in progress"; break;
        default:                            break;
      }
      bs_trace_warning_line("Packet NOT received (status=%u: %s) at rx_ts=%"PRItime"us\n",
                            rx_done_s.status, status_str, rx_done_s.rx_time_stamp);
    }
    free(packet_ptr);
    packet_ptr = NULL;

    /* Next scan window starts when this one ended + 10us; listen until sim end or disconnect */
    rx_s.start_time = rx_done_s.end_time + 10;
  }

  bs_trace_raw(2, "Simulation ended, terminating and disconnecting from PHY\n");
  p2G4_dev_terminate_c();
  bs_trace_info(1, "Device finished successfully\n");
  return 0;
}
