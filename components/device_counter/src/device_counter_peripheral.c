#include "bsim_device_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include "bs_tracing.h"
#include "bs_oswrap.h"
#include "bs_cmd_line.h"
#include "bs_cmd_line_typical.h"
#include "bs_pc_base.h"

typedef bs_basic_dev_args_t counter_args_t;

char executable_name[] = "bs_device_peripheral";
counter_args_t args;

static pb_dev_state_t pcom_dev_state;

static uint8_t clean_up() {
    bs_trace_raw(8,"Cleaning up\n");
    pb_dev_clean_up(&pcom_dev_state);
    return 0;
}

static void signal_end_handler(int sig) {
    bs_trace_raw(2,"Signal \"%s\" received\n", strsignal(sig));
}

void counter_argparse(int argc, char *argv[], counter_args_t *args) {
    bs_args_struct_t args_struct[] = {
        BS_BASIC_DEVICE_2G4_FAKE_OPTIONS_ARG_STRUCT,
        ARG_TABLE_ENDMARKER
    };

    bs_args_typical_dev_set_defaults((bs_basic_dev_args_t *)args, args_struct);
    static char default_phy[] ="2G4";
    bs_args_parse_cmd_line(argc, argv, args_struct);
    bs_args_typical_dev_post_check((bs_basic_dev_args_t *)args, args_struct, default_phy);
}

int main(int argc, char *argv[]) {
    bs_trace_register_cleanup_function(clean_up);
    bs_set_sig_term_handler(signal_end_handler, (int[]){SIGTERM, SIGINT}, 2);

    counter_argparse(argc, argv, &args);

    pb_dev_init_com(&pcom_dev_state, args.device_nbr, args.s_id, args.p_id);

    uint8_t buf[16];
    int len;

    while (1) {
        len = pb_dev_receive_packet(&pcom_dev_state, buf, sizeof(buf));
        if(len > 0) {
            printf("Peripheral received: %d\n", buf[0]);
            fflush(stdout);
        }
    }

    pb_dev_disconnect(&pcom_dev_state);
    return 0;
}
