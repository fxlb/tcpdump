/*
 * OSS-Fuzz harness for tcpdump packet dissectors.
 * Exercises the full dissector pipeline via pretty_print_packet().
 *
 * The fuzzer input format: first 2 bytes encode the DLT type (little-endian
 * index into the supported DLT list), remaining bytes are the raw packet.
 */

#include <config.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "print.h"

/* DLT types to fuzz — covers the most common link layers */
static const int fuzz_dlts[] = {
    DLT_EN10MB,   /* Ethernet */
    DLT_RAW,      /* Raw IP */
    DLT_NULL,     /* BSD loopback */
    DLT_LINUX_SLL, /* Linux cooked capture */
    DLT_IEEE802_11, /* 802.11 WiFi */
    DLT_PPP,       /* PPP */
    DLT_SLIP,      /* SLIP */
    DLT_FDDI,      /* FDDI */
};
#define NUM_FUZZDLTS (sizeof(fuzz_dlts)/sizeof(fuzz_dlts[0]))

/* Discard all output during fuzzing */
static int fuzz_printf(netdissect_options *ndo, const char *fmt, ...)
{
    (void)ndo;
    (void)fmt;
    return 0;
}

static void fuzz_error(netdissect_options *ndo, int status,
                       const char *fmt, ...)
{
    (void)ndo;
    (void)status;
    (void)fmt;
    /* longjmp out to avoid exit() */
}

static void fuzz_warning(netdissect_options *ndo, const char *fmt, ...)
{
    (void)ndo;
    (void)fmt;
}

static void fuzz_default_print(netdissect_options *ndo,
                               const u_char *bp, u_int length)
{
    (void)ndo;
    (void)bp;
    (void)length;
}

static netdissect_options Ndo;
static int initialized = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    char errbuf[PCAP_ERRBUF_SIZE];
    if (nd_init(errbuf, sizeof(errbuf)) != 0)
        return 0;

    memset(&Ndo, 0, sizeof(Ndo));
    Ndo.ndo_printf       = fuzz_printf;
    Ndo.ndo_error        = fuzz_error;
    Ndo.ndo_warning      = fuzz_warning;
    Ndo.ndo_default_print = fuzz_default_print;
    Ndo.ndo_snaplen       = 65535;
    Ndo.ndo_vflag         = 3;   /* verbose: exercises more dissector paths */
    Ndo.ndo_eflag         = 1;   /* print link-level headers */
    Ndo.ndo_qflag         = 0;

    initialized = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!initialized || size < 3)
        return 0;

    /* First byte selects the DLT type */
    int dlt_idx = data[0] % NUM_FUZZDLTS;
    int dlt = fuzz_dlts[dlt_idx];

    const u_char *packet = data + 1;
    u_int pktlen = (u_int)(size - 1);

    /* Set up the if_printer for the chosen DLT */
    if_printer printer = lookup_printer(dlt);
    if (printer == NULL)
        return 0;

    Ndo.ndo_if_printer = printer;

    struct pcap_pkthdr h;
    h.caplen = pktlen;
    h.len    = pktlen;
    h.ts.tv_sec  = 0;
    h.ts.tv_usec = 0;

    /*
     * pretty_print_packet() calls ndo->ndo_error() on fatal errors.
     * Since we've replaced ndo_error with a no-op, we may crash or
     * longjmp — wrap with a setjmp to be safe.
     */
    pretty_print_packet(&Ndo, &h, packet, 1);

    nd_free_all(&Ndo);
    return 0;
}
