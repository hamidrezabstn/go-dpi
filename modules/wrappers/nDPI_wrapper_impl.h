#include <pcap.h>
#ifndef DISABLE_NDPI
#include <libndpi-2.0.0/libndpi/ndpi_main.h>
#endif

extern int ndpiInitialize();
extern void ndpiDestroy(void);
extern u_int16_t *ndpiPacketProcess(const struct pcap_pkthdr*, const u_char*, void*);
extern void *ndpiGetFlow(const struct pcap_pkthdr*, const u_char*);
extern void ndpiFreeFlow(void*);
