#include <std/mem.pat>
#include <std/core.pat>

#pragma endian big

using NetString;
using NetSequence;

struct NetString {
    u16 length;
    if (length > 0) {
        char data[length];
    }
} [[format("format_net_string")]] ;

fn format_net_string(NetString val) {
    if (val.length > 0) {
        return val.data;
    } else {
        return "";
    }
};

struct NetSequence {
    u16 length;
    if (length > 0) {
        u8 data[length];
    }
};

// SItemGrid in Selection Screen appears to be fixed 48 bytes based on packet size analysis
struct SItemGrid {
    u16 id;
    if (id > 0) {
        u16 num;
        u16 endure[2];
        u16 energy[2];
        u8 forge_lv;
        u8 is_valid;
        u8 tradable;
        u8 padding;
        u32 expiration;
        u32 db_params[2];
        u16 inst_attrs[5][2];
    } else {
        u8 padding[46];
    }
} [[static]];

struct SelectCharacter {
    NetString name;
    NetString job;
    u16 degree;
    u16 type_id;
    SItemGrid equipment[34];
};

struct CMD_CM_LOGIN_PKT {
    u32 wpe_counter;
    NetString account;
    NetString password;
    NetString session_key;
    NetString mac_address;
    u16 code_911;
    u16 client_ver;
    u16 trailer;
};

struct CMD_MC_LOGIN_PKT {
    u16 error_code;
    NetSequence server_key;
    u8 max_chars;
    u8 num_chars;
    SelectCharacter characters[num_chars];
    u8 pass_flag;
    u32 account_id;
};

struct PacketHeader {
    u16 length;
    u32 session_id;
    u16 command_id;
};

struct Packet {
    PacketHeader header;

    if (header.command_id == 0x01AF) {
        CMD_CM_LOGIN_PKT body;
    } else if (header.command_id == 0x03A3) {
        CMD_MC_LOGIN_PKT body;
    } else {
        u8 body[header.length - 8];
    }
} [[single_color]];

Packet packets[while(!std::mem::eof())] @ 0x00;
