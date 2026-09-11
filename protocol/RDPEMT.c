#include "protocol/RDPEMT.h"

#include <stdlib.h>
#include <string.h>

struct RDPEMTDecoder {
    uint8_t *buffer;
    size_t length;
    RDPEMTFrameCallback callback;
    void *context;
};

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void write_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static bool subheaders_are_well_formed(const uint8_t *bytes, size_t length) {
    size_t cursor = 0;
    while (cursor < length) {
        if (length - cursor < 2) return false;
        uint8_t subheader_length = bytes[cursor];
        uint8_t subheader_type = bytes[cursor + 1];
        if (subheader_length < 2 || subheader_length > length - cursor)
            return false;
        /* MS-RDPEMT 2.2.1.1.1 defines only auto-detect request (0) and
         * auto-detect response (1). Unknown types cannot be safely ignored:
         * their length may be syntactically valid while their semantics alter
         * tunnel processing. */
        if (subheader_type > 1) return false;
        cursor += subheader_length;
    }
    return cursor == length;
}

bool rdpemt_parse_frame(const uint8_t *bytes, size_t length,
                        RDPEMTFrame *frame, size_t *consumed) {
    if (!bytes || !frame || !consumed) return false;
    *consumed = 0;
    if (length < 4) return true;

    uint8_t header_length = bytes[3];
    uint16_t payload_length = read_le16(bytes + 1);
    if (header_length < 4) return false;
    size_t total = (size_t)header_length + payload_length;
    if (total > RDPEMT_MAX_FRAME_LENGTH) return false;
    if (length < total) return true;
    if ((bytes[0] >> 4) != 0 || (bytes[0] & 0x0f) > RDPEMT_ACTION_DATA ||
        !subheaders_are_well_formed(bytes + 4, header_length - 4))
        return false;

    memset(frame, 0, sizeof(*frame));
    frame->action = bytes[0] & 0x0f;
    frame->flags = bytes[0] >> 4;
    frame->header_length = header_length;
    frame->subheaders = bytes + 4;
    frame->subheaders_length = header_length - 4;
    frame->payload = bytes + header_length;
    frame->payload_length = payload_length;
    *consumed = total;
    return true;
}

bool rdpemt_parse_create_request(
    const RDPEMTFrame *frame, uint32_t *request_id,
    uint8_t security_cookie[RDPEMT_SECURITY_COOKIE_LENGTH]) {
    if (!frame || frame->action != RDPEMT_ACTION_CREATE_REQUEST ||
        frame->flags != 0 || frame->header_length != 4 ||
        frame->payload_length != 24 || !frame->payload ||
        read_le32(frame->payload + 4) != 0)
        return false;
    if (request_id) *request_id = read_le32(frame->payload);
    if (security_cookie)
        memcpy(security_cookie, frame->payload + 8,
               RDPEMT_SECURITY_COOKIE_LENGTH);
    return true;
}

static bool constant_time_equal(const uint8_t *a, const uint8_t *b,
                                size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; i++) difference |= a[i] ^ b[i];
    return difference == 0;
}

bool rdpemt_validate_create_request(
    const RDPEMTFrame *frame, uint32_t expected_request_id,
    const uint8_t expected_cookie[RDPEMT_SECURITY_COOKIE_LENGTH]) {
    uint32_t request_id = 0;
    uint8_t cookie[RDPEMT_SECURITY_COOKIE_LENGTH];
    if (!expected_cookie ||
        !rdpemt_parse_create_request(frame, &request_id, cookie))
        return false;
    return request_id == expected_request_id &&
           constant_time_equal(cookie, expected_cookie, sizeof(cookie));
}

bool rdpemt_encode_create_response(uint32_t result,
                                   uint8_t output[8], size_t *length) {
    if (!output || !length) return false;
    output[0] = RDPEMT_ACTION_CREATE_RESPONSE;
    write_le16(output + 1, 4);
    output[3] = 4;
    write_le32(output + 4, result);
    *length = 8;
    return true;
}

bool rdpemt_encode_data(const uint8_t *data, size_t data_length,
                        uint8_t *output, size_t output_capacity,
                        size_t *output_length) {
    if (!output || !output_length || (!data && data_length) ||
        data_length > UINT16_MAX || output_capacity < data_length + 4)
        return false;
    output[0] = RDPEMT_ACTION_DATA;
    write_le16(output + 1, (uint16_t)data_length);
    output[3] = 4;
    if (data_length) memcpy(output + 4, data, data_length);
    *output_length = data_length + 4;
    return true;
}

RDPEMTDecoder *rdpemt_decoder_new(RDPEMTFrameCallback callback, void *context) {
    if (!callback) return NULL;
    RDPEMTDecoder *decoder = calloc(1, sizeof(*decoder));
    if (!decoder) return NULL;
    decoder->buffer = malloc(RDPEMT_MAX_FRAME_LENGTH);
    if (!decoder->buffer) {
        free(decoder);
        return NULL;
    }
    decoder->callback = callback;
    decoder->context = context;
    return decoder;
}

void rdpemt_decoder_free(RDPEMTDecoder *decoder) {
    if (!decoder) return;
    free(decoder->buffer);
    free(decoder);
}

bool rdpemt_decoder_feed(RDPEMTDecoder *decoder, const uint8_t *bytes,
                         size_t length) {
    if (!decoder || (!bytes && length) ||
        length > RDPEMT_MAX_FRAME_LENGTH - decoder->length)
        return false;
    if (length) {
        memcpy(decoder->buffer + decoder->length, bytes, length);
        decoder->length += length;
    }

    while (decoder->length) {
        RDPEMTFrame frame;
        size_t consumed = 0;
        if (!rdpemt_parse_frame(decoder->buffer, decoder->length,
                                &frame, &consumed))
            return false;
        if (!consumed) return true;
        if (!decoder->callback(decoder->context, &frame)) return false;
        decoder->length -= consumed;
        if (decoder->length)
            memmove(decoder->buffer, decoder->buffer + consumed,
                    decoder->length);
    }
    return true;
}
