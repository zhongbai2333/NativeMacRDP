#ifndef MACOS_RDP_EMT_H
#define MACOS_RDP_EMT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDPEMT_SECURITY_COOKIE_LENGTH 16u
#define RDPEMT_MAX_FRAME_LENGTH 65790u

enum {
    RDPEMT_ACTION_CREATE_REQUEST = 0,
    RDPEMT_ACTION_CREATE_RESPONSE = 1,
    RDPEMT_ACTION_DATA = 2,
};

typedef struct {
    uint8_t action;
    uint8_t flags;
    uint8_t header_length;
    const uint8_t *subheaders;
    size_t subheaders_length;
    const uint8_t *payload;
    uint16_t payload_length;
} RDPEMTFrame;

bool rdpemt_parse_frame(const uint8_t *bytes, size_t length,
                        RDPEMTFrame *frame, size_t *consumed);

bool rdpemt_parse_create_request(
    const RDPEMTFrame *frame, uint32_t *request_id,
    uint8_t security_cookie[RDPEMT_SECURITY_COOKIE_LENGTH]);

bool rdpemt_validate_create_request(
    const RDPEMTFrame *frame, uint32_t expected_request_id,
    const uint8_t expected_cookie[RDPEMT_SECURITY_COOKIE_LENGTH]);

bool rdpemt_encode_create_response(uint32_t result,
                                   uint8_t output[8], size_t *length);

bool rdpemt_encode_data(const uint8_t *data, size_t data_length,
                        uint8_t *output, size_t output_capacity,
                        size_t *output_length);

/* Return false to reject the frame and fail the containing tunnel stream. */
typedef bool (*RDPEMTFrameCallback)(void *context, const RDPEMTFrame *frame);
typedef struct RDPEMTDecoder RDPEMTDecoder;

RDPEMTDecoder *rdpemt_decoder_new(RDPEMTFrameCallback callback, void *context);
void rdpemt_decoder_free(RDPEMTDecoder *decoder);

/* Accepts an arbitrarily fragmented TLS plaintext byte stream. */
bool rdpemt_decoder_feed(RDPEMTDecoder *decoder, const uint8_t *bytes,
                         size_t length);

#ifdef __cplusplus
}
#endif

#endif
