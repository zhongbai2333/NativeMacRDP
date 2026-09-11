#include <freerdp/codec/color.h>
#include <freerdp/codec/progressive.h>
#include <freerdp/codec/region.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { TEST_WIDTH = 512, TEST_HEIGHT = 320, TEST_QUANT_COUNT = 10 };

static const UINT32 normalQuant[TEST_QUANT_COUNT] = {
    6u, 6u, 6u, 6u, 7u, 7u, 8u, 8u, 8u, 9u
};

static void fill_chroma_safe_motion_quants(uint8_t step,
                                           UINT32 values[30]) {
    for (size_t component = 0; component < 3u; component++) {
        for (size_t band = 0; band < TEST_QUANT_COUNT; band++) {
            UINT32 value = normalQuant[band];
            if (component == 0u && band >= 4u)
                value += step;
            values[component * TEST_QUANT_COUNT + band] = value;
        }
    }
}

static void fill_motion_frame(uint8_t *pixels) {
    for (uint32_t y = 0; y < TEST_HEIGHT; y++) {
        for (uint32_t x = 0; x < TEST_WIDTH; x++) {
            uint8_t *p = pixels + ((size_t)y * TEST_WIDTH + x) * 4u;
            const uint32_t detail = (x * 17u) ^ (y * 29u) ^ (x * y);
            p[0] = (uint8_t)(detail + x * 3u);
            p[1] = (uint8_t)((detail >> 3u) + y * 5u);
            p[2] = (uint8_t)((x * 7u + y * 11u) ^ (detail >> 5u));
            p[3] = 0xFFu;
        }
    }
}

static uint32_t encode_and_decode(const uint8_t *source, uint8_t quantStep,
                                  double *meanAbsoluteError) {
    PROGRESSIVE_CONTEXT *encoder = progressive_context_new(TRUE);
    PROGRESSIVE_CONTEXT *decoder = progressive_context_new(FALSE);
    assert(encoder && decoder);

    if (quantStep) {
        UINT32 quant[3u * TEST_QUANT_COUNT] = {0};
        fill_chroma_safe_motion_quants(quantStep, quant);
        assert(progressive_context_set_quantization(
            encoder, quant, 3u * TEST_QUANT_COUNT));
    }

    assert(progressive_create_surface_context(
               decoder, 1u, TEST_WIDTH, TEST_HEIGHT) >= 0);
    REGION16 full;
    region16_init(&full);
    RECTANGLE_16 bounds = { .left = 0u, .top = 0u,
                            .right = TEST_WIDTH, .bottom = TEST_HEIGHT };
    assert(region16_union_rect(&full, &full, &bounds));

    BYTE *compressed = NULL;
    UINT32 compressedSize = 0u;
    const UINT32 stride = TEST_WIDTH * 4u;
    assert(progressive_compress(
               encoder, source, stride * TEST_HEIGHT, PIXEL_FORMAT_BGRA32,
               TEST_WIDTH, TEST_HEIGHT, stride, &full,
               &compressed, &compressedSize) > 0);
    assert(compressed && compressedSize > 0u);

    uint8_t *decoded = calloc((size_t)stride, TEST_HEIGHT);
    assert(decoded);
    REGION16 decodedRegion;
    region16_init(&decodedRegion);
    assert(progressive_decompress(
               decoder, compressed, compressedSize, decoded,
               PIXEL_FORMAT_BGRA32, stride, 0u, 0u, &decodedRegion,
               1u, 1u) > 0);

    uint64_t error = 0u;
    const size_t pixels = (size_t)TEST_WIDTH * TEST_HEIGHT;
    for (size_t i = 0; i < pixels; i++) {
        for (size_t channel = 0; channel < 3u; channel++) {
            const int a = source[i * 4u + channel];
            const int b = decoded[i * 4u + channel];
            error += (uint64_t)(a > b ? a - b : b - a);
        }
    }
    *meanAbsoluteError = (double)error / (double)(pixels * 3u);

    region16_uninit(&decodedRegion);
    region16_uninit(&full);
    free(decoded);
    progressive_context_free(decoder);
    progressive_context_free(encoder);
    return compressedSize;
}

static void test_live_quality_switch(uint8_t *source) {
    UINT32 motionQuant[3u * TEST_QUANT_COUNT] = {0};
    UINT32 fullQualityQuant[3u * TEST_QUANT_COUNT] = {0};
    fill_chroma_safe_motion_quants(3u, motionQuant);
    fill_chroma_safe_motion_quants(0u, fullQualityQuant);

    PROGRESSIVE_CONTEXT *encoder = progressive_context_new(TRUE);
    PROGRESSIVE_CONTEXT *decoder = progressive_context_new(FALSE);
    assert(encoder && decoder);
    assert(progressive_create_surface_context(
               decoder, 1u, TEST_WIDTH, TEST_HEIGHT) >= 0);

    REGION16 full;
    REGION16 decodedRegion;
    region16_init(&full);
    region16_init(&decodedRegion);
    RECTANGLE_16 bounds = { .left = 0u, .top = 0u,
                            .right = TEST_WIDTH, .bottom = TEST_HEIGHT };
    assert(region16_union_rect(&full, &full, &bounds));
    const UINT32 stride = TEST_WIDTH * 4u;
    uint8_t *decoded = calloc((size_t)stride, TEST_HEIGHT);
    assert(decoded);

    for (UINT32 frame = 1u; frame <= 3u; frame++) {
        if (frame == 2u)
            assert(progressive_context_set_quantization(
                encoder, motionQuant, 3u * TEST_QUANT_COUNT));
        else if (frame == 3u)
            assert(progressive_context_set_quantization(
                encoder, fullQualityQuant, 3u * TEST_QUANT_COUNT));

        for (size_t i = 0; i < (size_t)TEST_WIDTH * TEST_HEIGHT; i++)
            source[i * 4u + (frame - 1u)] ^= (uint8_t)(i + frame * 13u);
        BYTE *compressed = NULL;
        UINT32 compressedSize = 0u;
        assert(progressive_compress(
                   encoder, source, stride * TEST_HEIGHT,
                   PIXEL_FORMAT_BGRA32, TEST_WIDTH, TEST_HEIGHT, stride,
                   &full, &compressed, &compressedSize) > 0);
        assert(progressive_decompress(
                   decoder, compressed, compressedSize, decoded,
                   PIXEL_FORMAT_BGRA32, stride, 0u, 0u, &decodedRegion,
                   1u, frame) > 0);
    }

    free(decoded);
    region16_uninit(&decodedRegion);
    region16_uninit(&full);
    progressive_context_free(decoder);
    progressive_context_free(encoder);
}

int main(void) {
    const size_t bytes = (size_t)TEST_WIDTH * TEST_HEIGHT * 4u;
    uint8_t *source = malloc(bytes);
    assert(source);
    fill_motion_frame(source);

    double normalError = 0.0;
    double motionError = 0.0;
    const uint32_t normalSize = encode_and_decode(source, 0u, &normalError);
    const uint32_t motionSize = encode_and_decode(source, 3u, &motionError);
    assert(motionSize < normalSize);
    assert(motionError < 35.0);
    printf("progressive quantization: normal=%u motion=%u reduction=%.1f%% "
           "mae=%.2f/%.2f\n",
           normalSize, motionSize,
           100.0 * (double)(normalSize - motionSize) / (double)normalSize,
           normalError, motionError);
    test_live_quality_switch(source);
    free(source);
    return 0;
}
