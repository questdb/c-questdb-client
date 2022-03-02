#include "utf8.h"

#include <stdint.h>

// https://tools.ietf.org/html/rfc3629
static const uint8_t utf8_char_width[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x1F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x3F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x5F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x9F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xBF
    0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 0xDF
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 0xEF
    4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xFF
};

static inline bool valid_first_two_bytes_of_three(uint8_t b1, uint8_t b2)
{
    // match (first, next!()) {
    //     (0xE0, 0xA0..=0xBF)
    //     | (0xE1..=0xEC, 0x80..=0xBF)
    //     | (0xED, 0x80..=0x9F)
    //     | (0xEE..=0xEF, 0x80..=0xBF) => {}
    //     _ => err!(Some(1)),
    // }
    if ((b1 == 0xE0) && (0xA0 <= b2) && (b2 <= 0xBF))
        return true;
    if ((0xE1 <= b1) && (b1 <= 0xEC) && (0x80 <= b2) && (b2 <= 0xBF))
        return true;
    if ((b1 == 0xED) && (0x80 <= b2) && (b2 <= 0x9F))
        return true;
    if ((0xEE <= b1) && (b1 <= 0xEF) && (0x80 <= b2) && (b2 <= 0xBF))
        return true;
    return false;
}

static inline bool valid_first_two_bytes_of_four(uint8_t b1, uint8_t b2)
{
    // match (first, next!()) {
    //     (0xF0, 0x90..=0xBF)
    //     | (0xF1..=0xF3, 0x80..=0xBF)
    //     | (0xF4, 0x80..=0x8F) => {}
    //     _ => err!(Some(1)),
    // }
    if ((b1 == 0xF0) && (0x90 <= b2) && (b2 <= 0xBF))
        return true;
    if ((0xF1 <= b1) && (b1 <= 0xF3) && (0x80 <= b2) && (b2 <= 0xBF))
        return true;
    if ((b1 == 0xF4) && (0x80 <= b2) && (b2 <= 0x8F))
        return true;
    return false;
}

// This code is a simplified port of from Rust's implementation to C of
//     fn run_utf8_validation(v: &[u8]) -> Result<(), Utf8Error>
// From:
//     https://github.com/rust-lang/
//         rust/blob/master/library/core/src/str/validations.rs
//
// That code is released under the MIT license:
// See: https://github.com/rust-lang/rust/blob/master/LICENSE-MIT
//
// The Rust code is retained here in comments for easier maintenance.
//
// Due to complexity of porting, this code skips aligned-pointer optimisations
// that can walk through ascii portions of buffers more efficiently.
bool utf8_check(size_t len, const char* buf, utf8_error* err_out)
{
    const uint8_t * v = (const uint8_t*)buf;

    // let len = v.len();
    (void)len;

    // let mut index = 0;
    size_t index = 0;

    // while index < len {
    while (index < len)
    {
        // let old_offset = index;
        const size_t old_offset = index;

        // macro_rules! err {
        //     ($error_len: expr) => {
        //         return Err(Utf8Error {
        //             valid_up_to: old_offset,
        //             error_len: $error_len })
        //     };
        // }
        #define UTF8_ERR(NEED_MORE, ERROR_LEN)     \
            {                                      \
                err_out->valid_up_to = old_offset; \
                err_out->need_more = NEED_MORE;    \
                err_out->error_len = ERROR_LEN;    \
                return false;                      \
            }

        // macro_rules! next {
        //     () => {{
        //         index += 1;
        //         // we needed data, but there was none: error!
        //         if index >= len {
        //             err!(None)
        //         }
        //         v[index]
        //     }};
        // }
        #define UTF8_NEXT()       \
            index += 1;           \
            if (index >= len)     \
                UTF8_ERR(true, 0)

        // let first = v[index];
        const uint8_t first = v[index];

        // if first >= 128 {
        if (first >= 128)
        {
            // let w = UTF8_CHAR_WIDTH[first as usize];
            const uint8_t w = utf8_char_width[(size_t)first];

            // 2-byte encoding is for codepoints  \u{0080} to  \u{07ff}
            //        first  C2 80        last DF BF
            // 3-byte encoding is for codepoints  \u{0800} to  \u{ffff}
            //        first  E0 A0 80     last EF BF BF
            //   excluding surrogates codepoints  \u{d800} to  \u{dfff}
            //               ED A0 80 to       ED BF BF
            // 4-byte encoding is for codepoints \u{1000}0 to \u{10ff}ff
            //        first  F0 90 80 80  last F4 8F BF BF
            //
            // Use the UTF-8 syntax from the RFC
            //
            // https://tools.ietf.org/html/rfc3629
            // UTF8-1      = %x00-7F
            // UTF8-2      = %xC2-DF UTF8-tail
            // UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
            //               %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
            // UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
            //               %xF4 %x80-8F 2( UTF8-tail )

            // match w {
            switch (w)
            {
            case 2:
                {
                    // if next!() as i8 >= -64 {
                    //     err!(Some(1))
                    // }
                    UTF8_NEXT();
                    const int8_t next = (int8_t)v[index];
                    if (next >= -64)
                        UTF8_ERR(false, 1);
                }
                break;

            case 3:
                {
                    // match (first, next!()) {
                    //     (0xE0, 0xA0..=0xBF)
                    //     | (0xE1..=0xEC, 0x80..=0xBF)
                    //     | (0xED, 0x80..=0x9F)
                    //     | (0xEE..=0xEF, 0x80..=0xBF) => {}
                    //     _ => err!(Some(1)),
                    // }
                    UTF8_NEXT();
                    const uint8_t second = v[index];
                    if (!valid_first_two_bytes_of_three(first, second))
                        UTF8_ERR(false, 1);

                    // if next!() as i8 >= -64 {
                    //     err!(Some(2))
                    // }
                    UTF8_NEXT();
                    const int8_t third = (int8_t)v[index];
                    if (third >= -64)
                        UTF8_ERR(false, 2);
                }
                break;

            case 4:
                {
                    // match (first, next!()) {
                    //     (0xF0, 0x90..=0xBF) | (0xF1..=0xF3, 0x80..=0xBF) | (0xF4, 0x80..=0x8F) => {}
                    //     _ => err!(Some(1)),
                    // }
                    UTF8_NEXT();
                    const uint8_t second = v[index];
                    if (!valid_first_two_bytes_of_four(first, second))
                        UTF8_ERR(false, 1);

                    // if next!() as i8 >= -64 {
                    //     err!(Some(2))
                    // }
                    UTF8_NEXT();
                    const int8_t third = (int8_t)v[index];
                    if (third >= -64)
                        UTF8_ERR(false, 2);

                    // if next!() as i8 >= -64 {
                    //     err!(Some(3))
                    // }
                    UTF8_NEXT();
                    const int8_t fourth = (int8_t)v[index];
                    if (fourth >= -64)
                        UTF8_ERR(false, 3);
                }
                break;

            default:
                // _ => err!(Some(1)),
                UTF8_ERR(false, 1);
            }

            // index += 1;
            ++index;
        }
        else
        {
            // index += 1;
            ++index;
        }
    }
    return true;
}

#undef UTF8_ERR
#undef UTF8_NEXT
