/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_CRYPTO
#include "crypto.h"
#include "session_id.h"

#include "socket_crypt.h"

static struct key_type
socket_crypt_kt(void)
{
    struct key_type kt;
    kt.cipher = cipher_kt_get("AES-256-CTR");
    kt.digest = md_kt_get("SHA256");

    if (!kt.cipher)
    {
        msg(M_WARN, "ERROR: --socket-crypt requires AES-256-CTR support.");
        return (struct key_type) { 0 };
    }
    if (!kt.digest)
    {
        msg(M_WARN, "ERROR: --socket-crypt requires HMAC-SHA-256 support.");
        return (struct key_type) { 0 };
    }

    kt.cipher_length = cipher_kt_key_size(kt.cipher);
    kt.hmac_length = md_kt_size(kt.digest);

    return kt;
}

int
socket_crypt_buf_overhead(void)
{
    return SOCK_CRYPT_IV_SIZE + SOCK_CRYPT_TAG_SIZE + SOCK_CRYPT_BLOCK_SIZE + 1 + SOCK_MAX_RND_SIZE;
}

void
socket_crypt_init_key(struct key_ctx_bi *key, const char *key_file,
                   const char *key_inline, bool tls_server)
{
    const int key_direction = tls_server ?
                              KEY_DIRECTION_NORMAL : KEY_DIRECTION_INVERSE;
    struct key_type kt = socket_crypt_kt();
    if (!kt.cipher || !kt.digest)
    {
        msg (M_FATAL, "ERROR: --socket-crypt not supported");
    }
    crypto_read_openvpn_key(&kt, key, key_file, key_inline, key_direction,
                            "Transport Layer Encryption", "socket-crypt");
}

void
socket_crypt_adjust_frame_parameters(struct frame *frame)
{
    frame_add_to_extra_frame(frame, socket_crypt_buf_overhead());

    msg(D_MTU_DEBUG, "%s: Adjusting frame parameters for socket-crypt by %i bytes",
        __func__, socket_crypt_buf_overhead());
}


bool
socket_crypt_wrap(const struct buffer *src, struct buffer *dst,
               struct key_ctx_bi *key)
{
    const struct key_ctx *ctx = &key->encrypt;
    struct gc_arena gc;
    
    buf_clear(dst);
    dst->offset = sizeof(uint16_t);

    /* IV and implicit IV required for this mode. */
    ASSERT(ctx->cipher);
    ASSERT(ctx->hmac);
    ASSERT(hmac_ctx_size(ctx->hmac) == 256/8);

    gc_init(&gc);
    
    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP FROM: len->%d", BLEN(src));

    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP FROM: %s",
         format_hex(BPTR(src), BLEN(src), 80, &gc));


    /* Buffer overflow check */
    if (!buf_safe(dst, BLEN(src) + socket_crypt_buf_overhead()))
    {
        msg(D_CRYPT_ERRORS, "SOCKET-CRYPT WRAP: buffer size error, "
            "sc=%d so=%d sl=%d dc=%d do=%d dl=%d", src->capacity, src->offset,
            src->len, dst->capacity, dst->offset, dst->len);
        goto err;
    }
    
    /* Calculate random IV */
    {
        uint8_t *iv = NULL;
        ASSERT(iv = buf_write_alloc(dst, SOCK_CRYPT_IV_SIZE));
        ASSERT(rand_bytes(iv, SOCK_CRYPT_IV_SIZE));
        ASSERT(cipher_ctx_reset(ctx->cipher, iv));
    }
    
    /* Allocate auth tag */
    uint8_t *tag = NULL;
    ASSERT(tag = buf_write_alloc(dst, SOCK_CRYPT_TAG_SIZE));
    
    /* Create random length random sequence */
    uint8_t rand_len = random_uniform(SOCK_MAX_RND_SIZE - SOCK_MIN_RND_SIZE + 1)
                       + SOCK_MIN_RND_SIZE;
    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP: rand_len = %u", rand_len);
    
    uint8_t *rnd_seq = NULL;
    ASSERT(rnd_seq = malloc(rand_len));
    ASSERT(rand_bytes(rnd_seq, rand_len));
    
    /* Encrypt the rnd_seq + src + rnd_seq_len */
    {
        int outlen = 0;
        
        // rnd_seq
        ASSERT(cipher_ctx_update(ctx->cipher, BEND(dst), &outlen,
                                 rnd_seq, rand_len));
        ASSERT(buf_inc_len(dst, outlen));
        
        // src data
        ASSERT(cipher_ctx_update(ctx->cipher, BEND(dst), &outlen,
                                 BPTR(src), BLEN(src)));
        ASSERT(buf_inc_len(dst, outlen));
        
        // rand_len
        ASSERT(cipher_ctx_update(ctx->cipher, BEND(dst), &outlen,
                                 &rand_len, 1));
        ASSERT(buf_inc_len(dst, outlen));
        
        // PKCS padding
        ASSERT(cipher_ctx_final(ctx->cipher, BEND(dst), &outlen));
        ASSERT(buf_inc_len(dst, outlen));
    }
    
    // Free the rnd_seq
    free(rnd_seq);
    
    /* Calculate auth tag */
    {
        hmac_ctx_reset(ctx->hmac);
        hmac_ctx_update(ctx->hmac, BPTR(dst), SOCK_CRYPT_IV_SIZE);
        hmac_ctx_update(ctx->hmac, BPTR(dst) + SOCK_CRYPT_OFF_ED,
                        BLEN(dst) - SOCK_CRYPT_IV_SIZE - SOCK_CRYPT_TAG_SIZE);

        hmac_ctx_final(ctx->hmac, tag);
        
        dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP TAG PTR: 0x%lx (0x%lx)", tag, BPTR(dst) + SOCK_CRYPT_OFF_TAG);
        dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP TAG: %s",
             format_hex(tag, SOCK_CRYPT_TAG_SIZE, 0, &gc));
    }
    
    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP To: len->%d", BLEN(dst));
    
    /*const md_kt_t *md5_k = md_kt_get("MD5");
    int hash_len = md_kt_size(md5_k);
    uint8_t *hash = malloc(hash_len);
    if (md_full(md5_k, BPTR(dst), BLEN(dst), hash))
        msg(M_WARN, "TLS-CRYPT WRAP hash: %s", format_hex(hash, hash_len, 80, &gc));
    else
        msg(M_WARN, "TLS-CRYPT WRAP hash: Failed!!!");
    free(hash);*/
    
    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT WRAP TO: %s",
         format_hex(BPTR(dst), BLEN(dst), 80, &gc));

    gc_free(&gc);
    return true;

err:
    crypto_clear_error();
    dst->len = 0;
    gc_free(&gc);
    return false;
}

bool
socket_crypt_unwrap(const struct buffer *src, struct buffer *dst,
                 struct key_ctx_bi *key)
{
    static const char error_prefix[] = "socket-crypt unwrap error";
    const struct key_ctx *ctx = &key->decrypt;
    struct gc_arena gc;
    
    buf_clear(dst);

    gc_init(&gc);

    ASSERT(src->len > 0);
    ASSERT(ctx->cipher);
    
    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT UNWRAP FROM: len->%d", BLEN(src));
    
    /*const md_kt_t *md5_k = md_kt_get("MD5");
    int hash_len = md_kt_size(md5_k);
    uint8_t *hash = malloc(hash_len);
    if (md_full(md5_k, BPTR(src), BLEN(src), hash))
        msg(M_WARN, "TLS-CRYPT UNWRAP hash: %s", format_hex(hash, hash_len, 80, &gc));
    else
        msg(M_WARN, "TLS-CRYPT UNWRAP hash: Failed!!!");
    free(hash);

    msg(M_WARN, "SOCKET-CRYPT UNWRAP FROM: %s",
         format_hex(BPTR(src), BLEN(src), 80, &gc));*/

    /* Authenticate IV + cipher text */
    {
        const uint8_t *tag = BPTR(src) + SOCK_CRYPT_OFF_TAG;
        uint8_t tag_check[SOCK_CRYPT_TAG_SIZE] = { 0 };
        
        hmac_ctx_reset(ctx->hmac);
        hmac_ctx_update(ctx->hmac, BPTR(src), SOCK_CRYPT_IV_SIZE);
        hmac_ctx_update(ctx->hmac, BPTR(src) + SOCK_CRYPT_OFF_ED,
                        BLEN(src) - SOCK_CRYPT_IV_SIZE - SOCK_CRYPT_TAG_SIZE);
        hmac_ctx_final(ctx->hmac, tag_check);
        
        if (memcmp_constant_time(tag, tag_check, sizeof(tag_check)))
        {
            dmsg(D_CRYPTO_DEBUG, "tag      : %s",
                 format_hex(tag, sizeof(tag_check), 0, &gc));
            dmsg(D_CRYPTO_DEBUG, "tag_check: %s",
                 format_hex(tag_check, sizeof(tag_check), 0, &gc));
            CRYPT_ERROR("packet authentication failed");
        }
    }

    /* Decrypt cipher text */
    {
        int outlen = 0;

        /* Buffer overflow check (should never fail) */
        if (!buf_safe(dst, BLEN(src) - SOCK_CRYPT_IV_SIZE - SOCK_CRYPT_TAG_SIZE + SOCK_CRYPT_BLOCK_SIZE))
        {
            CRYPT_ERROR("potential buffer overflow");
        }

        if (!cipher_ctx_reset(ctx->cipher, BPTR(src) + SOCK_CRYPT_OFF_IV))
        {
            CRYPT_ERROR("cipher reset failed");
        }
        if (!cipher_ctx_update(ctx->cipher, BPTR(dst), &outlen,
                               BPTR(src) + SOCK_CRYPT_OFF_ED, BLEN(src) - SOCK_CRYPT_IV_SIZE - SOCK_CRYPT_TAG_SIZE))
        {
            CRYPT_ERROR("cipher update failed");
        }
        ASSERT(buf_inc_len(dst, outlen));
        if (!cipher_ctx_final(ctx->cipher, BPTR(dst), &outlen))
        {
            CRYPT_ERROR("cipher final failed");
        }
        ASSERT(buf_inc_len(dst, outlen));
        
        dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT UNWRAP Decrypted: %s",
             format_hex(BPTR(dst), BLEN(dst), 80, &gc));
    }
    
    /* Strip the random length rnd_seq */
    {
        uint8_t rand_len = *BLAST(dst);
        ASSERT(buf_advance(dst, rand_len));
        ASSERT(buf_inc_len(dst, -1));
    }
    
    dmsg(D_PACKET_CONTENT, "SOCKET-CRYPT UNWRAP TO: len->%d", BLEN(dst));

    gc_free(&gc);
    return true;

error_exit:
    crypto_clear_error();
    dst->len = 0;
    gc_free(&gc);
    return false;
}

#endif /* ENABLE_CRYPTO */
