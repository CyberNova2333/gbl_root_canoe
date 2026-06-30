/*
 * vbmetarehash - make a third-party recovery pass AVB *hash* verification by
 * rebuilding the recovery vbmeta so its hash descriptor matches the new image.
 *
 * The plain "transplant" tool copies the stock recovery vbmeta onto a new
 * image. That keeps the stock image's hash, so a modified/third-party recovery
 * fails the descriptor hash check on a (fake-)locked bootloader. This tool
 * instead:
 *   1. parses the stock recovery vbmeta and its AvbHashDescriptor,
 *   2. recomputes the descriptor digest = HASH(salt || new_image),
 *   3. writes the new image_size + digest into the descriptor,
 *   4. recomputes the vbmeta authentication (integrity) hash over header+aux,
 *   5. attaches the rebuilt vbmeta + AVB footer to the new image.
 *
 * The vbmeta SIGNATURE is left as-is (we cannot re-sign with the OEM key). So
 * the output passes vbmeta-integrity and image-hash checks, and will boot iff
 * the recovery path does NOT additionally enforce the signature. That is the
 * one thing only on-device testing can confirm; if it still loops, the
 * recovery path checks the signature and only an ABL patch can help.
 *
 * Usage: vbmetarehash <stock_recovery.vbmeta> <new_recovery.img> <output.img>
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha2.h"

#define AVB_MAGIC "AVB0"
#define AVB_VBMETA_IMAGE_HEADER_SIZE 256
#define AVB_FOOTER_MAGIC "AVBf"
#define AVB_FOOTER_SIZE 64
#define AVB_DESCRIPTOR_TAG_HASH 2

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static uint64_t be64(const uint8_t *p) {
    return ((uint64_t)be32(p)<<32)|be32(p+4);
}
static void put_be32(uint8_t *p, uint32_t v) {
    p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v;
}
static void put_be64(uint8_t *p, uint64_t v) {
    put_be32(p, (uint32_t)(v>>32)); put_be32(p+4, (uint32_t)v);
}

static uint8_t *read_file(const char *path, size_t *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *b = malloc(sz);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, sz, f) != (size_t)sz) { free(b); fclose(f); return NULL; }
    fclose(f); *out = sz; return b;
}
static int write_file(const char *path, const uint8_t *d, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fwrite(d, 1, n, f) == n;
    fclose(f); return ok ? 0 : -1;
}

/* hash = HASH_alg(salt || data[0:len]); returns digest length or 0 on error */
static size_t hash_image(const char *alg, const uint8_t *salt, size_t salt_len,
                         const uint8_t *data, size_t len, uint8_t out[64]) {
    if (strcmp(alg, "sha256") == 0) {
        sha256_ctx c; sha256_init(&c);
        if (salt_len) sha256_update(&c, salt, salt_len);
        sha256_update(&c, data, len);
        sha256_final(&c, out);
        return 32;
    } else if (strcmp(alg, "sha512") == 0) {
        sha512_ctx c; sha512_init(&c);
        if (salt_len) sha512_update(&c, salt, salt_len);
        sha512_update(&c, data, len);
        sha512_final(&c, out);
        return 64;
    }
    return 0;
}

/* recompute vbmeta authentication hash over header(256) || aux_block */
static int recompute_auth_hash(uint8_t *vb, size_t vb_size) {
    if (vb_size < AVB_VBMETA_IMAGE_HEADER_SIZE) return -1;
    uint32_t alg   = be32(vb + 0x1c);
    uint64_t auth  = be64(vb + 0x0c);
    uint64_t aux   = be64(vb + 0x14);
    uint64_t h_off = be64(vb + 0x20);
    uint64_t h_sz  = be64(vb + 0x28);
    if (alg == 0) return 0;                 /* unsigned: no auth hash */
    size_t aux_start = AVB_VBMETA_IMAGE_HEADER_SIZE + (size_t)auth;
    if (aux_start + aux > vb_size) return -1;
    if (AVB_VBMETA_IMAGE_HEADER_SIZE + h_off + h_sz > AVB_VBMETA_IMAGE_HEADER_SIZE + auth)
        return -1;
    uint8_t digest[64];
    size_t dlen;
    if (alg >= 1 && alg <= 3) {             /* SHA256_RSA* */
        sha256_ctx c; sha256_init(&c);
        sha256_update(&c, vb, AVB_VBMETA_IMAGE_HEADER_SIZE);
        sha256_update(&c, vb + aux_start, (size_t)aux);
        sha256_final(&c, digest); dlen = 32;
    } else if (alg >= 4 && alg <= 6) {      /* SHA512_RSA* */
        sha512_ctx c; sha512_init(&c);
        sha512_update(&c, vb, AVB_VBMETA_IMAGE_HEADER_SIZE);
        sha512_update(&c, vb + aux_start, (size_t)aux);
        sha512_final(&c, digest); dlen = 64;
    } else {
        fprintf(stderr, "Unsupported vbmeta algorithm_type %u\n", alg);
        return -1;
    }
    if (dlen != h_sz) {
        fprintf(stderr, "vbmeta hash_size %llu != alg digest %zu\n",
                (unsigned long long)h_sz, dlen);
        return -1;
    }
    memcpy(vb + AVB_VBMETA_IMAGE_HEADER_SIZE + h_off, digest, dlen);
    return 0;
}

/* read AVBf footer at end of image; sets *orig (original image size) */
static int read_footer_orig(const uint8_t *d, size_t n, uint64_t *orig) {
    if (n < AVB_FOOTER_SIZE) return 0;
    const uint8_t *f = d + n - AVB_FOOTER_SIZE;
    if (memcmp(f, AVB_FOOTER_MAGIC, 4) != 0) return 0;
    *orig = be64(f + 12);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("Usage: %s <stock_recovery.vbmeta> <new_recovery.img> "
               "<partition_size> <output.img>\n", argv[0]);
        printf("  partition_size: recovery partition size in bytes "
               "(e.g. 104857600 for 100 MiB). The footer is placed at the very\n"
               "  end of the partition, where the bootloader looks for it, so the\n"
               "  output is exactly partition_size bytes.\n");
        return 1;
    }
    const char *vb_path = argv[1], *img_path = argv[2], *out_path = argv[4];
    uint64_t partition_size = strtoull(argv[3], NULL, 0);
    if (partition_size < AVB_VBMETA_IMAGE_HEADER_SIZE + AVB_FOOTER_SIZE) {
        fprintf(stderr, "Invalid partition_size '%s'\n", argv[3]);
        return 1;
    }

    size_t vb_size, img_size;
    uint8_t *vb = read_file(vb_path, &vb_size);
    if (!vb) { fprintf(stderr, "Cannot read vbmeta: %s\n", vb_path); return 1; }
    uint8_t *img = read_file(img_path, &img_size);
    if (!img) { fprintf(stderr, "Cannot read image: %s\n", img_path); free(vb); return 1; }

    if (vb_size < AVB_VBMETA_IMAGE_HEADER_SIZE || memcmp(vb, AVB_MAGIC, 4) != 0) {
        fprintf(stderr, "Source is not a valid VBMeta blob ('AVB0' missing)\n");
        free(vb); free(img); return 1;
    }

    /* --- locate the hash descriptor in the aux block --- */
    uint64_t auth = be64(vb + 0x0c);
    uint64_t aux  = be64(vb + 0x14);
    uint64_t desc_off = be64(vb + 0x60);
    uint64_t desc_sz  = be64(vb + 0x68);
    size_t aux_start = AVB_VBMETA_IMAGE_HEADER_SIZE + (size_t)auth;
    if (aux_start + aux > vb_size || desc_off + desc_sz > aux) {
        fprintf(stderr, "Malformed vbmeta (block sizes out of range)\n");
        free(vb); free(img); return 1;
    }
    uint8_t *descs = vb + aux_start + desc_off;

    size_t off = 0, hash_desc = (size_t)-1;
    while (off + 16 <= desc_sz) {
        uint64_t tag = be64(descs + off);
        uint64_t nb  = be64(descs + off + 8);
        if (off + 16 + nb > desc_sz) break;
        if (tag == AVB_DESCRIPTOR_TAG_HASH) { hash_desc = off; break; }
        off += 16 + nb;
        off = (off + 7) & ~(size_t)7;       /* 8-byte align */
    }
    if (hash_desc == (size_t)-1) {
        fprintf(stderr, "No AvbHashDescriptor in source vbmeta "
                "(is this a recovery/boot vbmeta?)\n");
        free(vb); free(img); return 1;
    }

    uint8_t *hd = descs + hash_desc;        /* AvbHashDescriptor start */
    /* field offsets relative to descriptor start (parent is first 16 bytes) */
    char alg[33] = {0};
    memcpy(alg, hd + 24, 32);
    alg[32] = 0;
    /* trim at NUL already; ensure lower-case known value */
    uint32_t pname_len = be32(hd + 56);
    uint32_t salt_len  = be32(hd + 60);
    uint32_t dig_len   = be32(hd + 64);
    uint8_t *salt   = hd + 132 + pname_len;
    uint8_t *digest = hd + 132 + pname_len + salt_len;
    if ((size_t)(132 + pname_len + salt_len + dig_len) > (size_t)(16 + be64(hd + 8))) {
        fprintf(stderr, "Hash descriptor fields overflow its length\n");
        free(vb); free(img); return 1;
    }

    /* --- determine new image size (footer original size, else full file) --- */
    uint64_t new_image_size;
    if (read_footer_orig(img, img_size, &new_image_size)) {
        printf("New image has its own AVB footer, original size = %llu\n",
               (unsigned long long)new_image_size);
    } else {
        new_image_size = img_size;
        printf("New image has no footer, hashing full file = %llu bytes\n",
               (unsigned long long)new_image_size);
    }
    if (new_image_size > img_size) {
        fprintf(stderr, "Image size from footer (%llu) exceeds file (%zu)\n",
                (unsigned long long)new_image_size, img_size);
        free(vb); free(img); return 1;
    }

    printf("Hash descriptor: alg=%s salt_len=%u digest_len=%u partition='%.*s'\n",
           alg, salt_len, dig_len, (int)pname_len, hd + 132);

    /* --- partition layout (matches avbtool / what the bootloader expects) ---
     *   [ image | zero-pad to block ][ vbmeta ][ zeros ][ footer @ end ]
     * The image is block-aligned, the descriptor hash covers the block-aligned
     * image, the vbmeta sits right after it, and the footer is at the very end
     * of the partition (where libavb reads the last 64 bytes). */
    const uint64_t BLOCK = 4096;
    uint64_t aligned = (new_image_size + (BLOCK - 1)) & ~(BLOCK - 1);
    if (aligned + vb_size + AVB_FOOTER_SIZE > partition_size) {
        fprintf(stderr, "Does not fit: image(%llu) + vbmeta(%zu) + footer(64) "
                "> partition(%llu)\n", (unsigned long long)aligned, vb_size,
                (unsigned long long)partition_size);
        free(vb); free(img); return 1;
    }

    uint8_t *out = calloc(1, partition_size);
    if (!out) {
        fprintf(stderr, "Out of memory (%llu bytes)\n",
                (unsigned long long)partition_size);
        free(vb); free(img); return 1;
    }
    memcpy(out, img, (size_t)new_image_size);   /* [new_image_size:aligned] = 0 */

    /* digest over the block-aligned image (image bytes + zero padding) */
    uint8_t newdig[64];
    size_t newdig_len = hash_image(alg, salt, salt_len, out, (size_t)aligned, newdig);
    if (newdig_len == 0) {
        fprintf(stderr, "Unsupported descriptor hash_algorithm '%s'\n", alg);
        free(vb); free(img); free(out); return 1;
    }
    if (newdig_len != dig_len) {
        fprintf(stderr, "Algorithm '%s' digest len %zu != descriptor digest_len %u\n",
                alg, newdig_len, dig_len);
        free(vb); free(img); free(out); return 1;
    }

    /* update the hash descriptor in the vbmeta: image_size = aligned, new digest */
    put_be64(hd + 16, aligned);
    memcpy(digest, newdig, dig_len);

    /* recompute the vbmeta authentication (integrity) hash; signature left stale */
    if (recompute_auth_hash(vb, vb_size) != 0) {
        fprintf(stderr, "Failed to recompute vbmeta authentication hash\n");
        free(vb); free(img); free(out); return 1;
    }
    printf("Recomputed vbmeta integrity hash; signature left unchanged "
           "(valid only if recovery path skips signature check)\n");

    /* place vbmeta after the aligned image, footer at the partition end */
    memcpy(out + aligned, vb, vb_size);
    uint8_t *f = out + partition_size - AVB_FOOTER_SIZE;
    memcpy(f, AVB_FOOTER_MAGIC, 4);
    put_be32(f + 4, 1); put_be32(f + 8, 0);
    put_be64(f + 12, aligned);              /* original_image_size */
    put_be64(f + 20, aligned);              /* vbmeta_offset       */
    put_be64(f + 28, vb_size);              /* vbmeta_size         */

    /* --- self-verify on the assembled output --- */
    uint8_t chk[64];
    size_t clen = hash_image(alg, salt, salt_len, out, (size_t)aligned, chk);
    uint8_t *emb = out + aligned;
    uint8_t *emb_digest = emb + (size_t)(hd - vb) + 132 + pname_len + salt_len;
    int img_ok = (clen == dig_len) && memcmp(chk, emb_digest, dig_len) == 0;

    uint8_t saved[64];
    uint32_t ealg = be32(emb + 0x1c);
    uint64_t eh_off = be64(emb + 0x20), eh_sz = be64(emb + 0x28);
    int auth_ok = 1;
    if (ealg != 0) {
        memcpy(saved, emb + AVB_VBMETA_IMAGE_HEADER_SIZE + eh_off, (size_t)eh_sz);
        recompute_auth_hash(emb, vb_size);
        auth_ok = memcmp(saved, emb + AVB_VBMETA_IMAGE_HEADER_SIZE + eh_off, (size_t)eh_sz) == 0;
    }

    if (write_file(out_path, out, partition_size) != 0) {
        fprintf(stderr, "Cannot write output: %s\n", out_path);
        free(vb); free(img); free(out); return 1;
    }

    printf("\nWrote %s (%llu bytes, partition-sized)\n",
           out_path, (unsigned long long)partition_size);
    printf("  image: 0x0..0x%llx, vbmeta @ 0x%llx, footer @ 0x%llx\n",
           (unsigned long long)aligned, (unsigned long long)aligned,
           (unsigned long long)(partition_size - AVB_FOOTER_SIZE));
    printf("  image hash self-check : %s\n", img_ok  ? "OK" : "FAILED");
    printf("  vbmeta integrity check: %s\n", auth_ok ? "OK" : "FAILED");
    printf("  vbmeta signature      : NOT re-signed (works only if recovery "
           "path skips signature)\n");

    free(vb); free(img); free(out);
    return (img_ok && auth_ok) ? 0 : 1;
}
