/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Defiant Core.
 *
 * Ghoti.io Defiant Core is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version
 * 3 as published by the Free Software Foundation.
 *
 * Ghoti.io Defiant Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file upload.h
 * @brief Files an editor attaches to an entity: staged with an expiry,
 * promoted when an entity references them, swept when nothing does.
 * @stability free
 *
 * **Where the bytes live.** The store port holds UTF-8 text of at most a few
 * kilobytes a value, so a file's bytes are not entity fields. They are kept
 * by a ::GDEFCORE_Blob_Store the host supplies (a directory, an object
 * store, memory in a test), under the tenant and the file's SHA-256 digest.
 * What the store holds is the file's metadata: a content entity of the type
 * ::GDEFCORE_UPLOAD_TYPE with its name, media type, size, digest, state, expiry
 * and the uploader. A host's blob store is not part of the store port's
 * snapshot: a restore brings the metadata back, and a file whose blob was
 * not backed up with it is read as missing (gdefcore_upload_read() says so).
 *
 * **Staged, kept.** gdefcore_upload_stage() checks the policy (size, media
 * type, name) before anything is stored, writes the blob, then one changeset
 * writes the entity as `staged` with an expiry. A file is referenced by a
 * field of type reference that names it. The reference count is **derived**:
 * gdefcore_upload_references() reads the current published revisions of the
 * entities of every content type and counts the reference fields, at any
 * depth and in every language the entity has, that name the file. A draft
 * that names a file holds it as a published revision does (the pair is counted
 * once). There is no stored counter to drift.
 *
 * gdefcore_upload_sweep() is the whole lifecycle, and is safe to run at any
 * time and as often as wanted: a staged file with a reference becomes `kept`
 * (promotion, even when its expiry has passed, so a reference saved just
 * before the sweep is never lost to it); a kept file with no reference
 * becomes `staged` again with a fresh expiry (so a revert has time); a
 * staged file past its expiry with no reference is deleted and its blob
 * removed, unless another file entity of the tenant has the same digest.
 *
 * **Personal fields.** A personal field's value is ciphertext, so a reference
 * held in one cannot be observed and its file would be swept. A file is
 * therefore never attached through a personal field:
 * gdefcore_upload_field_ok() says no, and the forms that offer files use it.
 *
 * **Reading the bytes.** gdefcore_upload_read() gives the bytes to the
 * uploader of a staged file, and, for a kept one, to a principal who may read
 * the referencing field of an entity that references it. There is no other way
 * to the bytes: no address anyone may guess. The principal's access filter is
 * the authority; this adds no grant of its own.
 */

#ifndef GHOTI_IO_GDEFCORE_UPLOAD_H
#define GHOTI_IO_GDEFCORE_UPLOAD_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The content type that holds a file's metadata. */
#define GDEFCORE_UPLOAD_TYPE "core.file"
/** @brief The state of a file nothing references yet. */
#define GDEFCORE_UPLOAD_STATE_STAGED "staged"
/** @brief The state of a file some entity references. */
#define GDEFCORE_UPLOAD_STATE_KEPT "kept"
/** @brief Hex characters of a digest. */
#define GDEFCORE_UPLOAD_DIGEST_LEN 64
/** @brief The most bytes one file may be, whatever a policy allows. */
#define GDEFCORE_UPLOAD_HARD_MAX (16u * 1024u * 1024u)
/** @brief Bytes of a file name, at most. */
#define GDEFCORE_UPLOAD_NAME_MAX 200

/**
 * @brief Where a file's bytes are kept. Begins with @ref size.
 *
 * Each call is made with the tenant's bytes and a digest of
 * ::GDEFCORE_UPLOAD_DIGEST_LEN lowercase hex characters; a store keeps a
 * different tenant's identical bytes apart. A call returns 0 on success.
 */
typedef struct GDEFCORE_Blob_Store {
  size_t size;  ///< Must be `sizeof(GDEFCORE_Blob_Store)`.
  void * ctx;   ///< Passed to each call.
  /** Keep @p len bytes under the digest. Keeping the same again is success. */
  int (*put)(void * ctx, const uint8_t * tenant, size_t tenant_len,
      const char * digest, const uint8_t * bytes, size_t len);
  /** Copy the blob into @p buf (@p cap bytes) and set @p out_len; a blob that
   * is not there, or does not fit, is non-zero. */
  int (*get)(void * ctx, const uint8_t * tenant, size_t tenant_len,
      const char * digest, uint8_t * buf, size_t cap, size_t * out_len);
  /** Forget the blob. One that is not there is success. */
  int (*remove)(void * ctx, const uint8_t * tenant, size_t tenant_len,
      const char * digest);
} GDEFCORE_Blob_Store;

/**
 * @brief What a site accepts. Begins with @ref size.
 */
typedef struct GDEFCORE_Upload_Policy {
  size_t size;                 ///< Must be `sizeof(GDEFCORE_Upload_Policy)`.
  uint64_t max_bytes;          ///< The most one file may be; 0 is the hard maximum.
  const char * const * media;  ///< The media types accepted, exactly spelled, lowercase.
  size_t media_count;          ///< How many. None accepts nothing.
  uint64_t ttl_ms;             ///< How long a staged file lives; 0 is one day.
} GDEFCORE_Upload_Policy;

/** @brief A file read by gdefcore_upload_read(). Opaque. */
typedef struct GDEFCORE_Upload_File GDEFCORE_Upload_File;

/**
 * @brief Define the file type and declare who may upload and see files.
 *
 * Safe to call again. The permissions are `create` and `read` of the type
 * ::GDEFCORE_UPLOAD_TYPE: a role holds them as it holds any content
 * permission, and `read` is what lets a person see a file's name in a list.
 * The bytes are governed by gdefcore_upload_read(), not by `read`.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_upload_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief Whether @p name is a file name: 1 to ::GDEFCORE_UPLOAD_NAME_MAX bytes
 * of UTF-8 with no control character, no `/` or `\`, not `.` or `..`.
 */
GDEFCORE_API int gdefcore_upload_name_ok(const char * name, size_t len);

/**
 * @brief Whether a media type @p media is acceptable under @p policy.
 *
 * It must equal one of the policy's types byte for byte. A type with
 * parameters, an upper-case letter or anything but `type/subtype` is not.
 */
GDEFCORE_API int gdefcore_upload_media_ok(const GDEFCORE_Upload_Policy * policy,
    const char * media, size_t len);

/**
 * @brief Stage a file: check it, keep its bytes, write its entity.
 *
 * The principal must hold `create` of ::GDEFCORE_UPLOAD_TYPE. The name, the
 * media type and the size are checked against @p policy before the bytes are
 * given to the store, and the digest is made here. A file of bytes the tenant
 * already has stages as a new entity that shares the blob.
 *
 * @param now_ms The time, in milliseconds since the epoch; the expiry is this
 *   plus the policy's lifetime.
 * @param out_id Receives the file's public id.
 * @return ::GDEFCORE_OK; ::GDEFCORE_ERR_INVALID for a refused file (the
 *   principal is not allowed, a name, type or size the policy refuses, an
 *   empty file) with nothing stored; or the store's or the changeset's error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_upload_stage(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Blob_Store * blobs,
    const GDEFCORE_Upload_Policy * policy, const char * name, size_t name_len,
    const char * media, size_t media_len, const uint8_t * bytes, size_t len,
    uint64_t now_ms, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief How many reference fields of current published entities name the
 * file. Derived from what is stored, never from a counter.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_upload_references(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    size_t * out_count);

/**
 * @brief Whether a field of a type may hold a file: the type and field exist,
 * the field is a reference and it is not personal.
 *
 * @p field is a path (`photos.file`). @p out_ok receives 1 or 0.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_upload_field_ok(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * field, size_t field_len,
    int * out_ok);

/**
 * @brief Promote, demote and delete files by what references them, once.
 *
 * Each out count may be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_upload_sweep(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Blob_Store * blobs, const GDEFCORE_Upload_Policy * policy,
    uint64_t now_ms, size_t * out_promoted, size_t * out_demoted,
    size_t * out_removed);

/**
 * @brief Read a file the principal may have. See the file's header text.
 *
 * @return ::GDEFCORE_OK with a file to free with gdefcore_upload_file_free();
 *   ::GDEFCORE_ERR_INVALID for no such file or one the principal may not have
 *   (the two are not told apart), or ::GDEFCORE_ERR_CORRUPT when the blob is
 *   missing or is not the bytes of the digest.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_upload_read(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Blob_Store * blobs, const char * id,
    size_t id_len, GDEFCORE_Upload_File ** out_file);

/** @brief The file's name. */
GDEFCORE_API const char * gdefcore_upload_file_name(const GDEFCORE_Upload_File * file);
/** @brief The file's media type. */
GDEFCORE_API const char * gdefcore_upload_file_media(const GDEFCORE_Upload_File * file);
/** @brief The file's bytes. */
GDEFCORE_API const uint8_t * gdefcore_upload_file_bytes(const GDEFCORE_Upload_File * file);
/** @brief The file's size in bytes. */
GDEFCORE_API size_t gdefcore_upload_file_size(const GDEFCORE_Upload_File * file);
/** @brief Free a file. NULL is ignored. */
GDEFCORE_API void gdefcore_upload_file_free(GDEFCORE_Upload_File * file);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_UPLOAD_H */
