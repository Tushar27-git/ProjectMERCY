/**
 * @file pe_parser.h
 * @brief SentinelDriver — Kernel-safe PE header parser declarations.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "common.h"
#include "../SentinelCommon/feature_vector.h"

/**
 * @brief Quick check if a buffer starts with a valid MZ/PE signature.
 * @param Buffer     Pointer to the data buffer.
 * @param BufferSize Size of the buffer in bytes.
 * @return TRUE if the buffer appears to be a PE file.
 */
BOOLEAN IsPeFile(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize);

/**
 * @brief Parse PE headers and populate the FeatureVector with section info.
 * @param Buffer         Pointer to the PE file data.
 * @param BufferSize     Size of the buffer.
 * @param pFeatureVector Output feature vector to populate.
 * @return STATUS_SUCCESS on success, error code on malformed PE.
 */
NTSTATUS ParsePeHeaders(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ FeatureVector* pFeatureVector);
