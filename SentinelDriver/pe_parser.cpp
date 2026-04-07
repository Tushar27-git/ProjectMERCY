/**
 * @file pe_parser.cpp
 * @brief SentinelDriver — Kernel-safe MZ/PE header parser with section analysis.
 *
 * Extracts section names, sizes, characteristics, and calculates per-section
 * Shannon entropy. All pointer arithmetic is bounds-checked to prevent BSODs
 * on malformed inputs.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "pe_parser.h"
#include "entropy.h"

// ---------------------------------------------------------------------------
// PE Signature Constants
// ---------------------------------------------------------------------------
#define IMAGE_DOS_SIGNATURE_VALUE   0x5A4D      // 'MZ'
#define IMAGE_NT_SIGNATURE_VALUE    0x00004550   // 'PE\0\0'

// Maximum sections we will parse (safety limit)
#define MAX_SECTIONS_TO_PARSE       16

// ---------------------------------------------------------------------------
// IsPeFile — Quick MZ+PE signature validation
// ---------------------------------------------------------------------------
BOOLEAN IsPeFile(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize)
{
    // Minimum size: DOS header + PE signature
    if (BufferSize < sizeof(IMAGE_DOS_HEADER) + sizeof(ULONG)) {
        return FALSE;
    }

    __try {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Buffer;

        // Check MZ signature
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE_VALUE) {
            return FALSE;
        }

        // Validate e_lfanew is within bounds
        if (dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
            (ULONG)dosHeader->e_lfanew > BufferSize - sizeof(ULONG)) {
            return FALSE;
        }

        // Check PE signature
        PULONG peSignature = (PULONG)(Buffer + dosHeader->e_lfanew);
        if (*peSignature != IMAGE_NT_SIGNATURE_VALUE) {
            return FALSE;
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// ---------------------------------------------------------------------------
// ParsePeHeaders — Extract sections, entropy, and RWX flags
// ---------------------------------------------------------------------------
NTSTATUS ParsePeHeaders(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ FeatureVector* pFeatureVector)
{
    if (Buffer == NULL || pFeatureVector == NULL || BufferSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Buffer;

        // Validate DOS header
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE_VALUE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Bounds-check e_lfanew — guard against unsigned underflow
        ULONG ntHeaderOffset = (ULONG)dosHeader->e_lfanew;
        if (sizeof(IMAGE_NT_HEADERS) > BufferSize ||
            ntHeaderOffset > BufferSize - (ULONG)sizeof(IMAGE_NT_HEADERS)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(Buffer + ntHeaderOffset);

        // Validate PE signature
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE_VALUE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Extract section count
        USHORT numberOfSections = ntHeaders->FileHeader.NumberOfSections;
        if (numberOfSections > MAX_SECTIONS_TO_PARSE) {
            numberOfSections = MAX_SECTIONS_TO_PARSE;
        }
        pFeatureVector->section_count = (UINT32)numberOfSections;

        // Locate section headers
        ULONG sectionTableOffset = ntHeaderOffset + sizeof(ULONG) +
            sizeof(IMAGE_FILE_HEADER) +
            ntHeaders->FileHeader.SizeOfOptionalHeader;

        if (sectionTableOffset >= BufferSize ||
            (numberOfSections * sizeof(IMAGE_SECTION_HEADER)) > (BufferSize - sectionTableOffset)) {
            // Section table extends beyond buffer — parse what we can
            numberOfSections = (USHORT)((BufferSize - sectionTableOffset) / sizeof(IMAGE_SECTION_HEADER));
            pFeatureVector->section_count = (UINT32)numberOfSections;
        }

        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(Buffer + sectionTableOffset);

        FLOAT maxEntropy = 0.0f;
        BOOLEAN hasRwxSection = FALSE;

        for (USHORT i = 0; i < numberOfSections; i++) {
            // Copy section name (8 bytes, null-padded)
            RtlCopyMemory(pFeatureVector->sections[i].name,
                sectionHeader[i].Name,
                8);

            // Section sizes
            pFeatureVector->sections[i].virtual_size = sectionHeader[i].Misc.VirtualSize;
            pFeatureVector->sections[i].raw_size = sectionHeader[i].SizeOfRawData;
            pFeatureVector->sections[i].characteristics = sectionHeader[i].Characteristics;

            // Check for RWX (Read + Write + Execute)
            const ULONG rwxMask = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
            if ((sectionHeader[i].Characteristics & rwxMask) == rwxMask) {
                hasRwxSection = TRUE;
            }

            // Calculate entropy for this section if data is within buffer bounds
            ULONG sectionOffset = sectionHeader[i].PointerToRawData;
            ULONG sectionSize = sectionHeader[i].SizeOfRawData;

            if (sectionOffset < BufferSize && sectionSize > 0) {
                // Clamp to available buffer
                if (sectionOffset + sectionSize > BufferSize) {
                    sectionSize = BufferSize - sectionOffset;
                }

                FLOAT sectionEntropy = CalculateShannonEntropy(
                    Buffer + sectionOffset,
                    sectionSize);

                pFeatureVector->sections[i].entropy = sectionEntropy;

                if (sectionEntropy > maxEntropy) {
                    maxEntropy = sectionEntropy;
                }
            } else {
                pFeatureVector->sections[i].entropy = 0.0f;
            }
        }

        pFeatureVector->max_entropy = maxEntropy;
        pFeatureVector->has_rwx_section = hasRwxSection ? 1 : 0;
        pFeatureVector->is_pe = 1;

        SentinelDbgPrint("ParsePE: %u sections, max_entropy=%.2f, rwx=%s",
            pFeatureVector->section_count,
            (double)maxEntropy,
            hasRwxSection ? "YES" : "NO");

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("ParsePE: Exception caught (0x%08X)", GetExceptionCode());
        return STATUS_UNHANDLED_EXCEPTION;
    }
}
