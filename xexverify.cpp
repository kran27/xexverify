// xexverify.cpp : Tool for verifying XEX compressed blocks to detect HDD fragmentation
//
// When a file is pulled from an HDD without proper filesystem metadata (e.g., raw sector carving),
// fragmented files end up with wrong sectors interleaved. This tool walks the compressed block
// chain and validates each block's SHA1 hash to identify where corruption/fragmentation occurs.

// ReSharper disable CppClangTidyClangDiagnosticPadded
#include <iostream>
#include <cstdio>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>

#include "3rdparty/byte_order.hpp"
#include "3rdparty/cxxopts.hpp"
#include "3rdparty/excrypt/src/excrypt.h"
#include "formats/xex.hpp"
#include "formats/xex_structs.hpp"
#include "formats/xex_optheaders.hpp"
#include "formats/xex_headerids.hpp"
#include "formats/xex_keys.hpp"

constexpr uint32_t CLUSTER_SIZE = 0x4000;  // FATX cluster size
constexpr uint32_t MAX_BLOCK_SIZE = 0x9800;  // Maximum sane block size

struct BlockInfo {
  int64_t file_offset;          // Offset in file where block starts
  uint32_t block_size;          // Size of this block
  uint8_t expected_hash[0x14];  // Expected SHA1 hash
  uint8_t actual_hash[0x14];    // Computed SHA1 hash
  bool hash_valid;              // Whether hash matches
  uint64_t cluster_start;       // Cluster-aligned start
  uint64_t cluster_end;         // Cluster-aligned end
  int first_bad_cluster;        // -1 if all good, else index of first bad cluster within block
};

namespace {
  void print_hash(const uint8_t* hash) {
    for (int i = 0; i < 0x14; i++)
      printf("%02X", hash[i]);
  }
}

namespace
{
  // Exhaustive brute force: test combinations of good/bad in order of likelihood/speed of checking
  // Unless frag is tiny, this will take a LONG time.
  // Recommended to only be used with set bounds. (and honestly, untested without. scan might be flawed)
  bool bruteforce_block(FILE* file, int64_t block_offset, uint32_t block_size,
                        const uint8_t* expected_hash, const uint8_t* session_key, 
                        const uint8_t* initial_iv,
                        bool encrypted, int64_t file_size,
                        int block_num, int64_t frag_offset = 0,
                        int64_t known_end_offset = 0) {
    // Sanity checks
    if (block_offset >= file_size) {
      printf("ERROR: Block offset 0x%llX is beyond file size 0x%llX\n",
             static_cast<unsigned long long>(block_offset), static_cast<unsigned long long>(file_size));
      return false;
    }
    if (block_size > MAX_BLOCK_SIZE) {
      printf("ERROR: Block size 0x%X exceeds maximum 0x%X\n", block_size, MAX_BLOCK_SIZE);
      return false;
    }
  
    // Calculate absolute cluster positions
    int64_t block_start_cluster = block_offset / CLUSTER_SIZE;
    uint32_t offset_in_cluster = block_offset % CLUSTER_SIZE;
  
    // Calculate how many clusters are needed for this block
    uint32_t bytes_in_first_cluster = CLUSTER_SIZE - offset_in_cluster;
    uint32_t bytes_needed_after_first = block_size > bytes_in_first_cluster 
                                         ? block_size - bytes_in_first_cluster : 0;
    uint32_t total_block_clusters = 1 + (bytes_needed_after_first + CLUSTER_SIZE - 1) / CLUSTER_SIZE;
  
    // Determine how many clusters are known-valid (fixed)
    // By default, first cluster is fixed (assumed valid based on being part of the last block)
    // Technically, the block could start on a 0x4000 alignment and be fragmented and cause issues.
    // If frag_offset is specified, all clusters before it are fixed
    uint32_t fixed_clusters_start = 1;  // At minimum, first cluster is fixed
  
    if (frag_offset > 0 && frag_offset > block_offset) {
      int64_t frag_cluster = frag_offset / CLUSTER_SIZE;
      if (frag_cluster > block_start_cluster) {
        fixed_clusters_start = static_cast<uint32_t>(frag_cluster - block_start_cluster);
        fixed_clusters_start = std::min(fixed_clusters_start, total_block_clusters);
      }
    }
  
    // Determine how many clusters are fixed at the END
    // If known_end_offset is specified, we know where the end of the block is
    uint32_t fixed_clusters_end = 0;
    int64_t end_cluster_file_pos = 0;  // File position of the first end-fixed cluster
  
    if (known_end_offset > 0) {
      // known_end_offset is where the remaining block data starts
      // Calculate how many clusters from there to the end of the block
      uint64_t end_cluster = known_end_offset / CLUSTER_SIZE;
    
      fixed_clusters_end = 1;  // Assume last cluster is known
      end_cluster_file_pos = known_end_offset;
    
      printf("  -> Known end position at 0x%llX (cluster %llu)\n",
             static_cast<unsigned long long>(known_end_offset), static_cast<unsigned long long>(end_cluster));
    }
  
    uint32_t clusters_to_bruteforce = total_block_clusters - fixed_clusters_start - fixed_clusters_end;
    int64_t first_bruteforce_cluster = block_start_cluster + fixed_clusters_start;
  
    // Sanity check: ensure file_size calculations don't overflow
    if (first_bruteforce_cluster * CLUSTER_SIZE > file_size) {
      printf("ERROR: First brute force cluster is beyond file end\n");
      return false;
    }
  
    uint32_t total_file_clusters = static_cast<uint32_t>((file_size + CLUSTER_SIZE - 1) / CLUSTER_SIZE);
    if (first_bruteforce_cluster > total_file_clusters) {
      printf("ERROR: Not enough data in file for brute force\n");
      return false;
    }
  
    // Calculate available clusters - limit to end-fixed position if specified
    uint32_t available_clusters;
    int64_t search_end_offset;
    if (fixed_clusters_end > 0 && end_cluster_file_pos > first_bruteforce_cluster * CLUSTER_SIZE) {
      // Only search up to the end-fixed position
      int64_t end_cluster_num = end_cluster_file_pos / CLUSTER_SIZE;
      available_clusters = static_cast<uint32_t>(end_cluster_num - first_bruteforce_cluster);
      search_end_offset = end_cluster_file_pos;
      printf("Search limited to clusters before end-fixed position\n");
    } else {
      available_clusters = total_file_clusters - static_cast<uint32_t>(first_bruteforce_cluster);
      search_end_offset = file_size;
    }
  
    printf("\n=== Exhaustive Brute Force for Block %d ===\n", block_num);
    printf("Block size: 0x%X (%u bytes)\n", block_size, block_size);
    printf("Block starts at file offset: 0x%llX\n", static_cast<unsigned long long>(block_offset));
    printf("  -> Cluster %llu + 0x%X bytes in\n", 
           static_cast<unsigned long long>(block_start_cluster), offset_in_cluster);
    printf("  -> Block spans %u clusters total\n", total_block_clusters);
  
    if (frag_offset > 0) {
      printf("  -> Known fragmentation at 0x%llX (cluster %llu)\n",
             static_cast<unsigned long long>(frag_offset), static_cast<unsigned long long>(frag_offset / CLUSTER_SIZE));
    }
  
    if (known_end_offset > 0) {
      printf("  -> Known end position at 0x%llX (cluster %llu)\n",
             static_cast<unsigned long long>(known_end_offset), static_cast<unsigned long long>(known_end_offset / CLUSTER_SIZE));
    }
  
    printf("  -> FIXED at start: %u clusters (clusters %llu to %llu)\n", 
           fixed_clusters_start,
           static_cast<unsigned long long>(block_start_cluster),
           static_cast<unsigned long long>(block_start_cluster + fixed_clusters_start - 1));
  
    if (fixed_clusters_end > 0) {
      printf("  -> FIXED at end: %u clusters (at file offset 0x%llX)\n",
             fixed_clusters_end, static_cast<unsigned long long>(end_cluster_file_pos));
    }
  
    printf("  -> Clusters to brute force: %u\n", clusters_to_bruteforce);
    printf("Available clusters (from cluster %llu onwards): %u\n", 
           static_cast<unsigned long long>(first_bruteforce_cluster), available_clusters);
  
    printf("Expected block hash: ");
    for (int i = 0; i < 0x14; i++) printf("%02X", expected_hash[i]);
    printf("\n");
  
    if (available_clusters < clusters_to_bruteforce) {
      printf("ERROR: Not enough clusters available!\n");
      return false;
    }
  
    if (clusters_to_bruteforce == 0) {
      printf("All clusters are fixed - nothing to brute force.\n");
      printf("If the block is still invalid, the fragmentation offset may be wrong.\n");
      return false;
    }
  
    // Read the FIXED clusters at the START
    uint32_t fixed_bytes_start = fixed_clusters_start * CLUSTER_SIZE;
    auto fixed_data_start = std::make_unique<uint8_t[]>(fixed_bytes_start);
    _fseeki64(file, block_start_cluster * CLUSTER_SIZE, SEEK_SET);
    if (fread(fixed_data_start.get(), 1, fixed_bytes_start, file) != fixed_bytes_start) {
      printf("Failed to read fixed start clusters\n");
      return false;
    }
  
    // Read the FIXED clusters at the END (if any)
    uint32_t fixed_bytes_end = fixed_clusters_end * CLUSTER_SIZE;
    std::unique_ptr<uint8_t[]> fixed_data_end;
    if (fixed_clusters_end > 0) {
      fixed_data_end = std::make_unique<uint8_t[]>(fixed_bytes_end);
      _fseeki64(file, end_cluster_file_pos, SEEK_SET);
      if (fread(fixed_data_end.get(), 1, fixed_bytes_end, file) != fixed_bytes_end) {
        printf("Failed to read fixed end clusters\n");
        return false;
      }
    }
  
    // Read all clusters from first_bruteforce_cluster to search_end (search space)
    int64_t search_start = first_bruteforce_cluster * CLUSTER_SIZE;
    uint64_t data_to_read = search_end_offset - search_start;
    printf("Reading search data: 0x%llX bytes (%.2f MB) from 0x%llX to 0x%llX\n",
           static_cast<unsigned long long>(data_to_read), static_cast<double>(data_to_read) / (1024.0 * 1024.0),
           static_cast<unsigned long long>(search_start), static_cast<unsigned long long>(search_end_offset));

    auto search_data = std::make_unique<uint8_t[]>(data_to_read);
    _fseeki64(file, search_start, SEEK_SET);
    if (fread(search_data.get(), 1, data_to_read, file) != data_to_read) {
      printf("Failed to read search data\n");
      return false;
    }
  
    // Allocate buffers for the full block's worth of clusters
    uint32_t total_cluster_bytes = total_block_clusters * CLUSTER_SIZE;
    auto assembled = std::make_unique<uint8_t[]>(total_cluster_bytes);
    auto block_buffer = std::make_unique<uint8_t[]>(block_size);
    auto decrypt_buffer = std::make_unique<uint8_t[]>(block_size);
  
    // Copy fixed START clusters into assembled buffer
    memcpy(assembled.get(), fixed_data_start.get(), fixed_bytes_start);
  
    // Copy fixed END clusters into assembled buffer (at the end)
    if (fixed_clusters_end > 0) {
      uint32_t end_offset = (fixed_clusters_start + clusters_to_bruteforce) * CLUSTER_SIZE;
      memcpy(assembled.get() + end_offset, fixed_data_end.get(), fixed_bytes_end);
    }
  
    uint32_t total_attempts = 0;
  
    // If we have end-fixed clusters, calculate the index that would put cluster right before them
    if (fixed_clusters_end > 0) {
      int64_t expected_prev_cluster_pos = end_cluster_file_pos - CLUSTER_SIZE;
      if (expected_prev_cluster_pos >= search_start) {
        uint32_t index_before_end = static_cast<uint32_t>((expected_prev_cluster_pos - search_start) / CLUSTER_SIZE);
        printf("\nNOTE: Cluster right before end-fixed position is at 0x%llX (index %u in search space)\n",
               static_cast<unsigned long long>(expected_prev_cluster_pos), index_before_end);
      }
    }
  
    // Lambda to test a specific cluster combination
    auto test_combination = [&](const std::vector<uint32_t>& indices) -> bool {
      total_attempts++;
    
      // Assemble brute-forced clusters in the MIDDLE (after start-fixed, before end-fixed)
      for (uint32_t i = 0; i < clusters_to_bruteforce; i++) {
        uint64_t src_offset = static_cast<uint64_t>(indices[i]) * CLUSTER_SIZE;
        if (src_offset + CLUSTER_SIZE > data_to_read) return false;
        memcpy(assembled.get() + fixed_bytes_start + static_cast<size_t>(i * CLUSTER_SIZE),
               search_data.get() + src_offset, CLUSTER_SIZE);
      }
    
      // Extract block
      memcpy(block_buffer.get(), assembled.get() + offset_in_cluster, block_size);
    
      // Decrypt
      memcpy(decrypt_buffer.get(), block_buffer.get(), block_size);
      if (encrypted) {
        uint8_t aes_iv_copy[0x10];
        memcpy(aes_iv_copy, initial_iv, 0x10);
        EXCRYPT_AES_STATE aes_state;
        ExCryptAesKey(&aes_state, session_key);
        ExCryptAesCbc(&aes_state, decrypt_buffer.get(), block_size, decrypt_buffer.get(), aes_iv_copy, false);
      }
    
      // Hash
      uint8_t sha_hash[0x14];
      ExCryptSha(decrypt_buffer.get(), block_size, nullptr, 0, nullptr, 0, sha_hash, sizeof(sha_hash));
    
      return memcmp(sha_hash, expected_hash, 0x14) == 0;
    };
  
    auto print_success = [&](const std::vector<uint32_t>& indices, const char* strategy) {
      printf("\n*** FOUND VALID BLOCK! (%s) ***\n", strategy);
      printf("After %llu total attempts\n", static_cast<unsigned long long>(total_attempts));
    
      printf("\nCluster assembly:\n");
    
      // Show all fixed START clusters
      for (uint32_t i = 0; i < fixed_clusters_start; i++) {
        uint64_t abs_cluster = block_start_cluster + i;
        printf("  FIXED (start): Cluster %llu (offset 0x%llX)\n",
               static_cast<unsigned long long>(abs_cluster),
               static_cast<unsigned long long>(abs_cluster * CLUSTER_SIZE));
      }
    
      // Show found clusters
      for (uint32_t i = 0; i < clusters_to_bruteforce; i++) {
        uint64_t abs_cluster = first_bruteforce_cluster + indices[i];
        printf("  FOUND: Cluster %llu (offset 0x%llX)\n",
               static_cast<unsigned long long>(abs_cluster),
               static_cast<unsigned long long>(abs_cluster * CLUSTER_SIZE));
      }
    
      // Show fixed END clusters
      if (fixed_clusters_end > 0) {
        for (uint32_t i = 0; i < fixed_clusters_end; i++) {
          uint64_t abs_cluster = end_cluster_file_pos / CLUSTER_SIZE + i;
          printf("  FIXED (end): Cluster %llu (offset 0x%llX)\n",
                 static_cast<unsigned long long>(abs_cluster),
                 static_cast<unsigned long long>(abs_cluster * CLUSTER_SIZE));
        }
      }
    
      // Show garbage clusters (but limit output if there are too many)
      printf("\nGarbage clusters to skip:\n");
      uint32_t last_used = indices.back();
      uint32_t garbage_count = 0;
      constexpr uint32_t MAX_GARBAGE_TO_PRINT = 20;
    
      for (uint32_t c = 0; c <= last_used; c++) {
        bool is_used = false;
        for (uint32_t i = 0; i < clusters_to_bruteforce; i++) {
          if (indices[i] == c) { is_used = true; break; }
        }
        if (!is_used) {
          garbage_count++;
          if (garbage_count <= MAX_GARBAGE_TO_PRINT) {
            uint64_t abs_cluster = first_bruteforce_cluster + c;
            printf("  Cluster %llu (offset 0x%llX)\n",
                   static_cast<unsigned long long>(abs_cluster),
                   static_cast<unsigned long long>(abs_cluster * CLUSTER_SIZE));
          }
        }
      }
      if (garbage_count > MAX_GARBAGE_TO_PRINT) {
        printf("  ... and %u more garbage clusters (total: %u)\n", 
               garbage_count - MAX_GARBAGE_TO_PRINT, garbage_count);
      }
      printf("\nTotal garbage clusters: %u\n", garbage_count);
    };
  
    constexpr uint32_t PROGRESS_INTERVAL = 10000;  // Report progress every N attempts
  
    // Strategy 0: If we have end-fixed clusters, try the clusters immediately before them first
    // With the limited search range, these are the LAST clusters in our search_data
    if (fixed_clusters_end > 0 && clusters_to_bruteforce >= 1) {
      printf("\nStrategy 0: Try clusters immediately before end-fixed position...\n");
      std::vector<uint32_t> indices(clusters_to_bruteforce);
    
      // The last N clusters in our search space, where N = clusters_to_bruteforce
      for (uint32_t i = 0; i < clusters_to_bruteforce; i++) {
        indices[i] = available_clusters - clusters_to_bruteforce + i;
        uint64_t pos = search_start + static_cast<uint64_t>(indices[i]) * CLUSTER_SIZE;
        printf("  Testing index %u (file offset 0x%llX)\n", indices[i], static_cast<unsigned long long>(pos));
      }
    
      // For debug: compute and show the hash we get
      {
        // Assemble brute-forced clusters
        for (uint32_t i = 0; i < clusters_to_bruteforce; i++) {
          uint64_t src_offset = static_cast<uint64_t>(indices[i]) * CLUSTER_SIZE;
          memcpy(assembled.get() + fixed_bytes_start + static_cast<size_t>(i * CLUSTER_SIZE),
                 search_data.get() + src_offset, CLUSTER_SIZE);
        }
      
        // Extract block
        memcpy(block_buffer.get(), assembled.get() + offset_in_cluster, block_size);
      
        // Decrypt
        memcpy(decrypt_buffer.get(), block_buffer.get(), block_size);
        if (encrypted) {
          uint8_t aes_iv_copy[0x10];
          memcpy(aes_iv_copy, initial_iv, 0x10);
          EXCRYPT_AES_STATE aes_state;
          ExCryptAesKey(&aes_state, session_key);
          ExCryptAesCbc(&aes_state, decrypt_buffer.get(), block_size, decrypt_buffer.get(), aes_iv_copy, false);
        }
      
        // Hash
        uint8_t sha_hash[0x14];
        ExCryptSha(decrypt_buffer.get(), block_size, nullptr, 0, nullptr, 0, sha_hash, sizeof(sha_hash));
      
        printf("  Computed hash: ");
        for (unsigned char i : sha_hash) printf("%02X", i);
        printf("\n  Expected hash: ");
        for (int i = 0; i < 0x14; i++) printf("%02X", expected_hash[i]);
        printf("\n");
      }
    
      if (test_combination(indices)) {
        print_success(indices, "immediately before end-fixed");
        return true;
      }
      printf("  No match at expected position.\n");
    }
  
    // Strategy 1: Only need 1 cluster - try each available cluster
    if (clusters_to_bruteforce == 1) {
      printf("\nStrategy 1: Need 1 cluster, trying each of %u possibilities...\n", available_clusters);
    
      std::vector<uint32_t> indices(1);
      for (uint32_t c = 0; c < available_clusters; c++) {
        if (c > 0 && c % PROGRESS_INTERVAL == 0) {
          printf("  Progress: %u / %u (%.1f%%)\n", c, available_clusters, 100.0 * c / available_clusters);
        }
        indices[0] = c;
        if (test_combination(indices)) {
          print_success(indices, "single cluster");
          return true;
        }
      }
      printf("  No match found in %u clusters.\n", available_clusters);
      printf("\n*** EXHAUSTED ALL SINGLE-CLUSTER POSSIBILITIES ***\n");
      printf("The missing cluster is NOT in the search range (0x%llX to 0x%llX)\n",
             static_cast<unsigned long long>(search_start), static_cast<unsigned long long>(search_end_offset));
      printf("Possible causes:\n");
      printf("  1. End position (-E) is wrong - cluster might be beyond it\n");
      printf("  2. Fragmentation position (-f) is wrong - more clusters before it are garbage\n");
      printf("  3. Expected hash is wrong - block before this one might also be fragmented\n");
      return false;
    }
  
    // Strategy 2: Need N clusters - try N contiguous clusters starting at each position
    // (The original sequential position 0,1,2... already failed, so start from position 1)
    if (clusters_to_bruteforce >= 1) {
      uint32_t num_positions = available_clusters - clusters_to_bruteforce;
      printf("\nStrategy 2: All %u clusters contiguous, different start position (%u possibilities)...\n", 
             clusters_to_bruteforce, num_positions);
    
      std::vector<uint32_t> indices(clusters_to_bruteforce);
      uint32_t checked = 0;
      for (uint32_t start = 1; start + clusters_to_bruteforce <= available_clusters; start++) {
        checked++;
        if (checked % PROGRESS_INTERVAL == 0) {
          printf("  Progress: %u / %u (%.1f%%)\n", checked, num_positions, 100.0 * checked / num_positions);
        }
        for (uint32_t i = 0; i < clusters_to_bruteforce; i++) {
          indices[i] = start + i;
        }
        if (test_combination(indices)) {
          print_success(indices, "contiguous block shifted");
          return true;
        }
      }
      printf("  No match.\n");
    }
  
    // Strategy 3: First (N-1) clusters sequential from 0, only final cluster varies
    // (Only makes sense if N > 1)
    if (clusters_to_bruteforce > 1) {
      uint32_t num_possibilities = available_clusters - clusters_to_bruteforce + 1;
      printf("\nStrategy 3: First %u clusters sequential, final cluster varies (%u possibilities)...\n",
             clusters_to_bruteforce - 1, num_possibilities);
    
      std::vector<uint32_t> indices(clusters_to_bruteforce);
      // First N-1 clusters are 0, 1, 2, ...
      for (uint32_t i = 0; i + 1 < clusters_to_bruteforce; i++) {
        indices[i] = i;
      }
    
      // Try each cluster as the final one (from position clusters_to_bruteforce-1 onwards)
      uint32_t checked = 0;
      for (uint32_t last = clusters_to_bruteforce - 1; last < available_clusters; last++) {
        checked++;
        if (checked % PROGRESS_INTERVAL == 0) {
          printf("  Progress: %u / %u (%.1f%%)\n", checked, num_possibilities, 100.0 * checked / num_possibilities);
        }
        indices[clusters_to_bruteforce - 1] = last;
        if (test_combination(indices)) {
          print_success(indices, "final cluster skip");
          return true;
        }
      }
      printf("  No match.\n");
    }
  
    // Strategy 4: Last 2 clusters are a contiguous pair from elsewhere
    // (Only if we need more than 2 clusters, otherwise this is covered by strategy 2)
    if (clusters_to_bruteforce > 2) {
      uint32_t num_possibilities = available_clusters - clusters_to_bruteforce;
      printf("\nStrategy 4: Last 2 clusters form contiguous pair elsewhere (%u possibilities)...\n", num_possibilities);
    
      std::vector<uint32_t> indices(clusters_to_bruteforce);
      // First N-2 clusters are sequential
      for (uint32_t i = 0; i + 2 < clusters_to_bruteforce; i++) {
        indices[i] = i;
      }
    
      // Try each contiguous pair for last 2 positions
      uint32_t checked = 0;
      for (uint32_t pair_start = clusters_to_bruteforce - 1; pair_start + 1 < available_clusters; pair_start++) {
        checked++;
        if (checked % PROGRESS_INTERVAL == 0) {
          printf("  Progress: %u / %u (%.1f%%)\n", checked, num_possibilities, 100.0 * checked / num_possibilities);
        }
        indices[clusters_to_bruteforce - 2] = pair_start;
        indices[clusters_to_bruteforce - 1] = pair_start + 1;
        if (test_combination(indices)) {
          print_success(indices, "last 2 contiguous elsewhere");
          return true;
        }
      }
      printf("  No match.\n");
    }
  
    // Strategy 5: Last 3 clusters are a contiguous triplet from elsewhere
    // (Only if we need more than 3 clusters, otherwise redundant with strategy 2)
    if (clusters_to_bruteforce > 3) {
      uint32_t num_possibilities = available_clusters - clusters_to_bruteforce;
      printf("\nStrategy 5: Last 3 clusters form contiguous triplet elsewhere (%u possibilities)...\n", num_possibilities);
    
      std::vector<uint32_t> indices(clusters_to_bruteforce);
      // First N-3 clusters are sequential
      for (uint32_t i = 0; i + 3 < clusters_to_bruteforce; i++) {
        indices[i] = i;
      }
    
      // Try each contiguous triplet for last 3 positions
      uint32_t checked = 0;
      for (uint32_t trip_start = clusters_to_bruteforce - 2; trip_start + 2 < available_clusters; trip_start++) {
        checked++;
        if (checked % PROGRESS_INTERVAL == 0) {
          printf("  Progress: %u / %u (%.1f%%)\n", checked, num_possibilities, 100.0 * checked / num_possibilities);
        }
        indices[clusters_to_bruteforce - 3] = trip_start;
        indices[clusters_to_bruteforce - 2] = trip_start + 1;
        indices[clusters_to_bruteforce - 1] = trip_start + 2;
        if (test_combination(indices)) {
          print_success(indices, "last 3 contiguous elsewhere");
          return true;
        }
      }
      printf("  No match.\n");
    }
  
    return false;
  }


  // Find next valid block: Skip fragmented block and scan for the N+1 block
  //
  // For CBC decryption, the IV for block N+1 is the last 16 bytes of block N's ciphertext.
  // Since we don't know which file bytes correspond to the end of block N (due to fragmentation),
  // we scan forward trying different IV sources.
  //
  // The approach:
  //   1. Calculate expected_next_offset = current_block_offset + current_block_size
  //   2. For various file positions around expected_next_offset, try decrypting the descriptor
  //   3. The IV source is the 16 bytes immediately BEFORE the candidate position
  //   4. If decrypted size looks valid (0 or 0x1000-0x9800), it's a candidate
  //
  void find_next_block(FILE* file, int64_t current_block_offset, uint32_t current_block_size,
                       const uint8_t* session_key, const uint8_t* known_iv,
                       bool encrypted, int64_t file_size,
                       int current_block_num, bool verbose,
                       int64_t scan_end_limit = 0) {
  
    printf("\n=== Find Next Block Mode ===\n");
    printf("Current block %d: offset 0x%llX, size 0x%X\n",
           current_block_num, static_cast<unsigned long long>(current_block_offset), current_block_size);
  
    // Calculate where the next block SHOULD start (if no fragmentation)
    int64_t expected_next_offset = current_block_offset + current_block_size;
    printf("Next block expected at: 0x%llX (if contiguous)\n", 
           static_cast<unsigned long long>(expected_next_offset));
  
    EXCRYPT_AES_STATE aes_state;
    if (encrypted)
      ExCryptAesKey(&aes_state, session_key);
  
    // Try to show the expected hash for the next block by decrypting the current block's descriptor
    // The descriptor at current_block_offset contains: Size of next block (4 bytes) + Hash of next block (20 bytes)
    // This only works if the first 0x18 bytes of the current block are not fragmented
    printf("\n--- Expected hash for block %d (from block %d's descriptor) ---\n", 
           current_block_num + 1, current_block_num);
  
    uint8_t desc_encrypted[0x20];
    _fseeki64(file, current_block_offset, SEEK_SET);
    if (fread(desc_encrypted, 1, 0x20, file) == 0x20) {
      uint8_t desc_decrypted[0x20];
      memcpy(desc_decrypted, desc_encrypted, 0x20);
    
      if (encrypted) {
        uint8_t iv_copy[0x10];
        memcpy(iv_copy, known_iv, 0x10);
        ExCryptAesCbc(&aes_state, desc_decrypted, 0x20, desc_decrypted, iv_copy, false);
      }
    
      uint32_t next_size = xe::byte_swap(*reinterpret_cast<uint32_t*>(desc_decrypted));
      uint8_t expected_next_hash[0x14];
      memcpy(expected_next_hash, desc_decrypted + 4, 0x14);
    
      printf("  Next block size: 0x%X\n", next_size);
      printf("  Next block hash: ");
      print_hash(expected_next_hash);
      printf("\n");
    
      if (next_size == 0) {
        printf("  (Size=0 means this is the LAST block - no more blocks after)\n");
        printf("\n");
        return;
      } else if (next_size < 0x1000 || next_size > MAX_BLOCK_SIZE) {
        printf("  WARNING: Size looks invalid - first cluster of this block may be garbage!\n");
      }
    
      printf("\n");
    
      // Strategy: We know the expected hash for the next block.
      // We need to find a position P where decrypting with IV from (P - 0x10) produces this hash.
      //
      // Key insight: The IV for any position P is ALWAYS the 16 bytes immediately before P.
      // This is because CBC decryption chains through contiguous ciphertext.
      //
      // The next block's data follows immediately after the current block's data in the
      // ciphertext stream. If garbage was inserted, the next block shifts forward,
      // but the IV relationship (P - 0x10) still holds.
    
      printf("Searching for block %d (hash ", current_block_num + 1);
      print_hash(expected_next_hash);
      printf(")...\n\n");
    
      // Scan range: from expected position to some distance beyond
      // We scan at CLUSTER boundaries because fragmentation occurs at cluster boundaries
      // But the actual block start might be at a non-aligned offset within a cluster
      // Scan from expected position to end (or user-specified limit)
      int64_t scan_start = expected_next_offset;
      int64_t scan_end = file_size - next_size;  // Need room for the full block
    
      // If user specified an end limit, use it (but ensure we have room for the block)
      if (scan_end_limit > 0 && scan_end_limit < scan_end) {
        scan_end = scan_end_limit;
        printf("Using user-specified scan end limit: 0x%llX\n", static_cast<unsigned long long>(scan_end));
      }
    
      struct Candidate {
        uint64_t file_offset;
        uint32_t decrypted_size;
        uint8_t hash[0x14];
        bool hash_matches;
      };
    
      std::vector<Candidate> matching_candidates;
    
      // Calculate the offset within cluster where the next block should start
      // This offset is preserved even when garbage clusters are inserted
      uint32_t expected_offset_in_cluster = expected_next_offset % CLUSTER_SIZE;
    
      uint64_t total_clusters_to_scan = (scan_end - scan_start) / CLUSTER_SIZE;
      printf("Expected offset within cluster: 0x%X\n", expected_offset_in_cluster);
      printf("Scanning from 0x%llX to 0x%llX (%llu clusters)...\n\n", 
             static_cast<unsigned long long>(scan_start), static_cast<unsigned long long>(scan_end),
             static_cast<unsigned long long>(total_clusters_to_scan));
    
      uint64_t clusters_scanned = 0;
      uint64_t last_progress = 0;
    
      // Scan at cluster boundaries + expected_offset_in_cluster
      for (int64_t cluster = expected_next_offset / CLUSTER_SIZE;
           cluster * CLUSTER_SIZE < scan_end;
           cluster++) {
      
        clusters_scanned++;
      
        // Progress reporting every 1000 clusters or 1% (whichever is less frequent)
        uint64_t progress_pct = clusters_scanned * 100 / total_clusters_to_scan;
        if (progress_pct > last_progress && total_clusters_to_scan > 1000) {
          printf("\r  Progress: %llu%% (%llu / %llu clusters, current: 0x%llX)   ", 
                 static_cast<unsigned long long>(progress_pct),
                 static_cast<unsigned long long>(clusters_scanned),
                 static_cast<unsigned long long>(total_clusters_to_scan),
                 static_cast<unsigned long long>(cluster * CLUSTER_SIZE));
          if (fflush(stdout))
          {
            printf("ERROR: fflush failed\n");
            return;
          }
          last_progress = progress_pct;
        }
      
        // The candidate position is this cluster + the expected offset within cluster
        int64_t candidate_offset = cluster * CLUSTER_SIZE + expected_offset_in_cluster;
      
        if (candidate_offset < 0x10 || candidate_offset + next_size > file_size) continue;
      
        // The IV is ALWAYS the 16 bytes immediately before the candidate position
        uint8_t trial_iv[0x10];
        _fseeki64(file, candidate_offset - 0x10, SEEK_SET);
        if (fread(trial_iv, 1, 0x10, file) != 0x10) continue;
      
        // Read encrypted descriptor at candidate position
        uint8_t encrypted_desc[0x20];
        _fseeki64(file, candidate_offset, SEEK_SET);
        if (fread(encrypted_desc, 1, 0x20, file) != 0x20) continue;
      
        // Decrypt descriptor to check size
        uint8_t decrypted_desc[0x20];
        memcpy(decrypted_desc, encrypted_desc, 0x20);
        uint8_t iv_copy[0x10];
        memcpy(iv_copy, trial_iv, 0x10);
        ExCryptAesCbc(&aes_state, decrypted_desc, 0x20, decrypted_desc, iv_copy, false);
      
        uint32_t size = xe::byte_swap(*reinterpret_cast<uint32_t*>(decrypted_desc));
      
        // Quick check: does the size match what we expect?
        // The descriptor contains {size of NEXT block, hash of NEXT block}
        // But we can at least check if the size looks reasonable
        bool size_matches = size == next_size;
        bool size_valid = size == 0 || (size >= 0x1000 && size <= MAX_BLOCK_SIZE);
      
        if (verbose) {
          printf("  0x%llX: desc_size=0x%X %s\n",
                 static_cast<unsigned long long>(candidate_offset), size,
                 size_matches ? "(matches expected)" : "");
        }
      
        // If size looks valid, read the FULL block and verify its hash
        if (size_valid) {
          // Read and decrypt the full block
          std::vector<uint8_t> block_data(next_size);
          _fseeki64(file, candidate_offset, SEEK_SET);
          if (fread(block_data.data(), 1, next_size, file) != next_size) continue;
        
          // Decrypt with fresh IV
          memcpy(iv_copy, trial_iv, 0x10);
          ExCryptAesCbc(&aes_state, block_data.data(), next_size, 
                        block_data.data(), iv_copy, false);
        
          // Compute SHA1 of decrypted block
          uint8_t computed_hash[0x14];
          ExCryptSha(block_data.data(), next_size, nullptr, 0, nullptr, 0,
                     computed_hash, sizeof(computed_hash));
        
          // Compare to expected hash

          if (memcmp(computed_hash, expected_next_hash, 0x14) == 0) {
            Candidate c;
            c.file_offset = candidate_offset;
            c.decrypted_size = size;  // This is size of block N+2
            memcpy(c.hash, computed_hash, 0x14);
            c.hash_matches = true;
            matching_candidates.push_back(c);
          
            printf("\n  0x%llX: HASH MATCHES! Block %d verified.\n",
                   static_cast<unsigned long long>(candidate_offset), current_block_num + 1);
          } else if (verbose) {
            printf("    Computed hash: ");
            print_hash(computed_hash);
            printf(" (no match)\n");
          }
        }
           }
    
      // Clear progress line
      if (total_clusters_to_scan > 1000) {
        printf("\r  Scan complete: %llu clusters checked.                              \n",
               static_cast<unsigned long long>(clusters_scanned));
      }
    
      // Report results
      if (!matching_candidates.empty()) {
        printf("\n*** FOUND %zu MATCHING CANDIDATE(S)! ***\n\n", matching_candidates.size());
        for (auto& c : matching_candidates) {
          uint64_t cluster = c.file_offset / CLUSTER_SIZE;
          uint32_t offset_in_cluster = c.file_offset % CLUSTER_SIZE;
          int64_t offset_diff = static_cast<int64_t>(c.file_offset) - static_cast<int64_t>(expected_next_offset);
          int32_t garbage_clusters = static_cast<int32_t>(offset_diff / CLUSTER_SIZE);
        
          printf("Block %d VERIFIED at file offset 0x%llX (cluster %llu + 0x%X)\n",
                 current_block_num + 1,
                 static_cast<unsigned long long>(c.file_offset),
                 static_cast<unsigned long long>(cluster), offset_in_cluster);
          printf("  Block size: 0x%X\n", next_size);
          printf("  Block hash: ");
          print_hash(c.hash);
          printf(" (VERIFIED)\n");
          printf("  Next block (block %d) size: 0x%X\n", current_block_num + 2, c.decrypted_size);
          if (garbage_clusters != 0) {
            printf("  Garbage in block %d: %d clusters (0x%uX bytes)\n",
                   current_block_num, garbage_clusters, garbage_clusters * CLUSTER_SIZE);
          }
          printf("\n");
        
          // Calculate where the fragmentation is
          printf("Fragmentation analysis for block %d:\n", current_block_num);
          printf("  Block %d starts at: 0x%llX\n", current_block_num, static_cast<unsigned long long>(current_block_offset));
          printf("  Block %d size: 0x%X\n", current_block_num, current_block_size);
          printf("  Expected end: 0x%llX\n", static_cast<unsigned long long>(expected_next_offset));
          printf("  Actual next block: 0x%llX\n", static_cast<unsigned long long>(c.file_offset));
          printf("  Garbage offset: somewhere between 0x%llX and 0x%llX\n",
                 static_cast<unsigned long long>(current_block_offset),
                 static_cast<unsigned long long>(c.file_offset));
          printf("  Garbage size: 0x%llX bytes (%d clusters)\n",
                 static_cast<unsigned long long>(c.file_offset - expected_next_offset),
                 garbage_clusters);
          printf("\n");
        }
      } else {
        printf("\nNo candidates with matching hash found.\n");
        printf("This could mean:\n");
        printf("  - The garbage insertion is not cluster-aligned\n");
        printf("  - The block's descriptor itself is corrupted\n");
        printf("  - The fragmentation pattern is more complex\n");
      }
    } else {
      printf("  Could not read descriptor from current block.\n");
    }
  }
}

int main(int argc, char* argv[]) {
  cxxopts::Options options("xexverify", "XEX Compressed Block Verification Tool\n"
    "Validates compressed blocks to detect HDD fragmentation in carved XEX files.\n");
  
  options.add_options()
    ("h,help", "Display this help message")
    ("v,verbose", "Verbose output - show more details")
    ("k,key", "Encryption key index (0=retail, 1=devkit, 2=retail-xex1, 3=devkit-xex1)", cxxopts::value<int>()->default_value("-1"))
    ("N,next", "Find next block: scan forward from fragmented block to find next valid block header")
    ("E,end", "Scan end position for -N mode (hex, e.g. 0x17FC7C800) - limits search range", cxxopts::value<std::string>()->default_value(""))
    ("c,clusters", "Show cluster-aligned information")
    ("b,bruteforce", "Brute force search for valid cluster combinations")
    ("f,frag-offset", "Known fragmentation offset (hex, e.g. 0x664000) - for bruteforce, clusters before this are assumed valid", cxxopts::value<std::string>()->default_value(""))
    ("positional", "Input XEX file", cxxopts::value<std::vector<std::string>>());
  
  options.parse_positional({ "positional" });
  options.positional_help("<xex_file>");
  
  auto result = options.parse(argc, argv);
  
  if (result.count("help") || !result.count("positional")) {
    printf("%s", options.help().c_str());
    return 0;
  }
  
  auto& positional = result["positional"].as<std::vector<std::string>>();
  auto& filepath = positional[0];
  
  bool verbose = result["v"].as<bool>();
  bool show_clusters = result["c"].as<bool>();
  bool do_find_next = result["N"].as<bool>();
  bool do_bruteforce = result["b"].as<bool>();
  int key_index = result["k"].as<int>();
  auto frag_offset_str = result["f"].as<std::string>();
  auto scan_end_str = result["E"].as<std::string>();
  
  // Parse scan end limit for -N mode
  int64_t scan_end_limit = 0;
  if (!scan_end_str.empty()) {
    scan_end_limit = strtoll(scan_end_str.c_str(), nullptr, 0);
    printf("Scan end limit: 0x%llX\n", static_cast<unsigned long long>(scan_end_limit));
  }
  
  // Parse fragmentation specs: offset:count pairs
  if (result.count("F")) {
    std::vector<uint32_t> frag_counts;
    std::vector<uint64_t> frag_offsets;
    auto& frag_specs = result["F"].as<std::vector<std::string>>();
    for (auto& spec : frag_specs) {
      // Parse "0x18000:2" format
      size_t colon = spec.find(':');
      if (colon != std::string::npos) {
        uint64_t offset = strtoull(spec.c_str(), nullptr, 0);
        uint32_t count = strtoul(spec.c_str() + colon + 1, nullptr, 0);
        frag_offsets.push_back(offset);
        frag_counts.push_back(count);
        printf("Garbage spec: 0x%llX (%u clusters)\n", static_cast<unsigned long long>(offset), count);
      } else {
        // Default to 1 cluster if no count specified
        uint64_t offset = strtoull(spec.c_str(), nullptr, 0);
        frag_offsets.push_back(offset);
        frag_counts.push_back(1);
        printf("Garbage spec: 0x%llX (1 cluster)\n", static_cast<unsigned long long>(offset));
      }
    }
  }
  
  int64_t frag_offset = 0;
  if (!frag_offset_str.empty()) {
    frag_offset = strtoll(frag_offset_str.c_str(), nullptr, 0);
    printf("Using known fragmentation offset (for bruteforce): 0x%llX\n", static_cast<unsigned long long>(frag_offset));
  }
  
  printf("XEX Compressed Block Verification Tool\n");
  printf("=======================================\n");
  printf("File: %s\n", filepath.c_str());
  printf("Cluster size: 0x%X (%u bytes)\n\n", CLUSTER_SIZE, CLUSTER_SIZE);
  
  FILE* file;
  if (errno_t err = fopen_s(&file, filepath.c_str(), "rb"); err != 0 || !file) {
    char err_buf[256];
    if (strerror_s(err_buf, sizeof(err_buf), err)) {
      printf("ERROR: strerror_s failed\n");
      return 1;
    }
    printf("Error: Cannot open file %s\n", filepath.c_str());
    printf("       Reason: %s (errno=%d)\n", err_buf, err);
    return 1;
  }
  
  // Get file size (use 64-bit version on Windows)
  _fseeki64(file, 0, SEEK_END);
  int64_t file_size = _ftelli64(file);
  _fseeki64(file, 0, SEEK_SET);
  
  printf("File size: 0x%llX (%llu bytes)\n", static_cast<unsigned long long>(file_size), static_cast<unsigned long long>(file_size));
  printf("File spans %llu clusters\n\n", static_cast<unsigned long long>((file_size + CLUSTER_SIZE - 1) / CLUSTER_SIZE));
  
  // Read XEX header
  xex::XexHeader xex_header;
  if (fread(&xex_header, sizeof(xex_header), 1, file) != 1) {
    printf("Error: Cannot read XEX header\n");
    if (fclose(file)) {
      printf("ERROR: fclose failed\n");
    }
    return 1;
  }
  
  // Check magic
  const char* xex_type = nullptr;
  switch (static_cast<uint32_t>(xex_header.Magic)) {
    case 0x58455832: xex_type = "XEX2"; break;
    case 0x58455831: xex_type = "XEX1"; break;
    case 0x58455825: xex_type = "XEX%"; break;
    case 0x5845582D: xex_type = "XEX-"; break;
    case 0x5845583F: xex_type = "XEX?"; break;
    case 0x58455830: xex_type = "XEX0"; break;
    default:
      printf("Error: Invalid XEX magic: 0x%08X\n", static_cast<uint32_t>(xex_header.Magic));
      printf("       Expected: 0x58455832 ('XEX2') or similar\n");
      printf("\n*** Header may be corrupted - first cluster might be fragmented! ***\n");
      
      if (fclose(file)) {
        printf("ERROR: fclose failed\n");
      }
      return 1;
  }
  
  printf("XEX Type: %s\n", xex_type);
  printf("Header Size: 0x%X\n", static_cast<uint32_t>(xex_header.SizeOfHeaders));
  printf("Header ends at cluster: %u (offset 0x%X)\n", 
         static_cast<uint32_t>(xex_header.SizeOfHeaders) / CLUSTER_SIZE,
         static_cast<uint32_t>(xex_header.SizeOfHeaders) / CLUSTER_SIZE * CLUSTER_SIZE);
  printf("Directory entries: %u\n\n", static_cast<uint32_t>(xex_header.HeaderDirectoryEntryCount));
  
  // Read all headers
  std::vector<uint8_t> headers(xex_header.SizeOfHeaders);
  _fseeki64(file, 0, SEEK_SET);
  if (fread(headers.data(), 1, xex_header.SizeOfHeaders, file) != xex_header.SizeOfHeaders) {
    printf("Error: Cannot read full XEX headers (file truncated?)\n");
    if (fclose(file))
    {
      printf("ERROR: fclose failed\n");
    }
    return 1;
  }
  
  // Parse directory entries
  auto dir_entries = reinterpret_cast<xex::XexDirectoryEntry*>(headers.data() + sizeof(xex::XexHeader));
  
  uint32_t data_descriptor_offset = 0;
  uint32_t security_info_offset = xex_header.SecurityInfo;  // SecurityInfo offset is in XEX header itself
  
  printf("Directory Entries:\n");
  for (uint32_t i = 0; i < xex_header.HeaderDirectoryEntryCount; i++) {
    uint32_t key = dir_entries[i].Key;
    uint32_t value = dir_entries[i].Value;
    
    if (verbose)
      printf("  [%2u] Key: 0x%08X, Value: 0x%08X\n", i, key, value);
    
    if (key == XEX_FILE_DATA_DESCRIPTOR_HEADER)
      data_descriptor_offset = value;
  }
  printf("\n");
  
  if (!data_descriptor_offset) {
    printf("Error: No data descriptor found - cannot verify compression\n");
    if (fclose(file))
    {
      printf("ERROR: fclose failed\n");
    }
    return 1;
  }
  
  // Read data descriptor
  auto data_desc = 
    reinterpret_cast<xex_opt::XexFileDataDescriptor*>(headers.data() + data_descriptor_offset);
  
  printf("Data Descriptor:\n");
  printf("  Size: 0x%X\n", static_cast<uint32_t>(data_desc->Size));
  printf("  Flags: 0x%X (%s)\n", static_cast<uint16_t>(data_desc->Flags), 
         static_cast<uint16_t>(data_desc->Flags) ? "Encrypted" : "Not Encrypted");
  printf("  Format: %u ", static_cast<uint16_t>(data_desc->Format));
  
  bool encrypted = static_cast<uint16_t>(data_desc->Flags) != 0;
  xex_opt::XexDataFormat format = data_desc->DataFormat();
  
  switch (format) {
    case xex_opt::XexDataFormat::None:
      printf("(None/Uncompressed)\n");
      break;
    case xex_opt::XexDataFormat::Raw:
      printf("(Raw/Uncompressed with zero blocks)\n");
      break;
    case xex_opt::XexDataFormat::Compressed:
      printf("(LZX Compressed)\n");
      break;
    case xex_opt::XexDataFormat::DeltaCompressed:
      printf("(Delta Compressed)\n");
      break;
  }
  printf("\n");
  
  if (format != xex_opt::XexDataFormat::Compressed && format != xex_opt::XexDataFormat::DeltaCompressed) {
    printf("File is not compressed - block verification not applicable.\n");
    if (fclose(file))
    {
      printf("ERROR: fclose failed\n");
    }
    return 0;
  }
  
  // Get session key if encrypted
  uint8_t session_key[0x10] = { 0 };
  if (encrypted) {
    if (key_index < 0) {
      // No key specified, try to get automatically
      XEXFile xex;
      // Load XEX for key detection. Prefer a try-catch for clean exit rather than checking return codes,
      // since an invalid XEX may have corrupted headers and "fail" to load but still give us valid data.
      try { xex.load(file); }
      catch (...)
      {
        // exit program if no key is provided, and automatic detection fails
        printf("Error: Failed to load XEX for automatic key detection. Please provide a key index with -k <i>\n");
        if (fclose(file))
        {
          printf("ERROR: fclose failed\n");
        }
        return 1;
      }
      key_index = static_cast<int>(xex.encryption_key_index());
      printf("Auto-detected encryption key index: %d\n\n", key_index);
    }
    // Read security info to get encrypted session key
    if (security_info_offset) {
      auto sec_info = reinterpret_cast<xex2::SecurityInfo*>(headers.data() + security_info_offset);
      
      // Decrypt session key
      EXCRYPT_AES_STATE aes_state;
      ExCryptAesKey(&aes_state, key_bytes[key_index]);
      ExCryptAesEcb(&aes_state, sec_info->ImageInfo.ImageKey, session_key, false);
      
      printf("Using %s key for decryption\n\n", key_names[key_index]);
    }
  }
  
  // Read compression info
  auto comp_desc = 
    reinterpret_cast<xex_opt::XexCompressedDataDescriptor*>(headers.data() + data_descriptor_offset + 8);
  
  printf("Compression Info:\n");
  printf("  LZX Window Size: 0x%X\n", static_cast<uint32_t>(comp_desc->WindowSize));
  printf("  First Block Size: 0x%X\n", static_cast<uint32_t>(comp_desc->FirstDescriptor.Size));
  printf("  First Block Hash: ");
  print_hash(comp_desc->FirstDescriptor.DataDigest);
  printf("\n\n");
  
  // Walk the block chain
  printf("=== Block Chain Verification ===\n\n");
  
  std::vector<BlockInfo> blocks;
  std::vector<uint8_t> valid_decrypted_data;  // Accumulates all valid decrypted blocks
  int64_t current_offset = xex_header.SizeOfHeaders;
  xex_opt::XexDataDescriptor current_desc = comp_desc->FirstDescriptor;
  int block_num = 0;
  int valid_blocks = 0;
  int invalid_blocks = 0;
  uint64_t last_valid_offset = current_offset;
  int first_invalid_block = -1;
  
  // AES state and IV persist across all blocks (CBC chains continuously!)
  uint8_t aes_iv[0x10] = { 0 };
  uint8_t saved_iv_before_invalid[0x10] = { 0 };  // IV state before first invalid block
  EXCRYPT_AES_STATE aes_state;
  if (encrypted)
    ExCryptAesKey(&aes_state, session_key);
  
  while (current_desc.Size) {
    // Sanity check block size to prevent heap corruption on bad data
    if (current_desc.Size > MAX_BLOCK_SIZE) {
      printf("Block %3d: INVALID SIZE 0x%X (max 0x%X) - likely corrupted header\n", 
             block_num, static_cast<uint32_t>(current_desc.Size), MAX_BLOCK_SIZE);
      printf("           Stopping verification to prevent crash.\n");
      invalid_blocks++;
      if (first_invalid_block < 0) first_invalid_block = block_num;
      break;
    }
    
    BlockInfo info;
    info.file_offset = current_offset;
    info.block_size = current_desc.Size;
    memcpy(info.expected_hash, current_desc.DataDigest, 0x14);
    info.cluster_start = current_offset / CLUSTER_SIZE * CLUSTER_SIZE;
    info.cluster_end = (current_offset + current_desc.Size + CLUSTER_SIZE - 1) / CLUSTER_SIZE * CLUSTER_SIZE;
    
    // Check if we're past end of file
    if (current_offset + current_desc.Size > file_size) {
      printf("Block %3d: TRUNCATED - extends past EOF\n", block_num);
      printf("           Offset: 0x%08llX, Size: 0x%X, EOF: 0x%llX\n",
             static_cast<unsigned long long>(current_offset), static_cast<uint32_t>(current_desc.Size), 
             static_cast<unsigned long long>(file_size));
      invalid_blocks++;
      break;
    }
    
    // Read block data
    auto block_data = std::make_unique<uint8_t[]>(current_desc.Size);
    _fseeki64(file, current_offset, SEEK_SET);
    size_t bytes_read = fread(block_data.get(), 1, current_desc.Size, file);
    
    if (bytes_read != current_desc.Size) {
      printf("Block %3d: READ ERROR - only got %zu of %u bytes\n", 
             block_num, bytes_read, static_cast<uint32_t>(current_desc.Size));
      invalid_blocks++;
      if (first_invalid_block < 0) first_invalid_block = block_num;
      break;
    }
    
    // Save IV state before decrypting this block (needed for brute force if this block is invalid)
    uint8_t iv_before_this_block[0x10];
    memcpy(iv_before_this_block, aes_iv, 0x10);
    
    // Decrypt if needed (uses persistent aes_state and aes_iv that chain across blocks)
    if (encrypted) {
      ExCryptAesCbc(&aes_state, block_data.get(), current_desc.Size, block_data.get(), aes_iv, false);
    }
    
    // Compute hash
    ExCryptSha(block_data.get(), current_desc.Size, nullptr, 0, nullptr, 0, 
               info.actual_hash, sizeof(info.actual_hash));
    
    info.hash_valid = memcmp(info.actual_hash, info.expected_hash, 0x14) == 0;
    
    // Print result
    if (info.hash_valid) {
      valid_blocks++;
      last_valid_offset = current_offset + current_desc.Size;
      
      // Accumulate valid decrypted block data (full block including descriptor)
      valid_decrypted_data.insert(valid_decrypted_data.end(), 
                                   block_data.get(), 
                                   block_data.get() + current_desc.Size);
      
      if (verbose) {
        printf("Block %3d: VALID   @ 0x%08llX, Size: 0x%06X", 
               block_num, static_cast<unsigned long long>(current_offset), static_cast<uint32_t>(current_desc.Size));
        if (show_clusters) {
          printf(" (clusters %llu-%llu)", 
                 static_cast<unsigned long long>(current_offset / CLUSTER_SIZE),
                 static_cast<unsigned long long>((current_offset + current_desc.Size - 1) / CLUSTER_SIZE));
        }
        printf("\n");
        printf("          Hash: ");
        print_hash(info.expected_hash);
        printf("\n");
      }
    } else {
      invalid_blocks++;
      
      // Save IV state before this (first) invalid block for brute force
      if (first_invalid_block < 0) {
        first_invalid_block = block_num;
        memcpy(saved_iv_before_invalid, iv_before_this_block, 0x10);
      }
      
      printf("Block %3d: INVALID @ 0x%08llX, Size: 0x%06X", 
             block_num, static_cast<unsigned long long>(current_offset), static_cast<uint32_t>(current_desc.Size));
      if (show_clusters) {
        printf(" (clusters %llu-%llu)", 
               static_cast<unsigned long long>(current_offset / CLUSTER_SIZE),
               static_cast<unsigned long long>((current_offset + current_desc.Size - 1) / CLUSTER_SIZE));
      }
      printf("\n");
      
      printf("           Expected: ");
      print_hash(info.expected_hash);
      printf("\n");
      printf("           Actual:   ");
      print_hash(info.actual_hash);
      printf("\n");
      
      // Show cluster boundaries within this block
      if (show_clusters) {
        printf("           Cluster breakdown:\n");
        uint64_t cluster = current_offset / CLUSTER_SIZE;
        uint64_t end_cluster = (current_offset + current_desc.Size - 1) / CLUSTER_SIZE;
        for (uint64_t c = cluster; c <= end_cluster; c++) {
          uint64_t c_start = c * CLUSTER_SIZE;
          uint64_t c_end = (c + 1) * CLUSTER_SIZE;
          uint64_t block_start = current_offset;
          uint64_t block_end = current_offset + current_desc.Size;
          uint64_t overlap_start = c_start > block_start ? c_start : block_start;
          uint64_t overlap_end = c_end < block_end ? c_end : block_end;
          printf("             Cluster %4llu: file 0x%08llX-0x%08llX (block bytes 0x%04llX-0x%04llX)\n",
                 static_cast<unsigned long long>(c),
                 static_cast<unsigned long long>(c_start),
                 static_cast<unsigned long long>(c_end),
                 static_cast<unsigned long long>(overlap_start - block_start),
                 static_cast<unsigned long long>(overlap_end - block_start));
        }
      }
    }
    
    blocks.push_back(info);
    
    // Get next block descriptor from the start of this block's data
    auto next_desc = reinterpret_cast<xex_opt::XexDataDescriptor*>(block_data.get());
    current_desc.Size = next_desc->Size;
    memcpy(current_desc.DataDigest, next_desc->DataDigest, 0x14);
    
    current_offset += info.block_size;
    block_num++;
    
    // Safety limit
    if (block_num > 10000) {
      printf("\nWarning: Exceeded 10000 blocks, stopping.\n");
      break;
    }
  }
  
  // Summary
  printf("\n=== Summary ===\n");
  printf("Total blocks: %d\n", block_num);
  printf("Valid blocks: %d\n", valid_blocks);
  printf("Invalid blocks: %d\n", invalid_blocks);
  
  if (invalid_blocks > 0) {
    printf("\n*** FRAGMENTATION/CORRUPTION DETECTED ***\n");
    
    // Find first bad block
    for (size_t i = 0; i < blocks.size(); i++) {
      if (!blocks[i].hash_valid) {
        printf("\nFirst corruption at:\n");
        printf("  Block: %zu\n", i);
        printf("  File offset: 0x%08llX\n", static_cast<unsigned long long>(blocks[i].file_offset));
        printf("  Cluster: %llu (offset 0x%08llX)\n", 
               static_cast<unsigned long long>(blocks[i].file_offset / CLUSTER_SIZE),
               static_cast<unsigned long long>(blocks[i].file_offset / CLUSTER_SIZE * CLUSTER_SIZE));
        printf("\nLast known good data ends at:\n");
        printf("  File offset: 0x%08llX\n", static_cast<unsigned long long>(last_valid_offset));
        printf("  Cluster: %llu\n", static_cast<unsigned long long>(last_valid_offset / CLUSTER_SIZE));
        
        // Calculate how much might be missing/corrupted
        if (blocks[i].file_offset < file_size) {
          uint64_t remaining = file_size - blocks[i].file_offset;
          printf("\nRemaining file data from corruption point: 0x%llX (%llu bytes, %llu clusters)\n",
                 static_cast<unsigned long long>(remaining), static_cast<unsigned long long>(remaining),
                 static_cast<unsigned long long>((remaining + CLUSTER_SIZE - 1) / CLUSTER_SIZE));
        } else {
          printf("\nCorruption point is beyond file end!\n");
        }
        break;
      }
    }
    
    // Find next block mode - scan forward to find where next block might start
    if (do_find_next && first_invalid_block >= 0 && first_invalid_block < static_cast<int>(blocks.size())) {
      find_next_block(file, blocks[first_invalid_block].file_offset,
                      blocks[first_invalid_block].block_size, session_key,
                      saved_iv_before_invalid,
                      encrypted, file_size, first_invalid_block, verbose,
                      scan_end_limit);
    }
    
    // Try brute force if requested on the first invalid block
    if (do_bruteforce && first_invalid_block >= 0 && first_invalid_block < static_cast<int>(blocks.size())) {
      bruteforce_block(file, blocks[first_invalid_block].file_offset, 
                       blocks[first_invalid_block].block_size,
                       blocks[first_invalid_block].expected_hash, session_key, 
                       saved_iv_before_invalid,
                       encrypted, file_size,
                       first_invalid_block, frag_offset, scan_end_limit);
    }
  } else if (block_num > 0) {
    printf("\n*** ALL BLOCKS VALID ***\n");
    printf("Compressed data appears intact.\n");
  }
  
  if (fclose(file)) {
    printf("ERROR: fclose failed\n");
    return 1;
  }
  return invalid_blocks > 0 ? 1 : 0;
}
