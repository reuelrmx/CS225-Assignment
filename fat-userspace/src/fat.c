#include <stdio.h>
#include "FAT.h"
#include <string.h>

// Initialization
int init_fat(const char *device_path, BPB *bpb) {
    FILE *device = fopen(device_path, "rb");
    if (!device) {
        return -1; // Unable to open device
    }

    fread(bpb, sizeof(BPB), 1, device);
    fclose(device);
    return 0;
}

// FAT Manipulation
int read_fat_entry(HANDLE device, const BPB *bpb, uint32_t cluster, FATEntry *entry) {
    DWORD bytesRead;
    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector = bpb->reserved_sectors + (fat_offset / bpb->bytes_per_sector);
    uint32_t fat_entry_offset = fat_offset % bpb->bytes_per_sector;

    SetFilePointer(device, fat_sector * bpb->bytes_per_sector + fat_entry_offset, NULL, FILE_BEGIN);
    if (!ReadFile(device, &entry->cluster, sizeof(uint32_t), &bytesRead, NULL) || bytesRead != sizeof(uint32_t)) {
        return -1; // Read error
    }

    return 0;
}

int write_fat_entry(HANDLE device, const BPB *bpb, uint32_t cluster, const FATEntry *entry) {
    DWORD bytesWritten;
    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector = bpb->reserved_sectors + (fat_offset / bpb->bytes_per_sector);
    uint32_t fat_entry_offset = fat_offset % bpb->bytes_per_sector;

    SetFilePointer(device, fat_sector * bpb->bytes_per_sector + fat_entry_offset, NULL, FILE_BEGIN);
    if (!WriteFile(device, &entry->cluster, sizeof(uint32_t), &bytesWritten, NULL) || bytesWritten != sizeof(uint32_t)) {
        return -1; // Write error
    }

    return 0;
}

// File Operations

int create_file(HANDLE device, const BPB *bpb, const char *path, DirEntry *entry) {
    // Variables for storing directory information
    DWORD bytesRead, bytesWritten;
    DirEntry dirEntry;
    uint32_t cluster = 2; // Start cluster number (root directory typically starts at 2 for FAT32)
    uint32_t sector, offset;
    uint8_t buffer[512];

    // Find a free directory entry
    while (1) {
        // Calculate the sector number of the current cluster
        sector = cluster_to_sector(bpb, cluster);

        // Read the sector
        SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!ReadFile(device, buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
            return -1; // Read error
        }

        // Search for a free entry in the sector
        for (offset = 0; offset < bpb->bytes_per_sector; offset += sizeof(DirEntry)) {
            memcpy(&dirEntry, buffer + offset, sizeof(DirEntry));
            if (dirEntry.name[0] == 0x00 || dirEntry.name[0] == 0xE5) {
                // Found a free entry
                memcpy(&dirEntry, entry, sizeof(DirEntry));
                dirEntry.name[0] = 0x00; // Mark as used
                memcpy(buffer + offset, &dirEntry, sizeof(DirEntry));

                // Write the sector back to the device
                SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
                if (!WriteFile(device, buffer, bpb->bytes_per_sector, &bytesWritten, NULL) || bytesWritten != bpb->bytes_per_sector) {
                    return -1; // Write error
                }

                // Update the entry with the start cluster (set to 0 for now)
                entry->first_cluster_low = 0;
                entry->first_cluster_high = 0;
                return 0; // Success
            }
        }

        // Move to the next cluster
        cluster++;
        if (cluster >= bpb->total_sectors_32 / bpb->sectors_per_cluster) {
            return -1; // No free directory entries available
        }
    }

    return -1; // No free directory entries found
}


// Helper function to find the directory entry for a given path
int find_directory_entry(HANDLE device, const BPB *bpb, const char *path, DirEntry *entry, uint32_t *entry_sector, uint32_t *entry_offset) {
    // This function should traverse the directory structure and find the directory entry for the given path
    // For simplicity, we assume that the path is in the root directory
    DWORD bytesRead;
    uint8_t buffer[512];
    DirEntry dirEntry;
    uint32_t cluster = 2; // Start cluster number (root directory typically starts at 2 for FAT32)
    uint32_t sector;
    uint32_t offset;

    while (1) {
        // Calculate the sector number of the current cluster
        sector = cluster_to_sector(bpb, cluster);

        // Read the sector
        SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!ReadFile(device, buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
            return -1; // Read error
        }

        // Search for the directory entry
        for (offset = 0; offset < bpb->bytes_per_sector; offset += sizeof(DirEntry)) {
            memcpy(&dirEntry, buffer + offset, sizeof(DirEntry));
            if (strncmp(dirEntry.name, path, 11) == 0) {
                // Found the directory entry
                memcpy(entry, &dirEntry, sizeof(DirEntry));
                *entry_sector = sector;
                *entry_offset = offset;
                return 0; // Success
            }
        }

        // Move to the next cluster
        cluster++;
        if (cluster >= bpb->total_sectors_32 / bpb->sectors_per_cluster) {
            return -1; // Directory entry not found
        }
    }

    return -1; // Directory entry not found
}

// Helper function to release clusters
int release_clusters(HANDLE device, const BPB *bpb, uint32_t start_cluster) {
    FATEntry fatEntry;
    uint32_t cluster = start_cluster;
    DWORD bytesRead, bytesWritten;

    while (cluster < FAT_EOF_CLUSTER) {
        // Read the FAT entry for the current cluster
        if (read_fat_entry(device, bpb, cluster, &fatEntry) != 0) {
            return -1; // Error reading FAT entry
        }

        uint32_t next_cluster = fatEntry.cluster;

        // Mark the current cluster as free
        fatEntry.cluster = FAT_FREE_CLUSTER;
        if (write_fat_entry(device, bpb, cluster, &fatEntry) != 0) {
            return -1; // Error writing FAT entry
        }

        if (next_cluster >= FAT_EOF_CLUSTER) {
            break; // End of cluster chain
        }

        cluster = next_cluster;
    }

    return 0;
}

// Function to delete a file
int delete_file(HANDLE device, const BPB *bpb, const char *path) {
    DirEntry entry;
    uint32_t entry_sector;
    uint32_t entry_offset;

    // Find the directory entry for the given path
    if (find_directory_entry(device, bpb, path, &entry, &entry_sector, &entry_offset) != 0) {
        return -1; // File not found
    }

    // Release the clusters allocated to the file
    uint32_t start_cluster = (entry.first_cluster_high << 16) | entry.first_cluster_low;
    if (release_clusters(device, bpb, start_cluster) != 0) {
        return -1; // Error releasing clusters
    }

    // Mark the directory entry as free
    entry.name[0] = 0xE5; // Mark as deleted
    uint8_t buffer[512];
    DWORD bytesRead, bytesWritten;
    SetFilePointer(device, entry_sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
    if (!ReadFile(device, buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
        return -1; // Read error
    }

    memcpy(buffer + entry_offset, &entry, sizeof(DirEntry));
    SetFilePointer(device, entry_sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
    if (!WriteFile(device, buffer, bpb->bytes_per_sector, &bytesWritten, NULL) || bytesWritten != bpb->bytes_per_sector) {
        return -1; // Write error
    }

    return 0; // Success
}


int read_file(HANDLE device, const BPB *bpb, const DirEntry *entry, void *buffer, uint32_t size) {
    uint32_t cluster = (entry->first_cluster_high << 16) | entry->first_cluster_low;
    uint32_t bytes_per_cluster = bpb->bytes_per_sector * bpb->sectors_per_cluster;
    uint32_t bytes_read = 0;
    uint8_t sector_buffer[512];
    DWORD bytesRead;

    while (cluster < FAT_EOF_CLUSTER && bytes_read < size) {
        // Calculate the sector number of the current cluster
        uint32_t sector = cluster_to_sector(bpb, cluster);

        for (uint32_t i = 0; i < bpb->sectors_per_cluster; ++i) {
            // Read the sector into sector_buffer
            SetFilePointer(device, (sector + i) * bpb->bytes_per_sector, NULL, FILE_BEGIN);
            if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
                return -1; // Read error
            }

            // Calculate the number of bytes to copy from this sector
            uint32_t bytes_to_copy = (size - bytes_read < bpb->bytes_per_sector) ? (size - bytes_read) : bpb->bytes_per_sector;

            // Copy the bytes from sector_buffer to the output buffer
            memcpy((uint8_t*)buffer + bytes_read, sector_buffer, bytes_to_copy);
            bytes_read += bytes_to_copy;

            if (bytes_read >= size) {
                return bytes_read; // Finished reading the requested size
            }
        }

        // Read the FAT entry for the current cluster to get the next cluster
        FATEntry fatEntry;
        if (read_fat_entry(device, bpb, cluster, &fatEntry) != 0) {
            return -1; // Error reading FAT entry
        }

        cluster = fatEntry.cluster;
    }

    return bytes_read; // Return the number of bytes read
}


// Helper function to allocate a new cluster
int allocate_cluster(HANDLE device, const BPB *bpb, uint32_t *new_cluster) {
    DWORD bytesRead, bytesWritten;
    uint32_t fat_size = bpb->sectors_per_fat_32 * bpb->bytes_per_sector;
    uint8_t *fat = malloc(fat_size);
    if (!fat) {
        return -1; // Memory allocation error
    }

    // Read the FAT into memory
    SetFilePointer(device, bpb->reserved_sectors * bpb->bytes_per_sector, NULL, FILE_BEGIN);
    if (!ReadFile(device, fat, fat_size, &bytesRead, NULL) || bytesRead != fat_size) {
        free(fat);
        return -1; // Read error
    }

    // Search for a free cluster
    for (uint32_t i = 2; i < fat_size / 4; ++i) {
        uint32_t *entry = (uint32_t *)(fat + i * 4);
        if (*entry == FAT_FREE_CLUSTER) {
            *entry = FAT_EOF_CLUSTER; // Mark as end of file
            *new_cluster = i;

            // Write the FAT back to the device
            SetFilePointer(device, bpb->reserved_sectors * bpb->bytes_per_sector, NULL, FILE_BEGIN);
            if (!WriteFile(device, fat, fat_size, &bytesWritten, NULL) || bytesWritten != fat_size) {
                free(fat);
                return -1; // Write error
            }

            free(fat);
            return 0; // Success
        }
    }

    free(fat);
    return -1; // No free clusters available
}

// Helper function to write a cluster of data
int write_cluster(HANDLE device, const BPB *bpb, uint32_t cluster, const void *buffer, uint32_t bytes_to_write) {
    uint32_t sector = cluster_to_sector(bpb, cluster);
    uint32_t bytes_written = 0;
    DWORD bytesWritten;

    while (bytes_written < bytes_to_write) {
        // Calculate the number of bytes to write to this sector
        uint32_t bytes_in_sector = (bytes_to_write - bytes_written < bpb->bytes_per_sector) ? (bytes_to_write - bytes_written) : bpb->bytes_per_sector;

        // Write the bytes from the input buffer to the device
        SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!WriteFile(device, (uint8_t *)buffer + bytes_written, bytes_in_sector, &bytesWritten, NULL) || bytesWritten != bytes_in_sector) {
            return -1; // Write error
        }

        bytes_written += bytes_in_sector;
        sector++;

        // If we've filled the current cluster, allocate a new one if needed
        if (bytes_written < bytes_to_write && (bytes_written % (bpb->bytes_per_sector * bpb->sectors_per_cluster)) == 0) {
            uint32_t new_cluster;
            if (allocate_cluster(device, bpb, &new_cluster) != 0) {
                return -1; // Allocation error
            }

            // Update the FAT entry for the current cluster to point to the new cluster
            FATEntry fatEntry;
            if (read_fat_entry(device, bpb, cluster, &fatEntry) != 0) {
                return -1; // Error reading FAT entry
            }
            fatEntry.cluster = new_cluster;
            if (write_fat_entry(device, bpb, cluster, &fatEntry) != 0) {
                return -1; // Error writing FAT entry
            }

            cluster = new_cluster;
        }
    }

    return bytes_written; // Return the number of bytes written
}

int write_file(HANDLE device, const BPB *bpb, const DirEntry *entry, const void *buffer, uint32_t size) {
    // Start writing from the beginning of the file
    uint32_t cluster = (entry->first_cluster_high << 16) | entry->first_cluster_low;

    // If the file has no clusters allocated, allocate the first cluster
    if (cluster == 0) {
        if (allocate_cluster(device, bpb, &cluster) != 0) {
            return -1; // Allocation error
        }

        // Update the directory entry with the new cluster
        DirEntry updated_entry = *entry;
        updated_entry.first_cluster_low = cluster & 0xFFFF;
        updated_entry.first_cluster_high = (cluster >> 16) & 0xFFFF;
        SetFilePointer(device, entry->entry_sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!WriteFile(device, &updated_entry, sizeof(DirEntry), NULL, NULL)) {
            return -1; // Write error
        }
    }

    // Write the data to the file clusters
    int bytes_written = write_cluster(device, bpb, cluster, buffer, size);

    return bytes_written; // Return the number of bytes written or -1 on error
}


// Directory Operations
int read_directory(HANDLE device, const BPB *bpb, const char *path, DirEntry *entries, uint32_t max_entries) {
    // Placeholder for error checking and validation of path
    if (device == INVALID_HANDLE_VALUE || bpb == NULL || path == NULL || entries == NULL || max_entries == 0) {
        return -1; // Invalid parameters
    }

    // Placeholder for path parsing and directory traversal
    // For simplicity, assume direct reading from the root directory
    DWORD bytesRead;
    uint8_t sector_buffer[512]; // Buffer for reading directory sectors

    // Calculate the starting sector of the root directory
    uint32_t root_dir_sector = bpb->reserved_sectors + (bpb->num_fats * bpb->sectors_per_fat_32);

    // Read directory entries until we reach the end or fill the entries array
    uint32_t current_entry = 0;
    for (uint32_t sector = root_dir_sector; sector < root_dir_sector + bpb->root_entries / (bpb->bytes_per_sector / sizeof(DirEntry)); ++sector) {
        SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
            return -1; // Read error
        }

        // Parse the sector buffer into directory entries
        for (uint32_t offset = 0; offset < bpb->bytes_per_sector; offset += sizeof(DirEntry)) {
            DirEntry *dir_entry = (DirEntry *)(sector_buffer + offset);

            // Check if this entry is free or deleted
            if (dir_entry->name[0] == 0x00 || dir_entry->name[0] == 0xE5) {
                continue; // Skip free or deleted entry
            }

            // Copy the directory entry to the entries array
            if (current_entry < max_entries) {
                entries[current_entry++] = *dir_entry;
            } else {
                return current_entry; // Reached max_entries limit
            }
        }
    }

    return current_entry; // Return the number of directory entries read
}


int find_free_directory_entry(HANDLE device, const BPB *bpb, uint32_t *sector, uint32_t *offset) {
    DWORD bytesRead;
    uint8_t sector_buffer[512];

    // Calculate the starting sector of the root directory
    uint32_t root_dir_sector = bpb->reserved_sectors + (bpb->num_fats * bpb->sectors_per_fat_32);

    // Iterate through each sector of the root directory
    for (uint32_t sector_num = root_dir_sector; sector_num < root_dir_sector + bpb->root_entries / (bpb->bytes_per_sector / sizeof(DirEntry)); ++sector_num) {
        SetFilePointer(device, sector_num * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
            return -1; // Read error
        }

        // Iterate through each directory entry in the sector buffer
        for (uint32_t entry_offset = 0; entry_offset < bpb->bytes_per_sector; entry_offset += sizeof(DirEntry)) {
            DirEntry *dir_entry = (DirEntry *)(sector_buffer + entry_offset);

            // Check if this directory entry is free
            if (dir_entry->name[0] == 0x00 || dir_entry->name[0] == 0xE5) {
                *sector = sector_num;
                *offset = entry_offset;
                return 0; // Found a free directory entry
            }
        }
    }

    return -1; // No free directory entry found
}

int allocate_clusters_for_directory(HANDLE device, const BPB *bpb, uint32_t *first_cluster) {
    // Placeholder for cluster allocation logic
    // For simplicity, assume no cluster allocation for now
    *first_cluster = 0; // Placeholder for actual allocation logic
    return 0; // Success
}

int create_directory(HANDLE device, const BPB *bpb, const char *path) {
    // Placeholder for path parsing and validation
    // For simplicity, assume direct creation in the root directory
    if (device == INVALID_HANDLE_VALUE || bpb == NULL || path == NULL) {
        return -1; // Invalid parameters
    }

    // Find a free directory entry in the root directory
    uint32_t sector, offset;
    if (find_free_directory_entry(device, bpb, &sector, &offset) != 0) {
        return -1; // No free directory entry found
    }

    // Allocate clusters for storing directory entries (if necessary)
    uint32_t first_cluster;
    if (allocate_clusters_for_directory(device, bpb, &first_cluster) != 0) {
        return -1; // Cluster allocation error
    }

    // Create a new directory entry
    DirEntry new_entry;
    memset(&new_entry, 0, sizeof(DirEntry)); // Initialize with zeros
    strncpy(new_entry.name, path, 11); // Copy directory name (truncate if necessary)
    new_entry.attr = 0x10; // Directory attribute
    new_entry.first_cluster_low = first_cluster & 0xFFFF;
    new_entry.first_cluster_high = (first_cluster >> 16) & 0xFFFF;

    // Write the new directory entry to the device
    SetFilePointer(device, sector * bpb->bytes_per_sector + offset, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    if (!WriteFile(device, &new_entry, sizeof(DirEntry), &bytesWritten, NULL) || bytesWritten != sizeof(DirEntry)) {
        return -1; // Write error
    }

    return 0; // Directory creation successful
}


int mark_directory_entry_as_free(HANDLE device, const BPB *bpb, uint32_t sector, uint32_t offset) {
    // Read the directory entry to mark as free
    DWORD bytesRead;
    uint8_t sector_buffer[512];

    // Read the sector containing the directory entry
    SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
    if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
        return -1; // Read error
    }

    // Mark the directory entry as free (set first byte of name to 0x00)
    sector_buffer[offset] = 0x00;

    // Write the updated sector back to the device
    SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    if (!WriteFile(device, sector_buffer, bpb->bytes_per_sector, &bytesWritten, NULL) || bytesWritten != bpb->bytes_per_sector) {
        return -1; // Write error
    }

    return 0; // Directory entry marked as free successfully
}

int release_clusters_for_directory(HANDLE device, const BPB *bpb, uint32_t first_cluster) {
    // Placeholder for cluster release logic
    // For simplicity, assume no cluster release for now
    return 0; // Success
}

int delete_directory(HANDLE device, const BPB *bpb, const char *path) {
    // Placeholder for path parsing and validation
    // For simplicity, assume direct deletion in the root directory
    if (device == INVALID_HANDLE_VALUE || bpb == NULL || path == NULL) {
        return -1; // Invalid parameters
    }

    // Find the directory entry in the root directory
    DWORD bytesRead;
    uint8_t sector_buffer[512]; // Buffer for reading directory sectors

    // Calculate the starting sector of the root directory
    uint32_t root_dir_sector = bpb->reserved_sectors + (bpb->num_fats * bpb->sectors_per_fat_32);

    // Iterate through each sector of the root directory
    for (uint32_t sector_num = root_dir_sector; sector_num < root_dir_sector + bpb->root_entries / (bpb->bytes_per_sector / sizeof(DirEntry)); ++sector_num) {
        SetFilePointer(device, sector_num * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, &bytesRead, NULL) || bytesRead != bpb->bytes_per_sector) {
            return -1; // Read error
        }

        // Iterate through each directory entry in the sector buffer
        for (uint32_t entry_offset = 0; entry_offset < bpb->bytes_per_sector; entry_offset += sizeof(DirEntry)) {
            DirEntry *dir_entry = (DirEntry *)(sector_buffer + entry_offset);

            // Check if this directory entry matches the path and is a directory
            if (dir_entry->name[0] == 0x00 || dir_entry->name[0] == 0xE5) {
                continue; // Skip free or deleted entry
            }

            // Compare directory name (adjust to compare with path)
            char entry_name[12];
            strncpy(entry_name, dir_entry->name, 11);
            entry_name[11] = '\0'; // Ensure null-termination
            if (strcmp(entry_name, path) == 0 && (dir_entry->attr & 0x10) != 0) {
                // Found the directory entry to delete

                // Mark the directory entry as free in the root directory
                if (mark_directory_entry_as_free(device, bpb, sector_num, entry_offset) != 0) {
                    return -1; // Error marking directory entry as free
                }

                // Release clusters allocated for directory entries (if any)
                uint32_t first_cluster = (dir_entry->first_cluster_high << 16) | dir_entry->first_cluster_low;
                if (release_clusters_for_directory(device, bpb, first_cluster) != 0) {
                    return -1; // Error releasing clusters
                }

                return 0; // Directory deletion successful
            }
        }
    }

    return -1; // Directory not found or other error
}


// Utility Functions
uint32_t cluster_to_sector(const BPB *bpb, uint32_t cluster) {
    return bpb->reserved_sectors + (cluster - 2) * bpb->sectors_per_cluster;
}

uint32_t sector_to_cluster(const BPB *bpb, uint32_t sector) {
    return (sector - bpb->reserved_sectors) / bpb->sectors_per_cluster + 2;
}
