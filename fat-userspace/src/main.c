#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "fat.h"
#include "fat_fs.h"
#include "fat_util.h"

//global variables if needed
#define BUFFER_SIZE 4096


// Initialization
int init_fat(const char *device_path, BPB *bpb) {
    // Open the device file
    HANDLE device = CreateFile(device_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: Could not open device %s\n", device_path);
        return FAT_ERROR;
    }

    // Read the BPB
    DWORD bytesRead;
    if (!ReadFile(device, bpb, sizeof(BPB), &bytesRead, NULL) || bytesRead != sizeof(BPB)) {
        fprintf(stderr, "Error: Could not read BPB from device %s\n", device_path);
        CloseHandle(device);
        return FAT_ERROR;
    }

    // Check if the filesystem is FAT12, FAT16, or FAT32
    if (bpb->total_sectors_16 == 0 && bpb->total_sectors_32 == 0) {
        fprintf(stderr, "Error: Invalid BPB, total sectors is zero\n");
        CloseHandle(device);
        return FAT_ERROR;
    }

    // Determine FAT type
    if (bpb->sectors_per_fat_16 != 0) {
        if (bpb->total_sectors_16 != 0 || bpb->total_sectors_32 < 65536) {
            printf("FAT16 filesystem detected.\n");
        } else {
            printf("FAT12 filesystem detected.\n");
        }
    } else if (bpb->sectors_per_fat_32 != 0) {
        printf("FAT32 filesystem detected.\n");
    } else {
        fprintf(stderr, "Error: Unsupported FAT type\n");
        CloseHandle(device);
        return FAT_ERROR;
    }

    // Close the device handle
    CloseHandle(device);

    return FAT_SUCCESS;
}

// FAT Manipulation
int read_fat_entry(HANDLE device, const BPB *bpb, uint32_t cluster, FATEntry *entry) {
    DWORD bytesRead;
    uint32_t fatOffset;
    uint32_t fatEntry;
    uint32_t fatSector;
    uint32_t fatEntryOffset;
    uint8_t sectorBuffer[SECTOR_SIZE];

    // Determine FAT type
    int fatType;
    if (bpb->sectors_per_fat_32 != 0) {
        fatType = FAT32;
    } else if (bpb->total_sectors_16 < 65536) {
        fatType = FAT16;
    } else {
        fatType = FAT12;
    }

    // Calculate the FAT offset based on the cluster number and FAT type
    switch (fatType) {
        case FAT12:
            fatOffset = cluster + (cluster / 2);
            break;
        case FAT16:
            fatOffset = cluster * 2;
            break;
        case FAT32:
            fatOffset = cluster * 4;
            break;
        default:
            fprintf(stderr, "Error: Unsupported FAT type\n");
            return FAT_ERROR;
    }

    // Calculate the sector number and offset within the sector
    fatSector = bpb->reserved_sectors + (fatOffset / SECTOR_SIZE);
    fatEntryOffset = fatOffset % SECTOR_SIZE;

    // Read the sector containing the FAT entry
    if (SetFilePointer(device, fatSector * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Error: Could not set file pointer to FAT sector\n");
        return FAT_ERROR;
    }
    if (!ReadFile(device, sectorBuffer, SECTOR_SIZE, &bytesRead, NULL) || bytesRead != SECTOR_SIZE) {
        fprintf(stderr, "Error: Could not read FAT sector\n");
        return FAT_ERROR;
    }

    // Read the FAT entry based on FAT type
    switch (fatType) {
        case FAT12:
            if (fatEntryOffset == SECTOR_SIZE - 1) {
                // Read across sector boundary
                fatEntry = sectorBuffer[fatEntryOffset];
                if (SetFilePointer(device, (fatSector + 1) * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                    fprintf(stderr, "Error: Could not set file pointer to next FAT sector\n");
                    return FAT_ERROR;
                }
                if (!ReadFile(device, sectorBuffer, SECTOR_SIZE, &bytesRead, NULL) || bytesRead != SECTOR_SIZE) {
                    fprintf(stderr, "Error: Could not read next FAT sector\n");
                    return FAT_ERROR;
                }
                fatEntry |= (sectorBuffer[0] << 8);
            } else {
                fatEntry = *(uint16_t *)(sectorBuffer + fatEntryOffset);
            }
            // Handle 12-bit FAT entry
            if (cluster & 1) {
                fatEntry = fatEntry >> 4;
            } else {
                fatEntry = fatEntry & 0x0FFF;
            }
            break;
        case FAT16:
            fatEntry = *(uint16_t *)(sectorBuffer + fatEntryOffset);
            break;
        case FAT32:
            fatEntry = *(uint32_t *)(sectorBuffer + fatEntryOffset) & 0x0FFFFFFF;
            break;
    }

    entry->cluster = fatEntry;
    return FAT_SUCCESS;
}

int write_fat_entry(HANDLE device, const BPB *bpb, uint32_t cluster, const FATEntry *entry) {
    DWORD bytesWritten;
    uint32_t fatOffset;
    uint32_t fatEntry;
    uint32_t fatSector;
    uint32_t fatEntryOffset;
    uint8_t sectorBuffer[SECTOR_SIZE];

    // Determine FAT type
    int fatType;
    if (bpb->sectors_per_fat_32 != 0) {
        fatType = FAT32;
    } else if (bpb->total_sectors_16 < 65536) {
        fatType = FAT16;
    } else {
        fatType = FAT12;
    }

    // Calculate the FAT offset based on the cluster number and FAT type
    switch (fatType) {
        case FAT12:
            fatOffset = cluster + (cluster / 2);
            break;
        case FAT16:
            fatOffset = cluster * 2;
            break;
        case FAT32:
            fatOffset = cluster * 4;
            break;
        default:
            fprintf(stderr, "Error: Unsupported FAT type\n");
            return FAT_ERROR;
    }

    // Calculate the sector number and offset within the sector
    fatSector = bpb->reserved_sectors + (fatOffset / SECTOR_SIZE);
    fatEntryOffset = fatOffset % SECTOR_SIZE;

    // Read the sector containing the FAT entry
    if (SetFilePointer(device, fatSector * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Error: Could not set file pointer to FAT sector\n");
        return FAT_ERROR;
    }
    if (!ReadFile(device, sectorBuffer, SECTOR_SIZE, &bytesWritten, NULL) || bytesWritten != SECTOR_SIZE) {
        fprintf(stderr, "Error: Could not read FAT sector\n");
        return FAT_ERROR;
    }

    // Modify the FAT entry based on FAT type
    switch (fatType) {
        case FAT12:
            if (fatEntryOffset == SECTOR_SIZE - 1) {
                // Modify across sector boundary
                fatEntry = sectorBuffer[fatEntryOffset];
                fatEntry |= (entry->cluster & 0x0F) << 8;
                sectorBuffer[fatEntryOffset] = (uint8_t)(fatEntry & 0xFF);

                // Write the modified sector back to the device
                if (SetFilePointer(device, fatSector * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                    fprintf(stderr, "Error: Could not set file pointer to FAT sector\n");
                    return FAT_ERROR;
                }
                if (!WriteFile(device, sectorBuffer, SECTOR_SIZE, &bytesWritten, NULL) || bytesWritten != SECTOR_SIZE) {
                    fprintf(stderr, "Error: Could not write FAT sector\n");
                    return FAT_ERROR;
                }

                // Read the next sector containing the rest of the FAT entry
                fatEntry = entry->cluster >> 4;
                if (SetFilePointer(device, (fatSector + 1) * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                    fprintf(stderr, "Error: Could not set file pointer to next FAT sector\n");
                    return FAT_ERROR;
                }
                if (!ReadFile(device, sectorBuffer, SECTOR_SIZE, &bytesWritten, NULL) || bytesWritten != SECTOR_SIZE) {
                    fprintf(stderr, "Error: Could not read next FAT sector\n");
                    return FAT_ERROR;
                }

                sectorBuffer[0] = (uint8_t)(fatEntry & 0xFF);
            } else {
                fatEntry = *(uint16_t *)(sectorBuffer + fatEntryOffset);
                if (cluster & 1) {
                    fatEntry = (fatEntry & 0x000F) | ((entry->cluster & 0xFFF) << 4);
                } else {
                    fatEntry = (fatEntry & 0xF000) | (entry->cluster & 0x0FFF);
                }
                *(uint16_t *)(sectorBuffer + fatEntryOffset) = fatEntry;
            }
            break;
        case FAT16:
            *(uint16_t *)(sectorBuffer + fatEntryOffset) = (uint16_t)(entry->cluster & 0xFFFF);
            break;
        case FAT32:
            *(uint32_t *)(sectorBuffer + fatEntryOffset) = (entry->cluster & 0x0FFFFFFF);
            break;
    }

    // Write the modified sector back to the device
    if (SetFilePointer(device, fatSector * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Error: Could not set file pointer to FAT sector\n");
        return FAT_ERROR;
    }
    if (!WriteFile(device, sectorBuffer, SECTOR_SIZE, &bytesWritten, NULL) || bytesWritten != SECTOR_SIZE) {
        fprintf(stderr, "Error: Could not write FAT sector\n");
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

// File Operations
int create_file(HANDLE device, const BPB *bpb, const char *path, DirEntry *entry) {
    // Parse the path to get directory and filename
    char dirPath[256];
    char fileName[12];
    const char *lastSlash = strrchr(path, '\\');
    if (!lastSlash) {
        fprintf(stderr, "Error: Invalid path\n");
        return FAT_ERROR;
    }

    strncpy(dirPath, path, lastSlash - path);
    dirPath[lastSlash - path] = '\0';
    strncpy(fileName, lastSlash + 1, 11);
    fileName[11] = '\0';

    // Read the directory
    DirEntry entries[256];
    int numEntries = read_directory(device, bpb, dirPath, entries, 256);
    if (numEntries == FAT_ERROR) {
        fprintf(stderr, "Error: Could not read directory\n");
        return FAT_ERROR;
    }

    // Check if file already exists
    for (int i = 0; i < numEntries; i++) {
        if (strncmp(entries[i].name, fileName, 11) == 0) {
            fprintf(stderr, "Error: File already exists\n");
            return FAT_ERROR;
        }
    }

    // Allocate a new cluster for the file
    FATEntry fatEntry;
    uint32_t newCluster = 0;
    for (uint32_t cluster = 2; cluster < bpb->total_sectors_32 / bpb->sectors_per_cluster; cluster++) {
        if (read_fat_entry(device, bpb, cluster, &fatEntry) == FAT_SUCCESS && fatEntry.cluster == FAT_FREE_CLUSTER) {
            newCluster = cluster;
            break;
        }
    }
    if (newCluster == 0) {
        fprintf(stderr, "Error: No free cluster available\n");
        return FAT_ERROR;
    }

    // Update the FAT entry
    fatEntry.cluster = FAT_EOF_CLUSTER;
    if (write_fat_entry(device, bpb, newCluster, &fatEntry) != FAT_SUCCESS) {
        fprintf(stderr, "Error: Could not update FAT entry\n");
        return FAT_ERROR;
    }

    // Create the directory entry
    memset(entry, 0, sizeof(DirEntry));
    strncpy(entry->name, fileName, 11);
    entry->attr = 0x20; // Archive attribute
    entry->first_cluster_low = (uint16_t)(newCluster & 0xFFFF);
    entry->first_cluster_high = (uint16_t)((newCluster >> 16) & 0xFFFF);

    // Find a free slot in the directory
    for (int i = 0; i < numEntries; i++) {
        if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5) {
            entries[i] = *entry;
            break;
        }
    }

    // Write the updated directory back to the device
    uint32_t dirCluster = sector_to_cluster(bpb, read_directory(device, bpb, dirPath, entries, 256));
    if (SetFilePointer(device, cluster_to_sector(bpb, dirCluster) * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Error: Could not set file pointer to directory sector\n");
        return FAT_ERROR;
    }
    if (!WriteFile(device, entries, sizeof(entries), &bytesWritten, NULL) || bytesWritten != sizeof(entries)) {
        fprintf(stderr, "Error: Could not write directory sector\n");
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int delete_file(HANDLE device, const BPB *bpb, const char *path) {
    // Parse the path to get directory and filename
    char dirPath[256];
    char fileName[12];
    const char *lastSlash = strrchr(path, '\\');
    if (!lastSlash) {
        fprintf(stderr, "Error: Invalid path\n");
        return FAT_ERROR;
    }

    strncpy(dirPath, path, lastSlash - path);
    dirPath[lastSlash - path] = '\0';
    strncpy(fileName, lastSlash + 1, 11);
    fileName[11] = '\0';

    // Read the directory
    DirEntry entries[256];
    int numEntries = read_directory(device, bpb, dirPath, entries, 256);
    if (numEntries == FAT_ERROR) {
        fprintf(stderr, "Error: Could not read directory\n");
        return FAT_ERROR;
    }

    // Locate the directory entry for the file
    DirEntry *fileEntry = NULL;
    for (int i = 0; i < numEntries; i++) {
        if (strncmp(entries[i].name, fileName, 11) == 0) {
            fileEntry = &entries[i];
            break;
        }
    }
    if (!fileEntry) {
        fprintf(stderr, "Error: File not found\n");
        return FAT_ERROR;
    }

    // Mark the file's directory entry as deleted
    fileEntry->name[0] = 0xE5; // 0xE5 indicates a deleted file

    // Write the updated directory back to the device
    uint32_t dirCluster = sector_to_cluster(bpb, read_directory(device, bpb, dirPath, entries, 256));
    DWORD bytesWritten;
    if (SetFilePointer(device, cluster_to_sector(bpb, dirCluster) * SECTOR_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Error: Could not set file pointer to directory sector\n");
        return FAT_ERROR;
    }
    if (!WriteFile(device, entries, sizeof(entries), &bytesWritten, NULL) || bytesWritten != sizeof(entries)) {
        fprintf(stderr, "Error: Could not write directory sector\n");
        return FAT_ERROR;
    }

    // Free the clusters allocated to the file by updating the FAT
    uint32_t cluster = (fileEntry->first_cluster_high << 16) | fileEntry->first_cluster_low;
    FATEntry fatEntry;
    while (cluster < FAT_EOF_CLUSTER) {
        if (read_fat_entry(device, bpb, cluster, &fatEntry) != FAT_SUCCESS) {
            fprintf(stderr, "Error: Could not read FAT entry\n");
            return FAT_ERROR;
        }
        uint32_t nextCluster = fatEntry.cluster;
        fatEntry.cluster = FAT_FREE_CLUSTER;
        if (write_fat_entry(device, bpb, cluster, &fatEntry) != FAT_SUCCESS) {
            fprintf(stderr, "Error: Could not write FAT entry\n");
            return FAT_ERROR;
        }
        cluster = nextCluster;
    }

    return FAT_SUCCESS;
}

int read_file(HANDLE device, const BPB *bpb, const DirEntry *entry, void *buffer, uint32_t size) {
    if (!device || !bpb || !entry || !buffer) {
        return FAT_ERROR;
    }

    uint32_t cluster_size = bpb->sectors_per_cluster * bpb->bytes_per_sector;
    uint32_t cluster = (entry->first_cluster_high << 16) | entry->first_cluster_low;
    uint32_t bytes_to_read = size;
    uint32_t bytes_read = 0;
    uint32_t sector;
    uint8_t *buf = (uint8_t *)buffer;

    while (cluster != FAT_EOF_CLUSTER && bytes_to_read > 0) {
        sector = cluster_to_sector(bpb, cluster);

        for (uint32_t i = 0; i < bpb->sectors_per_cluster && bytes_to_read > 0; i++) {
            uint8_t sector_buffer[SECTOR_SIZE];
            DWORD bytes_returned;

            if (!ReadFile(device, sector_buffer, SECTOR_SIZE, &bytes_returned, NULL) || bytes_returned != SECTOR_SIZE) {
                return FAT_ERROR;
            }

            uint32_t bytes_to_copy = min(bytes_to_read, SECTOR_SIZE);
            memcpy(buf + bytes_read, sector_buffer, bytes_to_copy);

            bytes_read += bytes_to_copy;
            bytes_to_read -= bytes_to_copy;
            sector++;
        }

        // Read the next cluster from FAT
        FATEntry fat_entry;
        if (read_fat_entry(device, bpb, cluster, &fat_entry) != FAT_SUCCESS) {
            return FAT_ERROR;
        }

        cluster = fat_entry.cluster;
    }

    return bytes_read;
}

int write_file(HANDLE device, const BPB *bpb, const DirEntry *entry, const void *buffer, uint32_t size) {
    if (!device || !bpb || !entry || !buffer) {
        return FAT_ERROR;
    }

    uint32_t cluster_size = bpb->sectors_per_cluster * bpb->bytes_per_sector;
    uint32_t cluster = (entry->first_cluster_high << 16) | entry->first_cluster_low;
    uint32_t bytes_to_write = size;
    uint32_t bytes_written = 0;
    uint32_t sector;
    const uint8_t *buf = (const uint8_t *)buffer;

    while (bytes_to_write > 0) {
        if (cluster == FAT_EOF_CLUSTER) {
            // Allocate a new cluster
            cluster = allocate_new_cluster(device, bpb);
            if (cluster == FAT_ERROR) {
                return FAT_ERROR;
            }

            // Update the directory entry with the new cluster
            entry->first_cluster_high = (uint16_t)(cluster >> 16);
            entry->first_cluster_low = (uint16_t)(cluster & 0xFFFF);
        }

        sector = cluster_to_sector(bpb, cluster);

        for (uint32_t i = 0; i < bpb->sectors_per_cluster && bytes_to_write > 0; i++) {
            uint32_t bytes_to_copy = min(bytes_to_write, SECTOR_SIZE);
            uint8_t sector_buffer[SECTOR_SIZE] = {0};
            memcpy(sector_buffer, buf + bytes_written, bytes_to_copy);

            DWORD bytes_returned;
            if (!WriteFile(device, sector_buffer, SECTOR_SIZE, &bytes_returned, NULL) || bytes_returned != SECTOR_SIZE) {
                return FAT_ERROR;
            }

            bytes_written += bytes_to_copy;
            bytes_to_write -= bytes_to_copy;
            sector++;
        }

        // Read the next cluster from FAT
        FATEntry fat_entry;
        if (read_fat_entry(device, bpb, cluster, &fat_entry) != FAT_SUCCESS) {
            return FAT_ERROR;
        }

        cluster = fat_entry.cluster;
    }

    // Update the file size in the directory entry
    entry->file_size = bytes_written;

    // Write the updated directory entry
    if (update_directory_entry(device, bpb, entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return bytes_written;
}

int copy_file(HANDLE device, const BPB *bpb, const char *src_path, const char *dest_path) {
    if (!device || !bpb || !src_path || !dest_path) {
        return FAT_ERROR;
    }

    // Open source file for reading
    FILE *src_file = fopen(src_path, "rb");
    if (!src_file) {
        return FAT_ERROR;
    }

    // Create or overwrite destination file for writing
    DirEntry dest_entry;
    if (create_file(device, bpb, dest_path, &dest_entry) != FAT_SUCCESS) {
        fclose(src_file);
        return FAT_ERROR;
    }

    // Buffer for reading/writing data
    uint8_t buffer[BUFFER_SIZE];

    // Read and write data in chunks
    size_t bytes_read, bytes_written;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, src_file)) > 0) {
        bytes_written = write_file(device, bpb, &dest_entry, buffer, (uint32_t)bytes_read);
        if (bytes_written != bytes_read) {
            fclose(src_file);
            delete_file(device, bpb, dest_path); // Delete the incomplete destination file
            return FAT_ERROR;
        }
    }

    // Close files
    fclose(src_file);

    return FAT_SUCCESS;
}

int move_file(HANDLE device, const BPB *bpb, const char *src_path, const char *dest_path) {
    if (!device || !bpb || !src_path || !dest_path) {
        return FAT_ERROR;
    }

    // Copy the file from source to destination
    if (copy_file(device, bpb, src_path, dest_path) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Delete the source file
    if (delete_file(device, bpb, src_path) != FAT_SUCCESS) {
        // If deletion fails, attempt to delete the partially copied destination file
        delete_file(device, bpb, dest_path);
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int rename_file(HANDLE device, const BPB *bpb, const char *old_path, const char *new_path) {
    if (!device || !bpb || !old_path || !new_path) {
        return FAT_ERROR;
    }

    // Read the directory entry for old_path
    DirEntry old_entry;
    if (find_directory_entry(device, bpb, old_path, &old_entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Update the name in the directory entry to new_path
    strncpy(old_entry.name, new_path, 11);
    old_entry.name[11] = '\0'; // Ensure null-terminated

    // Write the updated directory entry back to disk
    if (write_directory_entry(device, bpb, old_path, &old_entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

// Directory Operations
int read_directory(HANDLE device, const BPB *bpb, const char *path, DirEntry *entries, uint32_t max_entries) {
    if (!device || !bpb || !path || !entries || max_entries == 0) {
        return FAT_ERROR;
    }

    // Find the directory entry corresponding to the path
    DirEntry dir_entry;
    if (find_directory_entry(device, bpb, path, &dir_entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Validate that the found entry is a directory
    if (!(dir_entry.attr & ATTR_DIRECTORY)) {
        return FAT_ERROR; // Not a directory
    }

    // Read directory entries
    uint32_t total_entries_read = 0;
    uint32_t cluster = get_first_cluster(&dir_entry);
    uint32_t sector_size = bpb->bytes_per_sector;
    uint32_t dir_entries_per_sector = sector_size / sizeof(DirEntry);
    uint32_t sector = cluster_to_sector(bpb, cluster);

    while (cluster != FAT_EOF_CLUSTER) {
        // Read the sector
        uint8_t buffer[sector_size];
        if (read_sector(device, sector, buffer) != FAT_SUCCESS) {
            return FAT_ERROR;
        }

        // Parse directory entries in the sector
        DirEntry *sector_entries = (DirEntry *)buffer;
        for (int i = 0; i < dir_entries_per_sector; ++i) {
            if (sector_entries[i].name[0] == DIR_ENTRY_FREE || sector_entries[i].name[0] == DIR_ENTRY_DELETED) {
                continue; // Unused or deleted entry
            }

            // Copy the entry to the output array
            if (total_entries_read < max_entries) {
                memcpy(&entries[total_entries_read], &sector_entries[i], sizeof(DirEntry));
                total_entries_read++;
            } else {
                return total_entries_read; // Reached max_entries limit
            }
        }

        // Move to the next cluster in the chain
        cluster = get_next_cluster(device, bpb, cluster);
        sector = cluster_to_sector(bpb, cluster);
    }

    return total_entries_read;
}

int create_directory(HANDLE device, const BPB *bpb, const char *path) {
    if (!device || !bpb || !path) {
        return FAT_ERROR;
    }

    // Ensure the directory doesn't already exist
    DirEntry existing_entry;
    if (find_directory_entry(device, bpb, path, &existing_entry) == FAT_SUCCESS) {
        return FAT_ERROR; // Directory already exists
    }

    // Find the parent directory path
    char parent_path[MAX_PATH_LENGTH];
    if (!get_parent_directory(path, parent_path, MAX_PATH_LENGTH)) {
        return FAT_ERROR;
    }

    // Find the parent directory entry
    DirEntry parent_entry;
    if (find_directory_entry(device, bpb, parent_path, &parent_entry) != FAT_SUCCESS) {
        return FAT_ERROR; // Parent directory not found
    }

    // Validate that the parent entry is a directory
    if (!(parent_entry.attr & ATTR_DIRECTORY)) {
        return FAT_ERROR; // Parent is not a directory
    }

    // Create a new directory entry
    DirEntry new_entry;
    memset(&new_entry, 0, sizeof(DirEntry));
    strncpy(new_entry.name, get_filename_from_path(path), 11);
    new_entry.attr = ATTR_DIRECTORY;
    set_current_date_time(&new_entry);

    // Find a free cluster for the new directory
    uint32_t new_cluster = find_free_cluster(device, bpb);
    if (new_cluster == FAT_ERROR) {
        return FAT_ERROR; // No free clusters available
    }

    // Write the new directory entry to disk
    if (write_directory_entry(device, bpb, path, &new_entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Initialize the cluster chain for the new directory
    if (init_cluster_chain(device, bpb, new_cluster) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Update the parent directory's cluster chain to include the new directory
    if (append_cluster_to_chain(device, bpb, get_first_cluster(&parent_entry), new_cluster) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int delete_directory(HANDLE device, const BPB *bpb, const char *path) {
    if (!device || !bpb || !path) {
        return FAT_ERROR;
    }

    // Find the directory entry for the directory to be deleted
    DirEntry dir_entry;
    if (find_directory_entry(device, bpb, path, &dir_entry) != FAT_SUCCESS) {
        return FAT_ERROR; // Directory not found
    }

    // Validate that the found entry is a directory
    if (!(dir_entry.attr & ATTR_DIRECTORY)) {
        return FAT_ERROR; // Not a directory
    }

    // Ensure the directory is empty (no files or subdirectories)
    DirEntry entries[MAX_DIRECTORY_ENTRIES];
    int num_entries = read_directory(device, bpb, path, entries, MAX_DIRECTORY_ENTRIES);
    if (num_entries == FAT_ERROR) {
        return FAT_ERROR; // Error reading directory contents
    }

    for (int i = 0; i < num_entries; ++i) {
        if (strcmp(entries[i].name, ".") != 0 && strcmp(entries[i].name, "..") != 0) {
            return FAT_ERROR; // Directory is not empty
        }
    }

    // Remove the directory entry from its parent directory
    if (delete_directory_entry(device, bpb, path) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Free the cluster chain associated with the directory
    uint32_t first_cluster = get_first_cluster(&dir_entry);
    if (free_cluster_chain(device, bpb, first_cluster) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

// Utility Functions
uint32_t cluster_to_sector(const BPB *bpb, uint32_t cluster) {
    // Determine the starting sector of the data area (cluster 2 onwards)
    uint32_t data_start_sector = bpb->reserved_sectors + (bpb->num_fats * bpb->sectors_per_fat_32);

    // Calculate the sector where the cluster starts
    uint32_t sector = data_start_sector + ((cluster - 2) * bpb->sectors_per_cluster);

    return sector;
}

uint32_t sector_to_cluster(const BPB *bpb, uint32_t sector) {
    // Determine the starting sector of the data area (cluster 2 onwards)
    uint32_t data_start_sector = bpb->reserved_sectors + (bpb->num_fats * bpb->sectors_per_fat_32);

    // Calculate the cluster where the sector belongs
    uint32_t cluster = 2 + ((sector - data_start_sector) / bpb->sectors_per_cluster);

    return cluster;
}

int read_sector(char drive, unsigned long sector, void *buffer) {
    HANDLE hDevice;
    DWORD bytesRead;
    char szDrive[8];
    sprintf(szDrive, "\\\\.\\%c:", drive);

    // Open the drive in raw mode
    hDevice = CreateFile(szDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error opening drive %c\n", drive);
        return FAT_ERROR;
    }

    // Set the file pointer to the desired starting sector
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)sector * SECTOR_SIZE;
    if (!SetFilePointerEx(hDevice, li, NULL, FILE_BEGIN)) {
        CloseHandle(hDevice);
        printf("Error setting file pointer\n");
        return FAT_ERROR;
    }

    // Read the sector into the buffer
    if (!ReadFile(hDevice, buffer, SECTOR_SIZE, &bytesRead, NULL)) {
        CloseHandle(hDevice);
        printf("Error reading sector\n");
        return FAT_ERROR;
    }

    CloseHandle(hDevice);
    return FAT_SUCCESS;
}

int write_sector(char drive, unsigned long sector, const void *buffer) {
    HANDLE hDevice;
    DWORD bytesWritten;
    char szDrive[8];
    sprintf(szDrive, "\\\\.\\%c:", drive);

    // Open the drive in raw mode
    hDevice = CreateFile(szDrive, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error opening drive %c\n", drive);
        return FAT_ERROR;
    }

    // Set the file pointer to the desired starting sector
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)sector * SECTOR_SIZE;
    if (!SetFilePointerEx(hDevice, li, NULL, FILE_BEGIN)) {
        CloseHandle(hDevice);
        printf("Error setting file pointer\n");
        return FAT_ERROR;
    }

    // Write the sector from the buffer
    if (!WriteFile(hDevice, buffer, SECTOR_SIZE, &bytesWritten, NULL)) {
        CloseHandle(hDevice);
        printf("Error writing sector\n");
        return FAT_ERROR;
    }

    CloseHandle(hDevice);
    return FAT_SUCCESS;
}

int fat_time_to_string(unsigned short fat_time, unsigned short fat_date, char *buffer, size_t buffer_size) {
    // Extract time components
    int hour = (fat_time >> 11) & 0x1F;
    int minute = (fat_time >> 5) & 0x3F;
    int second = (fat_time & 0x1F) * 2; // FAT time records seconds in 2-second increments

    // Extract date components
    int year = ((fat_date >> 9) & 0x7F) + 1980;
    int month = (fat_date >> 5) & 0x0F;
    int day = fat_date & 0x1F;

    // Format the string according to FAT timestamp format
    snprintf(buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second);

    return FAT_SUCCESS;
}

// Main function or other entry point if needed
int main() {
    // Example usage or test code
    return 0;
}
