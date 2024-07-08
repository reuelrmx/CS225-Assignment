#include <string.h>
#include <stdlib.h>
#include "fat_fs.h"
#include "fat_util.h"

// Helper function to find an empty directory entry
static int find_empty_dir_entry(HANDLE device, const BPB *bpb, DirEntry *entry) {
    // Your implementation here to locate an empty directory entry
    // This is a placeholder and needs actual implementation
    return FAT_SUCCESS;
}

// Helper function to locate a file in the directory
static int locate_file(HANDLE device, const BPB *bpb, const char *path, DirEntry *entry) {
    // Your implementation here to locate a file in the directory
    // This is a placeholder and needs actual implementation
    return FAT_SUCCESS;
}

int create_file(HANDLE device, const BPB *bpb, const char *path, DirEntry *entry) {
    if (find_empty_dir_entry(device, bpb, entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Set up the new directory entry
    memset(entry, 0, sizeof(DirEntry));
    strncpy(entry->name, path, sizeof(entry->name));
    entry->attr = 0; // Set appropriate attributes

    // Write the new directory entry to the device
    if (write_fat_entry(device, bpb, entry->first_cluster_low, (FATEntry *)entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int delete_file(HANDLE device, const BPB *bpb, const char *path) {
    DirEntry entry;
    if (locate_file(device, bpb, path, &entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    // Mark the directory entry as deleted
    entry.name[0] = 0xE5;

    // Write the updated directory entry back to the device
    if (write_fat_entry(device, bpb, entry.first_cluster_low, (FATEntry *)&entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int read_file(HANDLE device, const BPB *bpb, const DirEntry *entry, void *buffer, uint32_t size) {
    uint32_t cluster = entry->first_cluster_low;
    uint32_t bytes_read = 0;
    uint8_t sector_buffer[512]; // Assuming sector size is 512 bytes

    while (size > 0) {
        uint32_t sector = cluster_to_sector(bpb, cluster);
        uint32_t sector_offset = bytes_read % bpb->bytes_per_sector;
        uint32_t to_read = min(size, bpb->bytes_per_sector - sector_offset);

        SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, NULL, NULL)) {
            return FAT_ERROR;
        }

        memcpy(buffer + bytes_read, sector_buffer + sector_offset, to_read);
        bytes_read += to_read;
        size -= to_read;

        if (sector_offset + to_read == bpb->bytes_per_sector) {
            // Move to next cluster
            if (read_fat_entry(device, bpb, cluster, (FATEntry *)&cluster) != FAT_SUCCESS) {
                return FAT_ERROR;
            }
        }
    }

    return bytes_read;
}

int write_file(HANDLE device, const BPB *bpb, const DirEntry *entry, const void *buffer, uint32_t size) {
    uint32_t cluster = entry->first_cluster_low;
    uint32_t bytes_written = 0;
    uint8_t sector_buffer[512]; // Assuming sector size is 512 bytes

    while (size > 0) {
        uint32_t sector = cluster_to_sector(bpb, cluster);
        uint32_t sector_offset = bytes_written % bpb->bytes_per_sector;
        uint32_t to_write = min(size, bpb->bytes_per_sector - sector_offset);

        if (sector_offset > 0 || to_write < bpb->bytes_per_sector) {
            SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
            if (!ReadFile(device, sector_buffer, bpb->bytes_per_sector, NULL, NULL)) {
                return FAT_ERROR;
            }
        }

        memcpy(sector_buffer + sector_offset, buffer + bytes_written, to_write);

        SetFilePointer(device, sector * bpb->bytes_per_sector, NULL, FILE_BEGIN);
        if (!WriteFile(device, sector_buffer, bpb->bytes_per_sector, NULL, NULL)) {
            return FAT_ERROR;
        }

        bytes_written += to_write;
        size -= to_write;

        if (sector_offset + to_write == bpb->bytes_per_sector) {
            // Move to next cluster
            if (read_fat_entry(device, bpb, cluster, (FATEntry *)&cluster) != FAT_SUCCESS) {
                return FAT_ERROR;
            }
        }
    }

    return bytes_written;
}

int copy_file(HANDLE device, const BPB *bpb, const char *src_path, const char *dest_path) {
    DirEntry src_entry, dest_entry;
    if (locate_file(device, bpb, src_path, &src_entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    if (create_file(device, bpb, dest_path, &dest_entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    void *buffer = malloc(src_entry.file_size);
    if (!buffer) {
        return FAT_ERROR;
    }

    if (read_file(device, bpb, &src_entry, buffer, src_entry.file_size) != src_entry.file_size) {
        free(buffer);
        return FAT_ERROR;
    }

    if (write_file(device, bpb, &dest_entry, buffer, src_entry.file_size) != src_entry.file_size) {
        free(buffer);
        return FAT_ERROR;
    }

    free(buffer);
    return FAT_SUCCESS;
}

int move_file(HANDLE device, const BPB *bpb, const char *src_path, const char *dest_path) {
    if (copy_file(device, bpb, src_path, dest_path) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    if (delete_file(device, bpb, src_path) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int rename_file(HANDLE device, const BPB *bpb, const char *old_path, const char *new_path) {
    DirEntry entry;
    if (locate_file(device, bpb, old_path, &entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    memset(entry.name, ' ', sizeof(entry.name));
    strncpy(entry.name, new_path, sizeof(entry.name));

    if (write_fat_entry(device, bpb, entry.first_cluster_low, (FATEntry *)&entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int read_directory(HANDLE device, const BPB *bpb, const char *path, DirEntry *entries, uint32_t max_entries) {
    // This function should read directory entries from the specified path
    // Your implementation here
    return 0; // Return number of entries read
}

int create_directory(HANDLE device, const BPB *bpb, const char *path) {
    DirEntry entry;
    if (find_empty_dir_entry(device, bpb, &entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    memset(&entry, 0, sizeof(DirEntry));
    strncpy(entry.name, path, sizeof(entry.name));
    entry.attr = 0x10; // Directory attribute

    if (write_fat_entry(device, bpb, entry.first_cluster_low, (FATEntry *)&entry) != FAT_SUCCESS) {
        return FAT_ERROR;
    }

    return FAT_SUCCESS;
}

int delete_directory(HANDLE device, const BPB *bpb, const char *path) {
    // This function should delete the directory and its contents
    // Your implementation here
    return FAT_SUCCESS;
}
