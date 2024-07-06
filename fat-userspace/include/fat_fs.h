#ifndef FAT_FS_H
#define FAT_FS_H

#include <stdint.h>
#include <windows.h>

#include "fat.h"

// Constants and Macros
#define FAT_SUCCESS 0
#define FAT_ERROR -1
#define FAT_EOF -2

// File Attribute Flags
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20

// Common FAT Structures and Definitions

// Directory Entry Structure
typedef struct {
    char name[11];             // File name
    uint8_t attr;              // File attributes
    uint8_t nt_res;            // Reserved for use by Windows NT
    uint8_t crt_time_tenth;    // Creation time (tenths of a second)
    uint16_t crt_time;         // Creation time
    uint16_t crt_date;         // Creation date
    uint16_t lst_acc_date;     // Last access date
    uint16_t fst_clus_hi;      // High word of first cluster
    uint16_t wrt_time;         // Last write time
    uint16_t wrt_date;         // Last write date
    uint16_t fst_clus_lo;      // Low word of first cluster
    uint32_t file_size;        // File size in bytes
} __attribute__((packed)) dir_entry_t;

// File Descriptor Structure
typedef struct {
    dir_entry_t dir_entry;     // Directory entry of the file
    uint32_t current_cluster;  // Current cluster of the file
    uint32_t file_pointer;     // Current position in the file
    HANDLE file_handle;        // Windows-specific file handle
} file_desc_t;

// Function Prototypes

// Mount the file system
int fat_mount(const char *device_name);

// Unmount the file system
int fat_unmount(void);

// Open a file
int fat_open(const char *path, file_desc_t *fd);

// Close a file
int fat_close(file_desc_t *fd);

// Read from a file
int fat_read(file_desc_t *fd, void *buffer, uint32_t size);

// Write to a file
int fat_write(file_desc_t *fd, const void *buffer, uint32_t size);

// Seek to a position in a file
int fat_lseek(file_desc_t *fd, uint32_t offset, uint32_t whence);

// List directory contents
int fat_list_dir(const char *path);

// Create a new directory
int fat_mkdir(const char *path);

// Delete a file
int fat_remove(const char *path);

// Delete a directory
int fat_rmdir(const char *path);

// Rename a file or directory
int fat_rename(const char *old_path, const char *new_path);

// Move a file or directory
int fat_move(const char *old_path, const char *new_path);

// Copy a file
int fat_copy(const char *src_path, const char *dest_path);

// Get file attributes
int fat_getattr(const char *path, dir_entry_t *entry);

// Set file attributes
int fat_setattr(const char *path, const dir_entry_t *entry);

#endif // FAT_FS_H
