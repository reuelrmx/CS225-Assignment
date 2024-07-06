#ifndef FAT_H_INCLUDED
#define FAT_H_INCLUDED

// this includes the standard integer type definitions
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

// ###################################################
// here the structures of the fat are defined        #
// this includes the BIOS Parameter Block (BPB)      #
// ###################################################

// BIOS Parameter Block (BPB) structure
#pragma pack(push, 1)
typedef struct {
    uint16_t bytes_per_sector;      // Bytes per sector
    uint8_t sectors_per_cluster;    // Sectors per cluster
    uint16_t reserved_sectors;      // Number of reserved sectors
    uint8_t num_fats;               // Number of FATs
    uint16_t root_entries;          // Number of root directory entries
    uint16_t total_sectors_16;      // Total sectors (if zero, use total_sectors_32)
    uint8_t media_descriptor;       // Media descriptor
    uint16_t sectors_per_fat_16;    // Sectors per FAT (if zero, use sectors_per_fat_32)
    uint16_t sectors_per_track;     // Sectors per track (for BIOS)
    uint16_t num_heads;             // Number of heads (for BIOS)
    uint32_t hidden_sectors;        // Hidden sectors
    uint32_t total_sectors_32;      // Total sectors (if total_sectors_16 is zero)

    // Extended Boot Record (EBR) for FAT32
    uint32_t sectors_per_fat_32;    // Sectors per FAT
    uint16_t extended_flags;        // Extended flags
    uint16_t fs_version;            // File system version
    uint32_t root_cluster;          // Root directory's starting cluster
    uint16_t fs_info;               // File system info sector number
    uint16_t backup_boot_sector;    // Backup boot sector number
    uint8_t reserved[12];           // Reserved
    uint8_t drive_number;           // Drive number
    uint8_t reserved1;              // Reserved
    uint8_t boot_signature;         // Boot signature
    uint32_t volume_id;             // Volume ID
    char volume_label[11];          // Volume label
    char fs_type[8];                // File system type
} BPB;
#pragma pack(pop)


// ###################################################
// this section represents an entry to the File      #
// Allocation Table structure                        #
// ###################################################
typedef struct {
    uint32_t cluster;
} FATEntry;

// ###################################################
// this section represents the directory entry,      #
//  holding metadata about files and directories     #
// ###################################################
#pragma pack(push, 1)
typedef struct {
    char name[11];                  // File name
    uint8_t attr;                   // File attributes
    uint8_t nt_reserved;            // Reserved for use by Windows NT
    uint8_t create_time_tenth;      // Millisecond stamp at file creation
    uint16_t create_time;           // Time file was created
    uint16_t create_date;           // Date file was created
    uint16_t last_access_date;      // Last access date
    uint16_t first_cluster_high;    // High word of first cluster number (FAT32)
    uint16_t write_time;            // Last write time
    uint16_t write_date;            // Last write date
    uint16_t first_cluster_low;     // Low word of first cluster number
    uint32_t file_size;             // File size in bytes
} DirEntry;
#pragma pack(pop)

// FAT Types
#define FAT12 12
#define FAT16 16
#define FAT32 32

// Special cluster values
#define FAT_FREE_CLUSTER     0x00000000
#define FAT_RESERVED_CLUSTER 0xFFFFFFF0
#define FAT_BAD_CLUSTER      0xFFFFFFF7
#define FAT_EOF_CLUSTER      0xFFFFFFFF

// Function Prototypes

// Initialization
int init_fat(const char *device_path, BPB *bpb);

// FAT Manipulation
int read_fat_entry(HANDLE device, const BPB *bpb, uint32_t cluster, FATEntry *entry);
int write_fat_entry(HANDLE device, const BPB *bpb, uint32_t cluster, const FATEntry *entry);

// File Operations
int create_file(HANDLE device, const BPB *bpb, const char *path, DirEntry *entry);
int delete_file(HANDLE device, const BPB *bpb, const char *path);
int read_file(HANDLE device, const BPB *bpb, const DirEntry *entry, void *buffer, uint32_t size);
int write_file(HANDLE device, const BPB *bpb, const DirEntry *entry, const void *buffer, uint32_t size);

// Directory Operations
int read_directory(HANDLE device, const BPB *bpb, const char *path, DirEntry *entries, uint32_t max_entries);
int create_directory(HANDLE device, const BPB *bpb, const char *path);
int delete_directory(HANDLE device, const BPB *bpb, const char *path);

// Utility Functions
uint32_t cluster_to_sector(const BPB *bpb, uint32_t cluster);
uint32_t sector_to_cluster(const BPB *bpb, uint32_t sector);

#endif // FAT_H_INCLUDED

