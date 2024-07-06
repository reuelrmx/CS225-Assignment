#ifndef FAT_UTIL_H
#define FAT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdio.h>

// Macro Definitions
#define SECTOR_SIZE 512  // Size of a sector in bytes
#define FAT12 1          // FAT12 file system type identifier
#define FAT16 2          // FAT16 file system type identifier
#define FAT32 3          // FAT32 file system type identifier

// Error Codes
#define FAT_SUCCESS 0    // Success return code
#define FAT_ERROR -1     // Error return code

// Utility Functions

/**
 * Reads a sector from a FAT file system.
 * @param drive: The drive letter (e.g., 'C').
 * @param sector: The sector number to read.
 * @param buffer: The buffer to store the read data.
 * @return FAT_SUCCESS on success, FAT_ERROR on failure.
 * 
 * This function reads a specified sector from the specified drive and 
 * stores the data in the provided buffer.
 */
int read_sector(char drive, unsigned long sector, void *buffer);

/**
 * Writes a sector to a FAT file system.
 * @param drive: The drive letter (e.g., 'C').
 * @param sector: The sector number to write.
 * @param buffer: The buffer containing data to write.
 * @return FAT_SUCCESS on success, FAT_ERROR on failure.
 * 
 * This function writes the data from the provided buffer to the specified
 * sector on the specified drive.
 */
int write_sector(char drive, unsigned long sector, const void *buffer);

/**
 * Converts a FAT timestamp to a human-readable format.
 * @param fat_time: The FAT time.
 * @param fat_date: The FAT date.
 * @param buffer: The buffer to store the formatted date and time.
 * @param buffer_size: The size of the buffer.
 * @return FAT_SUCCESS on success, FAT_ERROR on failure.
 * 
 * This function converts the FAT time and date into a human-readable string
 * and stores it in the provided buffer.
 */
int fat_time_to_string(unsigned short fat_time, unsigned short fat_date, char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif // FAT_UTIL_H
