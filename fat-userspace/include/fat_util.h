#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>



// Function to read the boot sector of the FAT filesystem
void read_boot_sector(FILE *fp, FAT_BootSector *boot_sector) {
    fseek(fp, 0, SEEK_SET); // Move to the start of the file
    fread(boot_sector, sizeof(FAT_BootSector), 1, fp); // Read boot sector
}

// Function to list the root directory entries
void list_root_directory(FILE *fp, FAT_BootSector *boot_sector) {
    FAT_DirEntry dir_entry;
    // Calculate the number of sectors used by the root directory
    uint32_t root_dir_sectors = ((boot_sector->root_entry_count * 32) + (boot_sector->bytes_per_sector - 1)) / boot_sector->bytes_per_sector;
    // Calculate the offset to the root directory
    uint32_t root_dir_offset = (boot_sector->reserved_sectors + (boot_sector->num_fats * boot_sector->fat_size_16)) * boot_sector->bytes_per_sector;

    fseek(fp, root_dir_offset, SEEK_SET); // Move to the root directory

    // Loop through the root directory entries
    for (int i = 0; i < boot_sector->root_entry_count; i++) {
        fread(&dir_entry, sizeof(FAT_DirEntry), 1, fp); // Read directory entry

        if (dir_entry.filename[0] == 0x00) break; // No more entries
        if (dir_entry.filename[0] == 0xE5) continue; // Deleted entry

        if (!(dir_entry.attr & 0x08)) { // Not a volume label
            printf("%.8s.%.3s  %10u bytes\n", dir_entry.filename, dir_entry.ext, dir_entry.file_size);
        }
    }
}

// Main Function
int main(int argc, char *argv[]) {
    // Ensure the program is called with one argument (the FAT image file)
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <FAT image file>\n", argv[0]);
        return 1;
    }

    // Open the FAT image file in binary read mode
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("Failed to open file");
        return 1;
    }

    FAT_BootSector boot_sector;
    read_boot_sector(fp, &boot_sector); // Read the boot sector
    list_root_directory(fp, &boot_sector); // List the root directory

    fclose(fp); // Close the file
    return 0;
}
