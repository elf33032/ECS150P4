#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define SIG_LEN 8
#define N_FILE 128
#define FAT_EOC 0xFFFF
#define FD_MAX_COUNT 32

/* TODO: Phase 1 */

typedef struct superblock
{
  uint8_t sig[SIG_LEN];
  uint16_t n_blocks;
  uint16_t rdr_i;
  uint16_t data_i;
  uint16_t n_data;
  uint8_t n_FAT;
  uint8_t padding[4079];
} __attribute__ ((__packed__)) superblock;

typedef uint16_t* FAT;

typedef struct file
{
  uint8_t file_name [FS_FILENAME_LEN];
  uint32_t file_size;
  uint16_t data_i;
  uint8_t padding[10];
} __attribute__ ((__packed__)) file;

typedef struct root_dir
{
  file f[N_FILE];
} __attribute__ ((__packed__)) root_dir;

typedef struct file_descriptor
{
  int rdr_i;
  int offset;
}file_descriptor;

superblock sb;
FAT fat;
root_dir rdr;
file_descriptor fdscpt[FD_MAX_COUNT];

int mounted;

int load_FAT(void)
{
  fat = malloc(sb.n_FAT * BLOCK_SIZE / 2 * sizeof(uint16_t));
  for(size_t i = 1; i < sb.n_FAT + 1; i++){
    if(block_read(i, &fat[(i - 1) * BLOCK_SIZE/2])){
      return -1;
    }
  }
  return 0;
}

int load_rdr(void)
{
  if(block_read(sb.rdr_i, &rdr)) return -1;
  return 0;
}

int load_sb(void)
{
  if(block_read(0, &sb)) return -1;
  return 0;
}

void init_fd(void)
{
  for(int i = 0; i < FD_MAX_COUNT; i++){
    fdscpt[i].rdr_i = -1;
    fdscpt[i].offset = 0;
  }
}

int is_empty_fd(void)
{
  for(int i = 0; i < FD_MAX_COUNT; i++){
    if(fdscpt[i].rdr_i != -1) return 0;
  }
  return 1;
}

int fat_spare(void)
{
  int count = 0;
  for(int i = 1; i < sb.n_data; i++){
    if(fat[i] == 0){
      count++;
    }
  }
  return count;
}

int rdr_spare(void)
{
  int count = 0;
  for(int i = 0; i < FS_FILE_MAX_COUNT; i++){
    if(rdr.f[i].file_name[0] == '\0')
      count ++;
  }
  return count;
}

int update_sb_rdr(void)
{
  if(block_write(0, &sb)) return -1;
  if(block_write(sb.rdr_i, &rdr)) return -1;
}

int update_fat(void){
  for(size_t i = 1; i < sb.n_FAT + 1; i++){
    if(block_write(i, &fat[(i - 1) * BLOCK_SIZE/2])){
      return -1;
    }
  }
  return 0;
}

int is_valid_fname(const char * filename)
{
  int fn_len = (int) strlen(filename);
  if(fn_len > FS_FILENAME_LEN) return 0;
  if(filename[0] == '\0') return 0;
  //if(filename[fn_len - 1] != '\0') return 0;
  return 1;
}

int file_exist(const char * filename)
{
  for(int i = 0; i < FS_FILE_MAX_COUNT; i++){
    if(strcmp((char *) rdr.f[i].file_name, filename) == 0)
      return i;
  }
  return -1;
}

int available_file(void)
{
  for(int i = 0; i < FS_FILE_MAX_COUNT; i++){
    if(rdr.f[i].file_name[0] == '\0') return i;
  }
  return -1;
}

void fat_del(size_t index)
{
  size_t index_next;
  while(fat[index] != FAT_EOC){
    index_next = fat[index];
    fat[index] = 0;
    index = index_next;
  }
}

int available_fd(void)
{
  for(int i = 0; i < FD_MAX_COUNT; i++){
    if(fdscpt[i].rdr_i == -1) return i;
  }
  return -1;
}

int is_open(char* filename, int loc)
{
  for(int i = 0; i < FD_MAX_COUNT; i++){
    if(fdscpt[i].rdr_i == loc)
      return 1;
  }
  return 0;
}

int from_block(int fd)
{
  int result = fdscpt[fd].offset / BLOCK_SIZE;
  return result + 1;
}

int get_remainOffset(int fd)
{
  int block_num = from_block(fd) - 1;
  int result = fdscpt[fd].offset - block_num*BLOCK_SIZE;
  return result;
}
//
// int to_block(size_t count, int offset)
// {
//   int result = (count+offset)/BLOCK_SIZE;
//   if((count+offset)%BLOCK_SIZE == 0)
//   {
//     return result;
//   }
//   else
//   {
//     return result+1;
//   }
// }

int get_filesize(int fd)
{
  int result = rdr.f[fdscpt[fd].rdr_i].file_size;
  return result;
}

int get_fileindex(int fd)
{
  int result = rdr.f[fdscpt[fd].rdr_i].data_i;
  return result;
}

int get_nextdataindex(int pre_index){
  int result = fat[pre_index];
  return result;
}

int fs_mount(const char *diskname)
{
	/* TODO: Phase 1 */
  if(block_disk_open(diskname)) return -1;
  if(load_sb()) return -1;
  if(memcmp(&sb.sig, "ECS150FS", SIG_LEN)) return -1;
  if((int) sb.n_blocks != block_disk_count()) return -1;
  if(load_FAT()) return -1;
  if(load_rdr()) return -1;
  init_fd();
  mounted = 1;
  return 0;
}

int fs_umount(void)
{
	/* TODO: Phase 1 */
  if(!mounted) return -1;
  if(update_sb_rdr()) return -1;
  if(update_fat()) return -1;
  //FD checking missing
  if(!is_empty_fd()) return -1;
  free(fat);
  if(block_disk_close()) return -1;
  return 0;
}

int fs_info(void)
{
	/* TODO: Phase 1 */
  if(!mounted) return -1;
  printf("FS Info:\n");
  printf("total_blk_count=%d\n", sb.n_blocks);
  printf("fat_blk_count=%d\n", sb.n_FAT);
  printf("rdir_blk=%d\n", sb.rdr_i);
  printf("data_blk=%d\n", sb.data_i);
  printf("data_blk_count=%d\n", sb.n_data);
  printf("fat_free_ratio=%d/%d\n", fat_spare(), sb.n_data);
  printf("rdir_free_ratio=%d/%d\n", rdr_spare(), FS_FILE_MAX_COUNT);
  return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
  int f_indx= -1;
  if(!is_valid_fname(filename)) return -1;
  if(file_exist(filename) != -1) return -1;
  f_indx = available_file();
  if(f_indx == -1) return -1;
  strcpy((char *) rdr.f[f_indx].file_name, filename);
  rdr.f[f_indx].file_size = 0;
  rdr.f[f_indx].data_i = FAT_EOC;
  return 0;
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
  if(!is_valid_fname(filename)) return -1;
  int loc = file_exist(filename);
  if(loc == -1) return -1;
  if(is_open(filename, loc)) return -1;
  fat_del(rdr.f[loc].data_i);
  if((char *) rdr.f[loc].file_name == NULL) return -1;
  strcpy((char *) rdr.f[loc].file_name, "\0");
  return 0;
}


int fs_ls(void)
{
	/* TODO: Phase 2 */
  if(!mounted) return -1;
  printf("FS Ls:\n");
  for(int i = 0; i < FS_FILE_MAX_COUNT; i++){
    if(rdr.f[i].file_name[0] != '\0'){
      printf("file: %s, size: %d, data_blk: %d\n", rdr.f[i].file_name,
              rdr.f[i].file_size, rdr.f[i].data_i);
    }
  }
  return 0;
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
  if(!mounted) return -1;
  int fd_i = available_fd();
  fdscpt[fd_i].rdr_i = file_exist(filename);
  return fd_i;
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
  if(!mounted) return -1;
  if(fd < 0 || fd > FD_MAX_COUNT) return -1;
  fdscpt[fd].rdr_i = -1;
  fdscpt[fd].offset = 0;
  return 0;
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
  if(!mounted) return -1;
  if(fd < 0 || fd > FD_MAX_COUNT) return -1;
  if(fdscpt[fd].rdr_i == -1) return -1;
  int size = -1;
  size = rdr.f[fdscpt[fd].rdr_i].file_size;
  return size;
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
  if(!mounted) return -1;
  if(fd < 0 || fd > FD_MAX_COUNT) return -1;
  if(fdscpt[fd].rdr_i == -1) return -1;
  fdscpt[fd].offset = offset;
  return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
  if(!mounted) return -1;
  if (fd > FD_MAX_COUNT || fd < 0) return -1;
  if (fdscpt[fd].rdr_i == -1) return -1;
  uint8_t *bounce_buf = malloc(BLOCK_SIZE);
  int block_index = get_fileindex(fd) - sb.data_i;
  int temp_index = -1;
  int rest_size = get_filesize(fd) - fdscpt[fd].offset;
  int temp_next_block = -1;
  int less_block = -1;
  int real_block_num = 0;
  int temp_block_index = block_index;
  int block_n = 0;
  int needed_block = 0;
  int block_count = 0;
  int real_count = count;

  while (get_nextdataindex(temp_block_index) != FAT_EOC)
  {
    temp_block_index = get_nextdataindex(temp_block_index)
    block_n++;
  }

  if (rest_size < count)
  {
    needed_block = (count - rest_size)/BLOCK_SIZE + 1;
    temp_index = 0;
    temp_next_block = get_nextdataindex(block_index);
    while (temp_next_block != FAT_EOC)
    {
      temp_index = temp_next_block;
      temp_next_block = get_nextdataindex(temp_index);
    }
    for (size_t j = 0; j < needed_block ; j++)
    {
      for (size_t i = 0; i < sb.n_data; i++)
      {
        if (fat[i] == 0)
        {
          fat[temp_index] = i;
          temp_index = i;
        }
        if (i == sb.n_data && fat[i] != 0)
        {
          less_block = needed_block - j;
          real_count = rest_size + j*BLOCK_SIZE;
        }
      }
    }
    fat[temp_index] = FAT_EOC;
  }

  uint8_t *file_buff = malloc((block_n + needed_block) * BLOCK_SIZE);
  uint8_t *write_buff = malloc((block_n + needed_block) * BLOCK_SIZE);
  uint8_t *block_buff = malloc(BLOCK_SIZE);

  do
  {
    block_read(block_index, &block_buf);
    memcpy(&file_buff+BLOCK_SIZE*block_count, &block_buf, BLOCK_SIZE);
    block_index = get_nextdataindex(block_index) + sb.data_i;
    block_count++
  } while(block_index != FAT_EOC);

  memcpy(&write_buff[offset], &buf, count);
  memcpy(&write_buff, &file_buff[offset], offset);
  memcpy

}

int fs_read(int fd, void *buf, size_t count)
{
  if(!mounted) return -1;
  if (fd > FD_MAX_COUNT || fd < 0) return -1;
  if (fdscpt[fd].rdr_i == -1) return -1;

  int block_index = get_fileindex(fd) - sb.data_i;
  int block_count = 0;
  int block_n = 0;
  int real_count = -1;
  int temp_block_index = block_index;

  if(get_filesize(fd)-fdscpt[fd].offset < count)
  {
    real_count = get_filesize(fd)-fdscpt[fd].offset;
  }
  else if(get_filesize(fd)-fdscpt[fd].offset < count)
  {
    real_count = count;
  }

  while (get_nextdataindex(temp_block_index) != FAT_EOC) {
    temp_block_index = get_nextdataindex(temp_block_index)
    block_n++;
  }

  uint8_t *bounce_buf = malloc(block_n * BLOCK_SIZE);
  uint8_t *block_buf = malloc(BLOCK_SIZE);

  do
  {
    block_read(block_index, &block_buf);
    memcpy(&bounce_buf+BLOCK_SIZE*block_count, &block_buf, BLOCK_SIZE);
    block_index = get_nextdataindex(block_index) + sb.data_i;
    block_count++
  } while(block_index != FAT_EOC);

  memcpy(&buf, &bounce_buf[fdscpt[fd].offset], real_count);
  return count;
}
