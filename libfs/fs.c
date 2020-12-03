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
file_descriptor fdscpt[FS_OPEN_MAX_COUNT];

int mounted;

int load_FAT(void)
{
  fat = malloc(sb.n_FAT * BLOCK_SIZE / 2 * sizeof(uint16_t));
  for(size_t i = 1; i < sb.n_FAT + 1; i++){
    if(block_read(i, &fat[(i - 1) * BLOCK_SIZE/2])){
      return -1;
    }
  }
  fat[0] = FAT_EOC;
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
  for(int i = 0; i < FS_OPEN_MAX_COUNT; i++){
    fdscpt[i].rdr_i = -1;
    fdscpt[i].offset = 0;
  }
}

int is_empty_fd(void)
{
  for(int i = 0; i < FS_OPEN_MAX_COUNT; i++){
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
  while(index != FAT_EOC){
    index_next = fat[index];
    fat[index] = 0;
    index = index_next;
  }
}

int available_fd(void)
{
  for(int i = 0; i < FS_OPEN_MAX_COUNT; i++){
    if(fdscpt[i].rdr_i == -1) return i;
  }
  return -1;
}

int is_open(const char* filename, int loc){
  for(int i = 0; i < FS_OPEN_MAX_COUNT; i++){
    if(fdscpt[i].rdr_i == loc)
      return 1;
  }
  return 0;
}

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

int get_size(int fd)
{
  return rdr.f[fdscpt[fd].rdr_i].file_size;
}

int get_data_index(int fd)
{
  return rdr.f[fdscpt[fd].rdr_i].data_i;
}

void set_data_index(int fd, int index)
{
  rdr.f[fdscpt[fd].rdr_i].data_i = index;
}

int available_fat(void)
{
  for(int i=1; i < sb.n_data; i++){
    if(fat[i] == 0)
      return i;
  }
  return -1;
}

int next_fat(int fat_i)
{
  int data_i = fat[fat_i];
  if(data_i == FAT_EOC) return -1;
  return data_i;
}

int fat_end_loc(int fd)
{
  int cur = rdr.f[fdscpt[fd].rdr_i].data_i;
  while(fat[cur] != FAT_EOC){
    cur = fat[cur];
  }
  return cur;
}

int fat_count(int fd)
{
  int cur = rdr.f[fdscpt[fd].rdr_i].data_i;
  int count = 1;
  while(fat[cur] != FAT_EOC){
    cur = fat[cur];
    count ++;
  }
  return count;
}

int extra_block(int count, int offset, int size)
{
  int cur_n_block = -1;
  int new_n_block = -1;
  int diff = 0;

  if(size % BLOCK_SIZE == 0)
    cur_n_block = size/BLOCK_SIZE;
  else
    cur_n_block = size/BLOCK_SIZE + 1;
  if(size == 0)
    cur_n_block = 1;
  if((count + offset) % BLOCK_SIZE == 0)
    new_n_block = (count + offset) / BLOCK_SIZE;
  else
    new_n_block = (count + offset) / BLOCK_SIZE + 1;
  diff = new_n_block - cur_n_block;
  if(diff > 0) return diff;
  else return 0;
}

int tot_write_block(int count, int offset)
{
  int total = count + offset;
  if(total % BLOCK_SIZE)
    return total/BLOCK_SIZE + 1;
  return total/BLOCK_SIZE;
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
  rdr.f[loc].file_name[0] = '\0';
  rdr.f[loc].data_i = -1;
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
  if(fd < 0 || fd > FS_OPEN_MAX_COUNT) return -1;
  fdscpt[fd].rdr_i = -1;
  fdscpt[fd].offset = 0;
  return 0;
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
  if(!mounted) return -1;
  if(fd < 0 || fd > FS_OPEN_MAX_COUNT) return -1;
  if(fdscpt[fd].rdr_i == -1) return -1;
  int size = -1;
  size = rdr.f[fdscpt[fd].rdr_i].file_size;
  return size;
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
  if(!mounted) return -1;
  if(fd < 0 || fd > FS_OPEN_MAX_COUNT) return -1;
  if(fdscpt[fd].rdr_i == -1) return -1;
  fdscpt[fd].offset = offset;
  return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4*/
  if(!mounted) return -1;
  if(fd < 0 || fd > FS_OPEN_MAX_COUNT) return -1;
  if(fdscpt[fd].rdr_i == -1) return -1;

  int offset = fdscpt[fd].offset;
  int extra = extra_block(count, offset, get_size(fd));
  uint8_t * bounce_buffer = malloc(BLOCK_SIZE);

  if(count != 0 && get_data_index(fd) == FAT_EOC){
    //create new fat
    int new_fat = available_fat();
    set_data_index(fd, new_fat);
    fat[new_fat] = FAT_EOC;
  }
  int next = fat_end_loc(fd);
  for(int i=0; i<extra; i++){
    fat[next] = available_fat();
    next = fat[next];
    fat[next] = FAT_EOC;
  }

  int tot_block = tot_write_block(count, offset);
  int cur_block = get_data_index(fd);

  int buf_pos = 0;
  int n_write = 0;
  int written = 0;
  for(int i=0; i<tot_block; i++){
    if(offset < BLOCK_SIZE){
      block_read(cur_block + sb.data_i, bounce_buffer);

      if(count + offset > BLOCK_SIZE){
        n_write = BLOCK_SIZE - offset;
      }
      else{
        n_write = count;
      }
      memcpy(bounce_buffer + offset, buf + buf_pos, n_write);
      block_write(cur_block + sb.data_i, bounce_buffer);
      buf_pos += BLOCK_SIZE - offset;
      count -= n_write;
      written += n_write;
      cur_block = next_fat(cur_block);
    }
    offset -= BLOCK_SIZE;
    if(offset <= 0)
      offset = 0;
  }
  rdr.f[fdscpt[fd].rdr_i].file_size += written;
  return written;
}

int fs_read(int fd, void *buf, size_t count)
{

  if(!mounted) return -1;
  if (fd > FS_OPEN_MAX_COUNT || fd < 0) return -1;
  if (fdscpt[fd].rdr_i == -1) return -1;

  int block_index = get_fileindex(fd);
  int block_count = 0;
  int block_n = 0;
  int real_count = -1;
  int temp_block_index = block_index;
  if(get_filesize(fd)-fdscpt[fd].offset < count)
  {
    real_count = get_filesize(fd)-fdscpt[fd].offset;
  }
  else if(get_filesize(fd)-fdscpt[fd].offset >= count)
  {
    real_count = count;
  }

  while (get_nextdataindex(temp_block_index) != FAT_EOC) {
    temp_block_index = get_nextdataindex(temp_block_index);
    block_n++;
  }
  uint8_t *bounce_buf = malloc(block_n * BLOCK_SIZE);

  uint8_t *block_buf = malloc(BLOCK_SIZE);
  do
  {
    block_read(block_index + sb.data_i, block_buf);
    memcpy(bounce_buf+BLOCK_SIZE*block_count, block_buf, BLOCK_SIZE);
    block_index = get_nextdataindex(block_index);
    block_count++;
  } while(block_index != FAT_EOC);
  printf("It is %c\n", bounce_buf[fdscpt[fd].offset]);
  memcpy(buf, bounce_buf+fdscpt[fd].offset, real_count);
  return count;
}
