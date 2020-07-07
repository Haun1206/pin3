#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/fat.h"
#include "devices/disk.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;
static void do_format (void);
struct dir *parse_path(char * path_name, char *file_name);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");
	inode_init ();

#ifdef EFILESYS
	
	fat_init ();
//	printf("HI\n");

	if (format)
		do_format ();
	//printf("HI\n");
	fat_open ();
	//printf("HI\n");
	inode_create (ROOT_DIR_SECTOR, DISK_SECTOR_SIZE, true);
	thread_current ()->cur_dir = dir_open_root ();
	dir_add(thread_current ()->cur_dir, ".", ROOT_DIR_SECTOR);
	//dir_add(thread_current ()->cur_dir, "..", NULL);

#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();


#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */

bool
filesys_create (const char *name, off_t initial_size) {
	//printf("HI\n");
	cluster_t clst = fat_create_chain (0);
	//printf("HI\n");
	disk_sector_t inode_sector = cluster_to_sector(clst);
	//printf("HI\n");
	//printf("HI\n");
	char tmp_name[PATH_MAX +1];
	//printf("%s\n",name);
	struct dir *dir = parse_path(name, tmp_name);
	//printf("%llx\n", dir);

	//printf("HI\n");
	//printf("HI\n");
	//printf("%d\n",clst);
	//printf("%d\n",dir!=NULL);
	bool success = (dir != NULL
			&& clst
			&& inode_create (inode_sector, initial_size, false)
			&& dir_add (dir, tmp_name, inode_sector));
	//printf("%d\n",success);
	//printf("HI\n");
	if (!success && inode_sector != 0){
		//printf("HI\n");
		fat_put(clst, 0);
		//printf("HI\n");
	}
	dir_close (dir);
	//printf("root:%d\n", dir->pos);
	
	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	char tmp_name[NAME_MAX+1];
	struct dir *dir = parse_path(name,tmp_name);
	struct inode *inode = NULL;
	//printf("HI\n");
	//printf("%s\n",name);
	//printf("%s\n",tmp_name);
	if (dir != NULL){
		dir_lookup (dir, tmp_name, &inode);
		dir_close (dir);
		return file_open(inode);
	}
	else
		return NULL;

}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	char tmp_name[NAME_MAX+1];
	struct dir *dir =parse_path(name,tmp_name);
	struct inode * i =NULL;
	dir_lookup(dir,tmp_name,&i);
	//printf("Pl:%d", chekc);
	struct dir *tmp_dir= NULL;

  	char tmp[PATH_MAX + 1];
	bool success = false;
	//printf("k:%d %d\n",inode_get_inumber(dir_get_inode(dir)), inode_is_dir(i));
	if (!inode_is_dir (i) || ((tmp_dir = dir_open (i) )&& !dir_readdir (tmp_dir, tmp))){
		//printf("pleas\n");
		if(dir && dir_remove(dir,tmp_name))
			success = true;
	}
	dir_close(dir);
	if(tmp_dir !=NULL){
		//printf("he\n");
		free (tmp_dir);
	}
	//printf("succe:%d\n", success);
	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
struct dir *parse_path(char * path_name, char *file_name){
	//printf("HI\n");
	struct dir *dir = NULL;
	char path[PATH_MAX+1];
	if(path_name ==NULL){
		//printf("HI\n");
		return NULL;
	}
	if(file_name ==NULL){
		//printf("HI\n");
		return NULL;
	}
	if(strlen(path_name)==0){
		//printf("HI\n");
		return NULL;
	}
	//printf("HI\n");
	//절대경로
	
	strlcpy(path, path_name, PATH_MAX);
	//printf("path:%s", path);
	if(path[0] =='/')
		dir = dir_open_root();
	
	//상대경로
	else{
		if(thread_current()->cur_dir ==NULL){
			dir = dir_open_root();
		}
		//printf("hehe\n", inode_get_inumber(dir_get_inode(dir)));
		dir = dir_reopen(thread_current()->cur_dir);
		//printf("add:%llx", dir);
		
	}

	struct inode * tmp = dir_get_inode(dir);
	//printf("sec:%d\n",tmp==NULL);
	if(inode_is_dir(tmp)==false){
		//printf("HI\n");
		return NULL;
	}
  	char *token, *next_token, *save_ptr;
  	token = strtok_r (path, "/", &save_ptr);
	next_token = strtok_r (NULL, "/", &save_ptr);
	//printf("chekc: %s\n", next_token);
	//printf("Here\n");
	if(token==NULL){
		//printf("HI\n");
		strlcpy(file_name,".",NAME_MAX);
		return dir;
	}
	while(token!=NULL && next_token != NULL){
		struct inode * tempo =NULL;
		//NO DIR
		//printf("??\n");
	
		//printf("sibal\n");
		if(dir_lookup(dir,token,&tempo)==false){
			//printf("HI\n");
			dir_close(dir);
			return NULL;
		}
		if(inode_is_dir(tempo)==false){
			//printf("??");
			dir_close(dir);
			return NULL;
		}
		//DONE
		dir_close(dir);
		//NEXT PART
		dir = dir_open (tempo);
		//printf("H:%d\n",dir==NULL);
		token = next_token;
		next_token = strtok_r (NULL, "/", &save_ptr);
	}
	//printf("check:%s\n", token);
	strlcpy (file_name, token, NAME_MAX);
	//printf("Please%d", inode_get_inumber(dir_get_inode(dir)));
	return dir;
}

bool filesys_create_dir(const char *name){
	cluster_t clst = fat_create_chain (0);
	disk_sector_t inode_sector = cluster_to_sector(clst);
	//printf("is:%d", inode_sector);
	char tmp_name[PATH_MAX +1];
	//printf("hart\n");
	struct dir *dir = parse_path(name, tmp_name);
	//printf("hart%d\n",inode_get_inumber(dir_get_inode(dir)));
	bool success = (dir != NULL
			&& clst
			&& dir_create (inode_sector, 16)
			&& dir_add (dir, tmp_name, inode_sector));
	if (!success && inode_sector != 0)
		fat_put(clst, 0);

	if(success)
	{
		struct dir *created_dir = dir_open(inode_open(inode_sector));
		dir_add(created_dir, ".", inode_sector);
		struct inode * tmp = dir_get_inode(dir);
		dir_add(created_dir, "..", inode_get_inumber(tmp));
		dir_close(created_dir);
	}
	
	//printf("Pleas");
	dir_close(dir);
	//printf("cd:%d", &thread_current()->cur_dir->inode == )
	return success;
}
