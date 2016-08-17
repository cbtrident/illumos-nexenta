/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "nfsgen.h"

int64_t io_buff_size = 32 * 1024; /* default to 32KB */
int64_t io_buff_num = 1024;
int64_t io_hold_num = -1;	/* default to no wait */
int64_t io_init_offset = 0;
int64_t io_loop_count = 1;
int64_t lock_init_offset = 0;
int64_t lock_range = 0;
int64_t maxTruncSize = 0;
short lock_type;
int is_read = 0;
int is_write = 0;
int is_lock = 0;
int is_blockinglock = 0;
int is_unlock = 0;
int is_closefile = 0;
int is_truncate = 0;
int is_returndel = 0;
int open_flag = O_RDONLY;
int signaled = 0;
mode_t open_mode = 0664;
unsigned int write_seed = 777;
unsigned int read_seed = 777;
unsigned int sleep_sec = 0;
char *file_name = NULL;

void
fileOperatorDump()
{
	dprint("io_buff_size: %lld\n", io_buff_size);
	dprint("io_buff_num: %lld\n", io_buff_num);
	dprint("io_hold_num: %lld\n", io_hold_num);
	dprint("io_init_offset: %lld\n", io_init_offset);
	dprint("io_loop_count: %lld\n", io_loop_count);
	dprint("lock_init_offset: %lld\n", lock_init_offset);
	dprint("lock_range: %lld\n", lock_range);
	dprint("lock_type: %d\n", lock_type);
	dprint("is_read: %d\n", is_read);
	dprint("is_write: %d\n", is_write);
	dprint("is_lock: %d\n", is_lock);
	dprint("is_unlock: %d\n", is_unlock);
	dprint("is_closefile: %d\n", is_closefile);
	dprint("is_truncate: %d\n", is_truncate);
	dprint("maxTruncSize: %lld\n", maxTruncSize);
	dprint("open_flag: %d\n", open_flag);
	dprint("open_mode: %d\n", open_mode);
	dprint("write_seed: %d\n", write_seed);
	dprint("read_seed: %d\n", read_seed);
	dprint("sleep_sec: %d\n", sleep_sec);
	dprint("debug: %d\n", debug);
	dprint("showerror: %d\n", showerror);
	dprint("file_name: %s\n", file_name);
	dprint("-----------------------------------------\n\n");
}


/*
 * signal(SIGUSR1) handler
 */
void
handler(int signo)
{
	dprint("got signal #%d\n", signo);
	signaled = 1;
}

/*
 * fill the buffer with random data
 * arguments:
 *      $1 : buffer used to contain data
 *      $2 : buffer size
 *      $3 : seed used to generate random data
 */
void
genBuffer(unsigned char *buff, int64_t size, unsigned int *write_seed)
{
	int64_t index = 0;
	for (index = 0; index < size; index ++) {
		buff[index] = (unsigned char)(rand_r(write_seed) % 256);
	}
}


/*
 * check data in buffer is correct or not
 * arguments:
 *	$1 : data buffer
 *	$2 : buffer size
 * return value:
 *	On sucess, return 0
 *	On error, return 1
 */
int
checkBuffer(unsigned char *buff, int64_t buff_size)
{
	int index = 0;
	int ret = 0;
	unsigned char tmp;

	dprint("Started to check buffer data ... \n");
	for (index = 0; index < buff_size; index++) {
		tmp = (unsigned char) (rand_r(&read_seed) % 256);
		if (buff[index] != tmp) {
			eprint("check buff failed at %d, expect: %c, \
			    real: %c \n", index, buff[index], tmp);
			ret = 1;
			break;
		}
	}

	return (ret);
}

/*
 * lock or unlock file with exclusive lock
 * arguments:
 *      $1 : file descriptor
 *      $2 : indicates lock or unlock
 * return value:
 *      On sucess, return 0
 *      On error, return 1
 */
int
lockUnlockFile(int fd, int is_lock, short l_type, off64_t l_start, \
    off64_t l_len)
{
	int ret = 0;
	struct flock lock_stat;

	lock_stat.l_whence = SEEK_SET;
	lock_stat.l_start = l_start;
	lock_stat.l_len = l_len;

	if (is_lock == 1) {
		dprint("Started to lock file ...\n");
		lock_stat.l_type = l_type;
		if (fcntl(fd, (is_blockinglock == 1) ? F_SETLKW : F_SETLK, \
		    &lock_stat) < 0) {
			eprint("failed to set lock(unavailable) on file: \
			    %s, %s\n", file_name, strerror(errno));
			ret = 1;
		} else {
			print("got %s lock; sleeping...\n", \
			    (is_write == 1) ? "exclusive" : "shared");

			sleep(sleep_sec);
		}
	} else {
		dprint("Started to unlock file ...\n");
		lock_stat.l_type = F_UNLCK;
		if (fcntl(fd, F_SETLKW, &lock_stat) < 0) {
			eprint("failed to unlock file, %s, \
			    %s\n", file_name, strerror(errno));
			ret = 1;
		}
	}

	return (ret);
}


/*
 * file operator main function to handle file IO
 */
int
mainFunc()
{
	int ret = 0;
	int fd = 0;
	int i = 0;
	unsigned char *buff = NULL;
	int64_t gotBytes = 0;
	off64_t truncOffset = 0;

	dprint("Started mainFunc() ...\n");

	/* register signal handler */
	signal(SIGUSR1, handler);

	/* open file */
	if ((fd = open(file_name, open_flag, open_mode)) < 0) {
		eprint("failed to open file: %s, %s\n", file_name, \
		    strerror(errno));
		ret = 1;
		return (ret);
	}

	/* lock file */
	if (is_lock == 1) {
		if ((ret = lockUnlockFile(fd, 1, lock_type, lock_init_offset, \
		    lock_range)) < 0) {
			eprint("failed to lock file: %s, %s\n", file_name, \
			    strerror(errno));
			ret = 1;
			close(fd);
			return (ret);
		}
	}

	/* generate data  buffer */
	if ((buff = (unsigned char *)malloc(io_buff_size)) == NULL) {
		eprint("failed to mallock %d size memory buff, %s\n", \
		    io_buff_size, strerror(errno));
		close(fd);
		ret = 1;
		return (ret);
	}

	while (io_loop_count > 0) {
		if (is_truncate == 1) {
			io_init_offset = (off64_t)rand_r(&write_seed) \
			    % maxTruncSize;
		}

		/* lseek to init offset */
		if (lseek64(fd, io_init_offset, SEEK_SET) != io_init_offset) {
			eprint("failed to lseek to :%d\n", io_init_offset);
			ret = 1;
			break;
		}

		/* file IO untill the waitnumber */
		dprint("Started to IO file till io_hold_num ...\n");
		for (i = 0; i < io_hold_num; i++) {
			if (is_write == 1) {
				genBuffer(buff, io_buff_size, &write_seed);
				if (nfsgenWrite(fd, buff, io_buff_size) != \
				    io_buff_size) {
					eprint("failed to write data:%d, %s\n",\
					    errno, strerror(errno));
					ret = 1;
					break;
				} else {
					/*
					 * read back for check
					 * if is_trucate set
					 */
					if (is_truncate == 1) {
						if (lseek64(fd, \
						    io_init_offset, \
						    SEEK_SET) != \
						    io_init_offset) {
							eprint("failed to \
							    lseek to :%d\n", \
							    io_init_offset);
							ret = 1;
							break;
						}
						if ((gotBytes = nfsgenRead(fd, \
						    buff, io_buff_size)) != \
						    io_buff_size) {
							eprint("failed to read \
							    data, exp: %d, \
							    real: %d \n", \
							    gotBytes, \
							    io_buff_size);
							ret = 1;
							break;
						}
						if (checkBuffer(buff, \
						    io_buff_size) \
						    != 0) {
							ret = 1;
							break;
						}
					}
				}
			} else {
				if ((gotBytes = nfsgenRead(fd, buff, \
				    io_buff_size)) != io_buff_size) {
					eprint("failed to read data, exp: %d, \
					    real: %d \n", gotBytes, \
					    io_buff_size);
					ret = 1;
					break;
				}
			}
		}

		if (ret != 0) {
			break;
		}

		/* okay, truncate file */
		if (is_truncate == 1) {
			dprint("Started to truncate file ...\n");
			if (ftruncate64(fd, (off64_t)rand_r(&write_seed) % \
			    maxTruncSize < 0)) {
				eprint("failed to truncate file to a random \
				    size, %s", strerror(errno));
				ret = 1;
				break;
			}
		}

		/* okay, I'm here, signal outside, I'm ready */
		if (io_hold_num >= 0) {
			print("I am ready, I_am_ready\n");
		}

		/* go to sleep, wait instruction from user */
		if (io_hold_num >= 0) {
			dprint("Started to wait the user signal comes from \
			    outsider ...\n");
			while (signaled == 0) {
				yield();
			}
		}

		if (signaled == 1) {
			/* read back data for check */
			print("signalled, read back data for check\n");
			if (lseek(fd, io_init_offset, SEEK_SET) != \
			    io_init_offset) {
				eprint("failed to lseek to :%d\n", \
				    io_init_offset);
				ret = 1;
				break;
			}

			/* read data */
			for (i = 0; i < io_hold_num; i++) {
				if ((gotBytes = nfsgenRead(fd, buff, \
				    io_buff_size)) != io_buff_size) {
					eprint("failed to read data, \
					    exp: %d, real: %d \n", \
					    gotBytes, io_buff_size);
					ret = 1;
					break;
				} else {
					if ((ret = checkBuffer(buff, \
					    io_buff_size)) != 0) {
						ret = 1;
						break;
					}
				}
			} /* end of for */
			if (ret != 0) {
				break;
			}
		}

		/* continue IO untill the waitnumber */
		dprint("Started to finish the remaining IO ...\n");
		for (; i < io_buff_num; i++) {
			if (is_write == 1) {
				genBuffer(buff, io_buff_size, &write_seed);
				if (nfsgenWrite(fd, buff, io_buff_size) \
				    != io_buff_size) {
					eprint("failed to write data: \
					    %d, %s\n", errno, \
					    strerror(errno));
					ret = 1;
					break;
				}
			} else {
				if ((gotBytes = nfsgenRead(fd, buff, \
				    io_buff_size)) != io_buff_size) {
					eprint("failed to read data, expect \
					    %d, real got %d \n", \
					    gotBytes, io_buff_size);
					ret = 1;
					break;
				}
			}
		} /* end of for */

		if (ret != 0) {
			break;
		}

		io_loop_count --;
	} /* end of while */

	/* unlock file */
	if ((ret == 0) && (is_unlock == 1)) {
		if ((ret = lockUnlockFile(fd, 0, lock_type, lock_init_offset, \
		    lock_range)) < 0) {
			eprint("failed to lock file: %s, %s\n", file_name, \
			    strerror(errno));
			ret = 1;
		}
	}

	/* return delegation type */
	if ((ret == 0) && (is_returndel == 1)) {
		i = get_deleg(fd, file_name);
		print("return_delegation_type=%d\n", i);
	}

	/* close file */
	if (is_closefile == 1) {
		if (close(fd) < 0) {
			eprint("failed to close file: %s, %s\n", file_name, \
			    strerror(errno));
			ret = errno;
		}
	}

	/* free data buff */
	free(buff);


	return (ret);
}


void
usage(char *cmd)
{
	printf("%s [options] filename\n", cmd);
	printf("options:\n");
	printf("\t -o open_flag     specify file open flag \n");
	printf("\t                  0: O_RDONLY \n");
	printf("\t                  1: O_WRONLY|O_CREAT \n");
	printf("\t                  2: O_WRONLY|O_APPEND \n");
	printf("\t                  3: O_WRONLY|O_TRUNC \n");
	printf("\t                  4: O_RDWR|O_CREAT \n");
	printf("\t                  5: O_RDWR|O_APPEND \n");
	printf("\t                  6: O_RDWR|O_TRUNC \n");
	printf("\t -m open_mode     specify file open mode, \n");
	printf("\t                  default to 0664 \n");
	printf("\t -L lock_type is_blocking offset range \n");
	printf("\t                  lock_type to 0 is read-lock, \n");
	printf("\t                  1 is write-lock \n");
	printf("\t -B buff_size buff_number hold_number \n");
	printf("\t                  specify buffer size, buffer number \n");
	printf("\t                  and where IO should be held and wait \n");
	printf("\t                  signal comes from outside user \n");
	printf("\t -e seed          specify seed to generate \n");
	printf("\t                  random data \n");
	printf("\t -s sleep_seconds specify sleep seconds \n");
	printf("\t -i offset        specify IO initial offset \n");
	printf("\t -l count         specify loop count \n");
	printf("\t -t maxTruncSize  specify max random truancate size in \n");
	printf("\t                  each loop iteration, but user cannot \n");
	printf("\t                  specify -t along with hold_number >= 0 \n");
	printf("\t                  in -B option \n");
	printf("\t -R               read data from file \n");
	printf("\t -W               write data into file \n");
	printf("\t -c               close file at end \n");
	printf("\t -d               return delegation type as return code \n");
	printf("\t                  at end \n");
	printf("\t -u               unlock file at end \n");
	printf("\t -D               trun on debug infomation \n");
	printf("\t -h               show this help information \n");
}

char
*removePrefixBlank(char *src)
{
	char *ret = src;
	while (*ret == ' ') {
		ret ++; }

	return (ret);
}

int
main(int argc, char *argv[])
{
	int c = 0;
	int ret = 0;
	int tmp = 0;
	char *poptarg = NULL;
	char *envBuff = NULL;

	if (argc < 2) {
		usage(argv[0]);
		return (1);
	}
	while ((c = getopt(argc, argv, "o:m:L:B:e:s:i:l:t:RWcduDh")) != -1) {
		switch (c) {
			case 'o':
				tmp = strtol(optarg, NULL, 0);
				switch (tmp) {
					case 0:
						open_flag = O_RDONLY;
						break;
					case 1:
						open_flag = O_WRONLY|O_CREAT;
						break;
					case 2:
						open_flag = \
						    O_WRONLY|O_APPEND|O_CREAT;
						break;
					case 3:
						open_flag = \
						    O_WRONLY|O_TRUNC|O_CREAT;
						break;
					case 4:
						open_flag = \
						    O_RDWR|O_CREAT|O_CREAT;
						break;
					case 5:
						open_flag = \
						    O_RDWR|O_APPEND|O_CREAT;
						break;
					case 6:
						open_flag = \
						    O_RDWR|O_TRUNC|O_CREAT;
						break;
					case 7:
						open_flag = O_WRONLY;
						break;
					default:
						print("Invalid open flag \
						    parameter\n");
						usage(argv[0]);
						return (1);
				}
				break;
			case 'm':
				open_mode = (mode_t)strtol(optarg, NULL, 0);
				break;
			case 'L':
				is_lock = 1;
				poptarg = (char *)optarg;
				tmp = strtol(optarg, NULL, 0);
				poptarg = \
				    strstr(removePrefixBlank(poptarg), " ");
				is_blockinglock = strtol(poptarg, NULL, 0);
				poptarg = \
				    strstr(removePrefixBlank(poptarg), " ");
				lock_init_offset = \
				    (off64_t)strtol(poptarg, NULL, 0);
				poptarg = \
				    strstr(removePrefixBlank(poptarg), " ");
				lock_range = (off64_t)strtol(poptarg, NULL, 0);
				switch (tmp) {
					case 0:
						lock_type = F_RDLCK;
						break;
					case 1:
						lock_type = F_WRLCK;
						break;
					default:
						print("Invalid lock \
						    parameter\n");
						usage(argv[0]);
						return (1);
				}
				break;
			case 'B':
				poptarg = (char *)optarg;
				io_buff_size = \
				    (int64_t)strtol(poptarg, NULL, 0);
				poptarg = \
				    strstr(removePrefixBlank(poptarg), " ");
				io_buff_num = (int64_t)strtol(poptarg, NULL, 0);
				poptarg = \
				    strstr(removePrefixBlank(poptarg), " ");
				io_hold_num = (int64_t)strtol(poptarg, NULL, 0);
				break;
			case 'e':
				write_seed = (unsigned int)strtol(optarg, \
				    NULL, 0);
				read_seed = write_seed;
				break;
			case 's':
				sleep_sec = (unsigned int)strtol(optarg, \
				    NULL, 0);
				break;
			case 'i':
				io_init_offset = (int64_t)strtol(optarg, \
				    NULL, 0);
				break;
			case 'l':
				io_loop_count = (int64_t)strtol(optarg, \
				    NULL, 0);
				break;
			case 't':
				is_truncate = 1;
				maxTruncSize = (int64_t)strtol(optarg, NULL, 0);
				break;
			case 'R':
				is_read = 1;
				break;
			case 'W':
				is_write = 1;
				break;
			case 'c':
				is_closefile = 1;
				break;
			case 'd':
				is_returndel = 1;
				break;
			case 'u':
				is_unlock = 1;
				break;
			case 'D':
				debug = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			default:
				usage(argv[0]);
				return (1);
		}
	}

	/* get filename */
	file_name = argv[optind];
	if (file_name == NULL) {
		print("no file_name specified\n");
		usage(argv[0]);
		return (1);
	}

	/* check for read and write */
	if (((is_read == 1) && (is_write == 1)) || \
	    ((is_read == 0) && (is_write == 0))) {
		print("User need to speicfy at least one of -R and -W option, \
		    -R and -W are exclusive options\n");
		usage(argv[0]);
		return (1);
	}

	/* check -t and hold_number in -B option */
	if ((is_truncate == 1) && (io_hold_num >= 0)) {
		print("Limitation: user cannot specify -t and hold_num \
		    large than -1 at the same time \n");
		usage(argv[0]);
		return (1);
	}

	/* check FILE_OPERATOR_DEBUG in case of user didn't specify -D option */
	if (debug == 0) {
		if ((envBuff = getenv("FILE_OPERATOR_DEBUG")) != NULL) {
			if (strcasecmp(envBuff, "ON") == 0) {
				debug = 1;
			}
		}
	}

	/*
	 * file_operator default to print out error info unless user
	 * specified env SHOWERROR=OFF
	 */
	showerror = 1;
	if ((envBuff = getenv("SHOWERROR")) != NULL) {
		if (strcasecmp(envBuff, "OFF") == 0) {
			showerror = 0;
		}
	}


	fileOperatorDump();

	/* okay, go to the mainFunc */
	if ((ret = mainFunc()) == 0) {
		print("completed successfully!\n");
	}

	return (ret);
}
