/*
 * info.c
 *
 * Copyright (C) 2006  Insigme Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * project (http://www.longene.org) in the Insigma Research Institute,  
 * which is a subdivision of Insigma Co., Ltd (http://www.insigma.com.cn).
 * 
 * The project is sponsored by Insigma Co., Ltd.
 *
 * The authors can be reached at linux@insigma.com.cn.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of  the GNU General  Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Revision History:
 *   Dec 2008 - Created.
 */

/* 
 * info.c:
 * Refered to Wine code
 */

#include <asm/poll.h>
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

static unsigned int dummyfile_poll(struct file *f, struct poll_table_struct *p)
{
	if (current_thread->wake_up) {
		current_thread->wake_up = 0;
		ktrace("ret %d\n", current_thread->wake_up);
		return POLLIN;
	} else {
		ktrace("ret 0\n");
		return 0;
	}
}

/* dummy file used in NtWaitforMultipleObjects() */
const struct file_operations dummy_fops = {
	.owner      = THIS_MODULE,
	.poll       = dummyfile_poll,
};

static struct file dummyfile_dft = {
	.f_op       = &dummy_fops,
};

static struct file *dummyfile = &dummyfile_dft;

void open_dummy_file(void)
{
	struct file *filp;

	filp = filp_open("/proc/unifiedkernel/io/dummy", O_RDWR, 0);
	if (!IS_ERR(filp)) {
		dummyfile = filp;
		ktrace("dummy file opened\n");
	}
}

void close_dummy_file(void)
{
	if (dummyfile != &dummyfile_dft)
		filp_close(dummyfile, NULL);
}

void create_dummy_file(struct w32process *process)
{
	int fd;

	if (process->dummyfd != -1)
		return;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd >= 0) {
		get_file(dummyfile);
		fd_install(fd, dummyfile);
    	process->dummyfd = fd;
	}

	ktrace("process %p, dummyfd %d\n", process, process->dummyfd);
}
#endif /* CONFIG_UNIFIED_KERNEL */
