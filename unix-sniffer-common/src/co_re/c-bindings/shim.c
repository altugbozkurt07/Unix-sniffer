#include "c-types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define UPID_LEN  1
#define SUNPATH_LEN 107
#define SHIM(struc, memb)                                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)
	
#define _SHIM_GETTER_BPF_CORE_READ_USER(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return BPF_CORE_READ_USER(struc, memb);                  \
	}

#define _SHIM_GETTER(ret, proto, accessed_member)                \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return __builtin_preserve_access_index(accessed_member); \
	}

#define _SHIM_GETTER_BPF_CORE_READ(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                \
	{                                                       \
		return BPF_CORE_READ(struc, memb);                  \
	}

#define _FIELD_EXISTS_DEF(_struct, memb, memb_name)                                                       \
	__attribute__((always_inline)) _Bool shim_##_struct##_##memb_name##_##exists(struct _struct *_struct) \
	{                                                                                                     \
		return bpf_core_field_exists(_struct->memb);                                                      \
	}

#define SHIM_REF(struc, memb)                                                                                             \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb(struct struc *struc), &(struc->memb))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb)) \
	_FIELD_EXISTS_DEF(struc, memb, memb)


#define ARRAY_SHIM(struc, memb)                                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM_WITH_NAME(struc, memb, memb_name)                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_ENUM_VALUE(enum_type, enum_value)                                      \
__attribute__((always_inline)) unsigned int shim_##enum_type##_##enum_value()   \
{                                                                               \
	return bpf_core_enum_value(enum enum_type, enum_value);                     \
}                                                                               \
__attribute__((always_inline)) _Bool shim_##enum_type##_##enum_value##_exists() \
{                                                                               \
	return bpf_core_enum_value_exists(enum enum_type, enum_value);              \
}

enum iter_type
{
	/* iter types */
	ITER_IOVEC,
	ITER_KVEC,
	ITER_BVEC,
	ITER_PIPE,
	ITER_XARRAY,
	ITER_DISCARD,
	ITER_UBUF,
};

SHIM_ENUM_VALUE(iter_type, ITER_IOVEC);
SHIM_ENUM_VALUE(iter_type, ITER_KVEC);
SHIM_ENUM_VALUE(iter_type, ITER_BVEC);
SHIM_ENUM_VALUE(iter_type, ITER_PIPE);
SHIM_ENUM_VALUE(iter_type, ITER_XARRAY);
SHIM_ENUM_VALUE(iter_type, ITER_DISCARD);
SHIM_ENUM_VALUE(iter_type, ITER_UBUF);


struct iov_iter
{
	union
	{
		u8 iter_type;
		unsigned int type;
	};
	size_t count;
	union
	{
		struct iovec *iov;
		struct iovec *__iov;
		void *ubuf;
		struct bio_vec *bvec;
	};

	union
	{
		unsigned long nr_segs;
	};
} __attribute__((preserve_access_index));


SHIM(iov_iter, iter_type);
SHIM(iov_iter, type);
SHIM(iov_iter, count);
SHIM(iov_iter, nr_segs);
SHIM(iov_iter, ubuf);
SHIM(iov_iter, iov);
SHIM(iov_iter, __iov);
SHIM(iov_iter, bvec);

struct iovec
{
	void *iov_base;
	__kernel_size_t iov_len;
} __attribute__((preserve_access_index));


SHIM(iovec, iov_base);
SHIM(iovec, iov_len);

struct cmsghdr{
	
	size_t cmsg_len;    
    int    cmsg_level;  
    int    cmsg_type;  
}__attribute__((preserve_access_index));

SHIM(cmsghdr, cmsg_len);
SHIM(cmsghdr, cmsg_level);
SHIM(cmsghdr, cmsg_type);


struct msghdr
{
	struct iov_iter msg_iter;
	__kernel_size_t msg_controllen;
	void *msg_control;
}__attribute__((preserve_access_index));

SHIM_REF(msghdr, msg_iter);
SHIM(msghdr, msg_control);
SHIM(msghdr, msg_controllen);

struct sock_common
{
	unsigned short skc_family;

}__attribute__((preserve_access_index));

SHIM(sock_common, skc_family);


struct upid
{
	__s32 nr;
}__attribute__((preserve_access_index));

SHIM(upid, nr);

struct pid
{
	struct upid numbers[UPID_LEN];

}__attribute__((preserve_access_index));

ARRAY_SHIM(pid, numbers);


struct sock
{
	struct sock_common __sk_common;
	struct pid *sk_peer_pid;
}__attribute__((preserve_access_index));

SHIM_REF(sock, __sk_common);
SHIM(sock, sk_peer_pid);


struct socket
{
	struct sock *sk;
}__attribute__((preserve_access_index));

SHIM(socket, sk);

struct sockaddr_un
{
	char sun_path[SUNPATH_LEN + 1];

}__attribute__((preserve_access_index));

ARRAY_SHIM(sockaddr_un, sun_path);

struct unix_address
{
	__s32 len;
	struct sockaddr_un name[];
}__attribute__((preserve_access_index));

SHIM(unix_address, len);
SHIM_REF(unix_address, name);

struct inode
{
	unsigned long i_ino;

}__attribute__((preserve_access_index));

SHIM(inode, i_ino);

struct dentry
{
	struct inode *d_inode;

}__attribute__((preserve_access_index));

SHIM(dentry, d_inode);

struct path
{
	struct dentry *dentry;

}__attribute__((preserve_access_index));

SHIM(path, dentry);


struct unix_sock
{
	struct sock *peer;
	struct unix_address *addr;
	struct path path;

}__attribute__((preserve_access_index));

SHIM(unix_sock, peer);
SHIM(unix_sock, addr);
SHIM_REF(unix_sock, path);


struct file
{
	struct inode *f_inode;
	struct path f_path;
	void *private_data;
} __attribute__((preserve_access_index));

SHIM_REF(file, f_path);
SHIM(file, f_inode);
SHIM(file, private_data);

struct fdtable
{
	unsigned int max_fds;
	struct file **fd;
}__attribute__((preserve_access_index));

SHIM(fdtable, max_fds);
SHIM(fdtable, fd);

struct files_struct
{
	struct fdtable *fdt;
	struct file *fd_array[1];
}__attribute__((preserve_access_index));

SHIM(files_struct, fdt);
SHIM_REF(files_struct, fd_array);

struct task_struct
{
	struct files_struct *files;
}__attribute__((preserve_access_index));

SHIM(task_struct, files);


struct ucred {
	__u32	pid;
	__u32	uid;
	__u32	gid;
}__attribute__((preserve_access_index));

SHIM(ucred, pid);
SHIM(ucred, uid);
SHIM(ucred, gid);