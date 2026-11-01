#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>  
#include <linux/uaccess.h> 
#include <linux/errno.h>   
#include <linux/seq_file.h>
#include <linux/fs.h>  
#include <linux/rcupdate.h>

/* Netfilter Hook 設定 */
static struct nf_hook_ops firewall_ops;

/* 封鎖 IP 節點, 每個節點代表一筆封鎖規則 */
struct blocked_ip_entry {
    __be32 addr;              /* IPv4 位址 */
    struct list_head list; 
    struct rcu_head rcu;
};

/* 封鎖 IP 清單 */
static LIST_HEAD(blocked_ip_list);

/* proc entry */
static struct proc_dir_entry *firewall_proc;

static ssize_t firewall_write(
    struct file *file,
    const char __user *user_buf,
    size_t count,
    loff_t *ppos
);

/* =========================================================
 * 同步機制
 *
 * 保護 blocked_ip_list。
 *
 * Hook 可能在 Softirq 等不可睡眠的上下文執行，
 * 因此使用 spinlock_bh() 保護清單。
 * ========================================================= */
static DEFINE_SPINLOCK(blocked_ip_lock);

/* 封包計數器 */
static atomic_t packet_count = ATOMIC_INIT(0);

static int add_blocked_ip(__be32 addr)
{
    struct blocked_ip_entry *entry;
    struct blocked_ip_entry *new_entry;

    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry)
        return -ENOMEM;

    new_entry->addr = addr;
    INIT_LIST_HEAD(&new_entry->list);

    spin_lock_bh(&blocked_ip_lock);

    list_for_each_entry(entry, &blocked_ip_list, list) {
        if (entry->addr == addr) {
            spin_unlock_bh(&blocked_ip_lock);
            kfree(new_entry);
            return -EEXIST;
        }
    }

    list_add_tail_rcu(&new_entry->list, &blocked_ip_list);

    spin_unlock_bh(&blocked_ip_lock);

    pr_info("Firewall: added blocked IP %pI4\n", &addr);

    return 0;
}

static int remove_blocked_ip(__be32 addr)
{
    struct blocked_ip_entry *entry;
    struct blocked_ip_entry *found = NULL;

    spin_lock_bh(&blocked_ip_lock);

    list_for_each_entry(entry, &blocked_ip_list, list) {
        if (entry->addr == addr) {
            list_del_rcu(&entry->list);
            found = entry;
            break;
        }
    }

    spin_unlock_bh(&blocked_ip_lock);

    if (!found)
        return -ENOENT;

    kfree_rcu(found, rcu);

    pr_info("Firewall: removed blocked IP %pI4\n", &addr);

    return 0;
}

static ssize_t firewall_write(
    struct file *file,
    const char __user *user_buf,
    size_t count,
    loff_t *ppos)
{
    char kbuf[32];
    char *ip_str;

    __be32 addr;

    int ret;

    /* 檢查輸入長度 */
    if (count == 0 || count >= sizeof(kbuf)) {
        return -EINVAL;
    }

    /* 從 User Space 複製資料 */
    if (copy_from_user(kbuf, user_buf, count)) {
        return -EFAULT;
    }

    /* 加上字串結尾 */
    kbuf[count] = '\0';

    /* 移除前後空白與換行 */
    ip_str = strim(kbuf);

    /* 檢查指令格式 */
    if (ip_str[0] != '+' && ip_str[0] != '-') {
        pr_err("Firewall: invalid command\n");
        return -EINVAL;
    }

    /* 解析 IPv4 位址 */
    if (!in4_pton(
            ip_str + 1,
            -1,
            (u8 *)&addr,
            -1,
            NULL)) {

        pr_err("Firewall: invalid IPv4 address\n");

        return -EINVAL;
    }

    /* 根據第一個字元決定操作 */
    if (ip_str[0] == '+') {
        ret = add_blocked_ip(addr);
        if (ret == -EEXIST) {
            pr_info("Firewall: IP already exists\n");
        }
    } else {
        ret = remove_blocked_ip(addr);
        if (ret == -ENOENT) {
            pr_info("Firewall: IP does not exist\n");
        }
    }  

    if (ret < 0) {
        return ret;
    }

    return count;
}

static int firewall_show(struct seq_file *m, void *v)
{
    int ret;

    struct blocked_ip_entry *entry;

    /* 取得一個核心緩衝區 */
    char *buf;

    size_t len = 0;

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

    if (!buf) {
        return -ENOMEM;
    }

    /* 鎖住封鎖 IP 清單 */
    spin_lock_bh(&blocked_ip_lock);

    /* 遍歷整個 Linked List */
    list_for_each_entry(entry, &blocked_ip_list, list) {
        /* 確認緩衝區還有足夠空間，IP 需要 16 bytes */  
        if (PAGE_SIZE - len < 17) {
            spin_unlock_bh(&blocked_ip_lock);
            kfree(buf);
            return -ENOSPC;
        }

        /* 將 IPv4 位址轉成字串 */
        len += scnprintf(
            buf + len, 
            PAGE_SIZE - len, 
            "%pI4\n", 
            &entry->addr
        );
    }

    spin_unlock_bh(&blocked_ip_lock);

    /* 將整理好的資料輸出到 seq_file */
    ret = seq_write(m, buf, len);
    kfree(buf);

    return ret;
}

static int firewall_open(struct inode *inode, struct file *file)
{
    return single_open(file, firewall_show, NULL);
}

static const struct proc_ops firewall_proc_ops = {
    .proc_open    = firewall_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = firewall_write,  
};

/* =========================================================
 * Netfilter Hook
 *
 * 1. 檢查 IPv4 標頭是否完整。
 * 2. 取得封包來源 IP。
 * 3. 查詢來源 IP 是否存在於封鎖清單。
 * 4. 如果命中，回傳 NF_DROP。
 * 5. 否則回傳 NF_ACCEPT。
 * ========================================================= */
static unsigned int firewall_hook(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct blocked_ip_entry *entry;

    __be32 src_addr;

    bool blocked = false;

    int count;

    /* -----------------------------------------------------
     * 1. 確保 skb 中至少有完整的 IPv4 固定標頭
     * ----------------------------------------------------- */
    if (!pskb_may_pull(
            skb,
            skb_network_offset(skb) + sizeof(struct iphdr))) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    /* -----------------------------------------------------
     * 2. 檢查 IPv4 標頭長度
     *
     * ihl 的單位是 32-bit word。
     * 最小值為 5，也就是 20 bytes。
     * ----------------------------------------------------- */
    if (iph->ihl < 5) {
        return NF_ACCEPT;
    }

    /* -----------------------------------------------------
     * 3. 確保完整的 IPv4 標頭已經載入
     *
     * IPv4 標頭可能包含 options。
     * ----------------------------------------------------- */
    if (!pskb_may_pull(skb, skb_network_offset(skb) + iph->ihl * 4)) {
        return NF_ACCEPT;
    }

    /* pskb_may_pull 可能移動封包資料，重新取得標頭指標 */
    iph = ip_hdr(skb);

    /* -----------------------------------------------------
     * 4. 取得來源 IP
     *
     * 先將來源 IP 複製到區域變數，
     * 避免後續使用封包標頭指標。
     * ----------------------------------------------------- */
    src_addr = iph->saddr;

    /* -----------------------------------------------------
     * 5. 更新封包計數器
     * ----------------------------------------------------- */
    count = atomic_inc_return(&packet_count);

    /* -----------------------------------------------------
     * 6. 查詢封鎖 IP 清單
     *
     * 使用 RCU 保護讀取流程。
     * 新增與刪除操作則使用 spinlock 序列化 Writer。
     * ----------------------------------------------------- */
    rcu_read_lock();
    list_for_each_entry_rcu(entry, &blocked_ip_list, list) {
        if (entry->addr == src_addr) {
            blocked = true;
            break;
        }
    }  
    rcu_read_unlock();

    /* -----------------------------------------------------
     * 7. 根據查詢結果決定封包處理方式
     *
     * 日誌放在鎖外，避免持有 spinlock 時執行輸出。
     * ----------------------------------------------------- */
    if (blocked) {
        pr_info("Firewall: DROP packet from %pI4\n", &src_addr);
        return NF_DROP;
    }

    /* -----------------------------------------------------
     * 8. 輸出前 10 個未命中封鎖清單的封包資訊
     * ----------------------------------------------------- */
    if (count <= 10) {
        pr_info(
            "Firewall: ACCEPT src=%pI4 dst=%pI4 protocol=%u\n",
            &iph->saddr,
            &iph->daddr,
            iph->protocol
        );
    }

    return NF_ACCEPT;
}

static int __init firewall_init(void)
{
    int ret;

    /* 設定 Netfilter Hook  */
    firewall_ops.hook = firewall_hook;
    firewall_ops.pf = NFPROTO_IPV4;
    firewall_ops.hooknum = NF_INET_LOCAL_IN;
    firewall_ops.priority = NF_IP_PRI_FIRST;

    /* 註冊 Netfilter Hook */
    ret = nf_register_net_hook(&init_net, &firewall_ops);

    if (ret < 0) {
        pr_err("Firewall: failed to register hook: %d\n", ret);
        return ret;
    }

    pr_info("Firewall: Netfilter hook registered\n");

    /* 建立 /proc/firewall */
    firewall_proc = proc_create(
        "firewall", 0600, NULL, &firewall_proc_ops
    );

    if (!firewall_proc) {
        pr_err("Firewall: failed to create /proc/firewall\n");

        /* 建立 proc 失敗，取消 Hook 註冊 */
        nf_unregister_net_hook(&init_net, &firewall_ops);

        return -ENOMEM;
    }

    pr_info("Firewall: /proc/firewall created\n");

    return 0;
}

static void __exit firewall_exit(void)
{
    struct blocked_ip_entry *entry;
    struct blocked_ip_entry *tmp;

    proc_remove(firewall_proc);
    nf_unregister_net_hook(&init_net, &firewall_ops);

    /* Ensure existing RCU readers have finished */
    synchronize_rcu();

    spin_lock_bh(&blocked_ip_lock);
    list_for_each_entry_safe(entry, tmp, &blocked_ip_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_bh(&blocked_ip_lock);  

    pr_info("Firewall: module unloaded\n");
}
  
module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChengChaoChun");
MODULE_DESCRIPTION("A Linux Netfilter firewall module");