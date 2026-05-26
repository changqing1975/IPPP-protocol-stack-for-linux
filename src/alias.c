#include "ipppk.h"

void map_init(struct alias_map *m) {
    hash_init(m->table);
    spin_lock_init(&m->lock);
    m->count = 0;
}

/**
* 返回值：0成功，-ENOMEM内存不足
*/
int map_add(struct alias_map *m, char *key, uint32_t len, __be32 value) {
    struct map_entry *e;
    uint32_t h = map_hash(key, len);
    int ret = 0;

    // 检查参数合法性
    if (!m || !key || len == 0 || strlen(key) == 0)
        return -EINVAL;

    spin_lock(&m->lock);
    // 查找是否已存在
    hash_for_each_possible(m->table, e, node, h) {
        if (e->key_len == len && !memcmp(e->key, key, len)) {
            e->value = value; // 更新值
            spin_unlock(&m->lock);
            return 0;
        }
    }

    // 新建节点
    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        spin_unlock(&m->lock);
        return -ENOMEM;
    }
    e->key = kmalloc(len + 1, GFP_KERNEL);
    if (!e->key) {
        kfree(e);
        spin_unlock(&m->lock);
        return -ENOMEM;
    }
    memcpy(e->key, key, len);
    e->key[len] = '\0';
    e->key_len = len;
    e->value = value;
    hash_add(m->table, &e->node, h);
    m->count++;
    spin_unlock(&m->lock);
    return ret;
}

/**
 * 根据key查询value
 * 返回：0找到，-ENOENT未找到
 */
int map_get_by_key(struct alias_map *m, const char *key, uint32_t len, struct map_entry **entry) {
    struct map_entry *e;
    uint32_t h = map_hash(key, len);
    int ret = -ENOENT;

    if (!m || !key)
        return -EINVAL;

    spin_lock(&m->lock);
    hash_for_each_possible(m->table, e, node, h) {
        if (e->key_len == len && !memcmp(e->key, key, len)) {
            *entry = e;
            ret = 0;
            break;
        }
    }
    spin_unlock(&m->lock);
    return ret;
}

int map_get_by_value(struct alias_map *m, __be32 value, struct map_entry **entry) {
    struct map_entry *e;
    int bkt;
    int ret = -ENOENT;

    if (!m || !value)
        return -EINVAL;

    spin_lock(&m->lock);
    hash_for_each(m->table, bkt, e, node) {
        if (e->value == value) {
            *entry = e;
            ret = 0;
            break;
        }
    }
    spin_unlock(&m->lock);
    return ret;
}

inline void del_entry(struct map_entry *e) {
    hlist_del(&e->node);
    kfree(e->key);
    kfree(e);
}

int __attribute__((unused)) map_del_by_key(struct alias_map *m, const char *key) {
    struct map_entry *e;
    int ret = map_get_by_key(m, key, strlen(key), &e);
    if(ret == 0) {
        spin_lock(&m->lock);
        del_entry(e);
        m->count--;
        spin_unlock(&m->lock);
    }
    return ret;
}

int map_del_by_value(struct alias_map *m, __be32 value) {
    struct map_entry *e;
    int ret = map_get_by_value(m, value, &e);
    if(ret == 0) {
        spin_lock(&m->lock);
        del_entry(e);
        m->count--;
        spin_unlock(&m->lock);
    }
    return ret;
}

int __attribute__((unused)) map_mod_by_key(struct alias_map *m, const char *key, __be32 value) {
    struct map_entry *e;
    int ret = map_get_by_key(m, key, strlen(key), &e);
    if(ret == 0) {
        e->value = value;
    }
    return ret;
}

int map_mod_by_value(struct alias_map *m, __be32 value, char *key) {
    struct map_entry *e;
    int ret = map_get_by_value(m, value, &e);
    if(ret == 0) {
        kfree(e->key);
        e->key = key;
        e->key_len = strlen(key);
    }
    return ret;
}

void map_destroy(struct alias_map *m) {
    struct map_entry *e;
    struct hlist_node *tmp;
    int bkt;

    if (!m)
        return;

    spin_lock(&m->lock);
    hash_for_each_safe(m->table, bkt, tmp, e, node)
        del_entry(e);
    m->count = 0;
    spin_unlock(&m->lock);
}

// -------------------------- 3. 序列化/反序列化 --------------------------
/**
* map_serialize - 将map序列化为字节流
* @alias_map: map指针
* @buf: 输出缓冲区（内核空间，需提前分配）
* @buf_len: 缓冲区长度（输出：实际使用的长度）
* 返回：0成功，-EINVAL参数错误，-ENOMEM缓冲区不足
*/
int map_serialize(struct alias_map *m, char *buf, size_t *buf_len) {
    if (!m || !buf || !buf_len)
        return -EINVAL;
 
    // 第一步：计算需要的总长度（4字节count + 每个节点：4字节key_len + key + 4字节value）
    size_t required_len = 4;  // 存储节点数量（32位）
    int _key_len;
    // struct node *node;
    int bkt;
    struct map_entry *e;
    hash_for_each(m->table, bkt, e, node) {
        _key_len = strlen(e->key) + 1;  // 包含'\0'
        required_len += 4 + _key_len + 4;  // _key_len(4) + key + value(4)
    }

    // 检查缓冲区是否足够
    if (*buf_len < required_len) {
        *buf_len = required_len;  // 返回需要的长度
        return -ENOMEM;
    }

    // 第二步：写入节点数量（大端，保证跨端兼容性）
    size_t offset = 0;
    *(uint32_t *)(buf + offset) = htonl(m->count);
    offset += 4;

    // 第三步：写入每个节点
    hash_for_each(m->table, bkt, e, node) {
        _key_len = strlen(e->key) + 1;
        // 写入key长度（大端）
        *(uint32_t *)(buf + offset) = htonl(_key_len);
        offset += 4;
        // 写入key字符串
        memcpy(buf + offset, e->key, _key_len);
        offset += _key_len;
        // 写入value（__be32本身已是大端，直接拷贝）
        memcpy(buf + offset, &e->value, 4);
        offset += 4;
    }

    *buf_len = offset;  // 更新实际使用的长度
    return 0;
}
 
/**
* map_deserialize - 从字节流反序列化恢复map
* @m: 待初始化的map指针
* @buf: 输入字节流（内核空间）
* @buf_len: 字节流长度
* 返回：0成功，-EINVAL格式错误
*/
inline int map_deserialize(struct alias_map *m, const char *buf, size_t buf_len) {
    if (!m || !buf || buf_len < 4)
        return -EINVAL;

    // 初始化map（避免原有数据）
    map_destroy(m);
    map_init(m);

    // 读取节点数量（转为主机序）
    size_t offset = 0;
    uint32_t _count = ntohl(*(uint32_t *)(buf + offset));
    offset += 4;

    // 遍历解析每个节点
    uint32_t _key_len;
    __be32 value;
    char *key;
    for (int i = 0; i < _count; i++) {
        // 检查剩余长度是否足够
        if (offset + 4 + 1 + 4 > buf_len)  // _key_len(4) + 至少1字节key + value(4)
            goto err;

        // 读取key长度
        _key_len = ntohl(*(uint32_t *)(buf + offset));
        offset += 4;

        // 检查key长度合法性
        if (offset + _key_len + 4 > buf_len)
            goto err;

        // 读取key
        key = kmalloc(_key_len, GFP_KERNEL);
        if (!key)
            goto err;
        memcpy(key, buf + offset, _key_len);
        offset += _key_len;

        // 读取value
        memcpy(&value, buf + offset, 4);
        offset += 4;

        // 添加到map
        if (map_add(m, key, _key_len, value) != 0) {
            kfree(key);
            goto err;
        }
        kfree(key);
    }

    return 0;
 
err:
    map_destroy(m);
    return -EINVAL;
}
 
// -------------------------- 4. 文件存取功能 --------------------------
/**
* 将map保存到文件（内核态文件）
* @m: map指针
* @path: 文件路径（如"/tmp/map_data"）
* 返回：0成功，负数错误码
*/
int __attribute__((unused)) map_save_to_file(struct alias_map *m, const char *path) {

    if (!m || !path)
        return -EINVAL;
 
    // 第一步：计算序列化所需长度
    char *buf = NULL;
    size_t buf_len = 0;
    int ret = map_serialize(m, NULL, &buf_len);
    if (ret == -ENOMEM) {
        // 分配缓冲区
        buf = kmalloc(buf_len, GFP_KERNEL);
        if (!buf)
            return -ENOMEM;
        // 真正序列化
        ret = map_serialize(m, buf, &buf_len);
    }
    if (ret != 0) {
        kfree(buf);
        return ret;
    }

    // 第二步：打开文件（O_WRONLY|O_CREAT|O_TRUNC：只写、创建、截断）
    struct file *filp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        kfree(buf);
        return ret;
    }

    // 第三步：写入文件
    loff_t pos = 0;
    ret = kernel_write(filp, buf, buf_len, &pos);
    if (ret < 0 || (size_t)ret != buf_len) {
        ret = -EIO;
        goto out;
    }

out:
    filp_close(filp, NULL);
    kfree(buf);
    return ret >= 0 ? 0 : ret;
}

/**
* 从文件加载map
* @m: 待恢复的map指针
* @path: 文件路径
* 返回：0成功，负数错误码
*/
int map_load_from_file(struct alias_map *m, const char *path) {
    if (!m || !path)
        return -EINVAL;
 
    // 第一步：打开文件
    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        return PTR_ERR(filp);
    }

    // 第二步：获取文件大小
    char *buf = NULL;
    struct kstat stat;
    int ret = vfs_getattr(&filp->f_path, &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);
    if (ret != 0)
        goto out;

    // 第三步：分配缓冲区并读取文件
    buf = kmalloc(stat.size, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    loff_t pos = 0;
    ret = kernel_read(filp, buf, stat.size, &pos);
    if (ret < 0 || (size_t)ret != stat.size) {
        ret = -EIO;
        goto out;
    }

    // 第四步：反序列化
    ret = map_deserialize(m, buf, stat.size);

out:
    filp_close(filp, NULL);
    kfree(buf);
    return ret;
}

     // 2. 查询测试
//     __be32 value;
//     ret = map_get(&alias_map, "eth0", &value);
//     if (ret == 0) {
//         pr_info("eth0: %08x (host: %u.%u.%u.%u)\n", 
//                 be32_to_cpu(value),
//                 (be32_to_cpu(value) >> 24) & 0xff,
//                 (be32_to_cpu(value) >> 16) & 0xff,
//                 (be32_to_cpu(value) >> 8) & 0xff,
//                 be32_to_cpu(value) & 0xff);
//     }

//     // 3. 保存到文件
//     ret = map_save_to_file(&alias_map, "/tmp/alias_map.dat");
//     if (ret != 0) {
//         pr_err("Save to file failed: %d\n", ret);
//         goto err;
//     }
//     pr_info("Map saved to /tmp/alias_map.dat\n");

//     // 4. 销毁原有map，从文件加载
//     map_destroy(&alias_map);
//     ret = map_load_from_file(&alias_map, "/tmp/alias_map.dat");
//     if (ret != 0) {
//         pr_err("Load from file failed: %d\n", ret);
//         goto err;
//     }
//     pr_info("Map loaded from file\n");