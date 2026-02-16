# Coding Standards

> "Code should minimize the time it takes for someone else to understand it."
> — *The Art of Readable Code*

## Naming

### Descriptive Names

```c
// Bad
int fwd_pkt(struct sk_buff *s);

// Good
int forward_packet(struct sk_buff *skb);
```

### Prefixes

```c
// Public API - use prefix
int sess_create(struct sess_key *key);
void sess_delete(struct session *s);

// Internal - static, no prefix
static bool validate_tcp_flags(u8 flags);
```

### Constants

```c
#define SESSION_HASH_BITS   10
#define SESSION_TIMEOUT_SEC 300

enum sess_state {
    SESS_NEW,
    SESS_ESTABLISHED,
    SESS_CLOSING,
};
```

## Comments

### Explain "Why", Not "What"

```c
// Bad
atomic64_inc(&pkts_forwarded);  // Increment counter

// Good - explains why
atomic64_inc(&pkts_forwarded);  // Track for /proc/stargazer/stats
```

### Function Documentation

```c
/**
 * sess_lookup - Find session by 5-tuple
 * @key: source/dest IP, ports, protocol
 *
 * RCU-protected O(1) hash lookup. Caller holds rcu_read_lock().
 *
 * Return: session pointer or NULL
 */
struct session *sess_lookup(const struct sess_key *key);
```

## Code Structure

### Single Responsibility

```c
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    if (!is_valid_ipv4(skb))
        return NF_DROP;

    // Future: sess_lookup(), ips_check(), ml_classify()

    atomic64_inc(&pkts_forwarded);
    return NF_ACCEPT;
}
```

### Early Returns

```c
// Bad - deep nesting
if (skb) {
    if (validate(skb)) {
        if (session) {
            // work
        }
    }
}

// Good - flat
if (!skb)
    return -EINVAL;
if (!validate(skb))
    return -EBADMSG;
if (!session)
    return -ENOENT;
// work
```

## Error Handling

```c
// Guard clauses reject bad input early, keep main logic flat
if (rating >= MALICIOUS_THRESHOLD)
    return -EPERM;

// Do work
```

### Limit Variable Scope

**Bad (wide scope):**
```c
void process_packets(void) {
    struct iphdr *ip_header;
    int i;
    
    for (i = 0; i < 100; i++) {
        // ip_header used 50 lines later
    }
}
```

**Good (narrow scope):**
```c
void process_packets(void) {
    for (int i = 0; i < 100; i++) {
        struct iphdr *ip_header = get_ip_header(packets[i]);
        // Use immediately
    }
}
```

---

## Error Handling

```c
// Always check return values
ret = nf_register_net_hook(&init_net, &nf_ops);
if (ret < 0) {
    pr_err("pkt_forward: hook failed (%d)\n", ret);
    return ret;
}

// Use meaningful errno
if (!session)   return -ENOENT;  // No entry
if (table_full) return -ENOSPC;  // No space
```

## Performance

```c
// Rate-limit logging in fast path
if (net_ratelimit())
    pr_debug("packet from %pI4\n", &iph->saddr);

// Use O(1) hash lookup, not O(n) scan
u32 hash = key_hash(key);
hash_for_each_possible_rcu(table, s, node, hash) { ... }
```

## Style

- **Indent**: Tabs (kernel style)
- **Line length**: 80 chars (100 max)
- **Braces**: K&R style

```c
if (condition) {
    do_something();
} else {
    do_other();
}
```

## Checklist

- [ ] Descriptive names
- [ ] Comments explain "why"
- [ ] Functions < 50 lines
- [ ] No magic numbers
- [ ] Error returns checked
- [ ] No warnings with `-Wall -Wextra`

---

*Last Updated: February 3, 2026*
