# Stargazer Coding Standards

**Based on "The Art of Readable Code" by Dustin Boswell & Trevor Foucher**

## Core Principles

### 1. Code Should Be Easy to Understand

> "Code should be written to minimize the time it would take for someone else to understand it."

This is the fundamental principle. All other guidelines serve this goal.

---

## Naming Conventions

### Choose Descriptive Names

**❌ Bad:**
```c
int fwd_pkt(struct sk_buff *s) {
    struct iphdr *h = ip_hdr(s);
    // ...
}
```

**✅ Good:**
```c
int forward_packet(struct sk_buff *skb) {
    struct iphdr *ip_header = ip_hdr(skb);
    // ...
}
```

### Use Concrete Names Over Abstract

**❌ Bad:**
```c
int process_data(void *data);
```

**✅ Good:**
```c
int classify_flow_with_ml(struct netflow_record *flow);
```

### Module-Specific Prefixes

All public functions/variables use `stargazer_` prefix to avoid namespace pollution:

```c
// Public API
int stargazer_session_create(struct session_key *key);
void stargazer_session_destroy(u32 session_id);

// Internal (static) functions don't need prefix
static bool validate_tcp_flags(u8 flags);
```

### Enum and Constant Naming

```c
// ALL_CAPS for #define constants
#define STARGAZER_MAX_SESSIONS  8192
#define ML_RATING_THRESHOLD     0.95

// lowercase for enum types, CAPS for values
enum session_state {
    SESSION_STATE_NEW,
    SESSION_STATE_ESTABLISHED,
    SESSION_STATE_CLOSING,
};
```

---

## Comments and Documentation

### Write Comments That Explain "Why", Not "What"

**❌ Bad (obvious "what"):**
```c
// Increment counter
atomic64_inc(&packets_forwarded);
```

**✅ Good (explains "why"):**
```c
// Track forwarded packets for performance monitoring
// This data feeds into /proc/stargazer/stats for admin visibility
atomic64_inc(&packets_forwarded);
```

### Function Header Comments

Every non-trivial function gets a header:

```c
/*
 * stargazer_session_lookup - Find session by 5-tuple key
 * @key: Source/dest IP, ports, and protocol
 * 
 * Returns: Pointer to session structure if found, NULL otherwise
 * 
 * Uses hash table for O(1) average lookup. Called in fast path,
 * so must be lock-free using RCU (Read-Copy-Update).
 */
static struct session *stargazer_session_lookup(struct session_key *key)
{
    // Implementation...
}
```

### TODO Comments with Context

**❌ Bad:**
```c
// TODO: fix this
```

**✅ Good:**
```c
/*
 * TODO (Phase 3): Replace linear scan with Aho-Corasick automaton
 * Current O(n*m) signature matching won't scale beyond 1000 rules.
 * See IPS optimization task #47.
 */
```

---

## Code Structure

### Keep Functions Small and Focused

Each function should do **one thing**. If you can't summarize it in one sentence, it's too complex.

**❌ Bad (does too much):**
```c
int process_packet(struct sk_buff *skb) {
    // Extract IP header
    // Validate checksum
    // Lookup session
    // Run IPS
    // Run ML
    // Log result
    // Update stats
    // ... (150 lines)
}
```

**✅ Good (single responsibility):**
```c
static unsigned int stargazer_forward_hook(void *priv, 
                                           struct sk_buff *skb,
                                           const struct nf_hook_state *state)
{
    if (!validate_ip_packet(skb))
        return NF_DROP;
    
    struct session *sess = lookup_or_create_session(skb);
    if (!sess)
        return NF_DROP;
    
    if (should_block_by_ips(sess, skb))
        return NF_DROP;
    
    if (should_block_by_ml_rating(sess))
        return NF_DROP;
    
    update_session_stats(sess, skb);
    return NF_ACCEPT;
}
```

### Early Returns to Reduce Nesting

**❌ Bad (deep nesting):**
```c
if (skb) {
    if (validate(skb)) {
        if (session) {
            if (rating < threshold) {
                // Do work
            }
        }
    }
}
```

**✅ Good (flat structure):**
```c
if (!skb)
    return -EINVAL;

if (!validate(skb))
    return -EBADMSG;

if (!session)
    return -ENOENT;

if (rating >= MALICIOUS_THRESHOLD)
    return -EPERM;

// Do work
```

### Limit Variable Scope

**❌ Bad (wide scope):**
```c
void process_packets(void) {
    struct iphdr *ip_header;
    int i;
    
    for (i = 0; i < 100; i++) {
        // ip_header used 50 lines later
    }
}
```

**✅ Good (narrow scope):**
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

### Check All Return Values

**❌ Bad:**
```c
nf_register_net_hook(&init_net, &hook_ops);
printk("Module loaded\n");
```

**✅ Good:**
```c
ret = nf_register_net_hook(&init_net, &hook_ops);
if (ret < 0) {
    printk(KERN_ERR "Stargazer: Failed to register hook: %d\n", ret);
    return ret;
}
printk(KERN_INFO "Stargazer: Module loaded\n");
```

### Use Descriptive Error Codes

```c
// Return meaningful errno values
if (!session)
    return -ENOENT;      // "No such entry"

if (rating > ML_RATING_MALICIOUS_MIN)
    return -EPERM;       // "Operation not permitted"

if (table_full)
    return -ENOSPC;      // "No space left"
```

---

## Performance Best Practices

### Avoid Premature Optimization

First make it **correct** and **readable**, then profile and optimize hot paths.

### But Be Aware of Costs

```c
// ❌ Bad: O(n) lookup in fast path
for (int i = 0; i < num_sessions; i++) {
    if (match(sessions[i], key))
        return &sessions[i];
}

// ✅ Good: O(1) hash lookup
u32 hash = session_hash(key);
return hash_table[hash % HASH_BUCKETS];
```

### Rate-Limit Logging in Fast Path

```c
// ❌ Bad: Can flood kernel log at 1Gbps
printk(KERN_INFO "Packet from %pI4\n", &ip->saddr);

// ✅ Good: Rate-limited
if (net_ratelimit())
    printk(KERN_DEBUG "Packet from %pI4\n", &ip->saddr);
```

---

## Formatting Standards

### Follow Linux Kernel Style

- **Indentation**: Tabs (8 spaces wide)
- **Line length**: 80 characters (100 max for readability exceptions)
- **Braces**: K&R style (opening brace on same line)

```c
if (condition) {
    do_something();
} else {
    do_other_thing();
}
```

### Alignment for Readability

**Struct definitions:**
```c
struct session {
    u32             session_id;       /* Unique identifier */
    u16             flags;            /* SESSION_* flags */
    u64             packets_tx;       /* Transmitted packets */
    u64             packets_rx;       /* Received packets */
    ktime_t         last_activity;    /* For timeout detection */
};
```

**Function parameters:**
```c
static unsigned int stargazer_forward_hook(void *priv,
                                           struct sk_buff *skb,
                                           const struct nf_hook_state *state)
```

---

## Testing Considerations

### Write Testable Code

```c
// ❌ Bad: Hard to unit test (global state)
int process(void) {
    return global_counter++;
}

// ✅ Good: Pure function, easy to test
int calculate_flow_rating(struct netflow_features *features) {
    return (features->iat_mean > THRESHOLD) ? HIGH_RISK : LOW_RISK;
}
```

### Add Debug Instrumentation

```c
#ifdef STARGAZER_DEBUG
    stargazer_debug("Session %u: packets=%llu, rating=%.2f",
                    sess->id, sess->packets_tx, sess->ml_rating);
#endif
```

---

## Module-Specific Guidelines

### Kernel Modules (C)

- Prefer `static` for internal functions (avoids symbol conflicts)
- Use `__init` and `__exit` markers for module lifecycle functions
- Always clean up in reverse order of initialization

```c
static int __init stargazer_init(void)
{
    // Initialize in order: A → B → C
    if (init_session_table() < 0)
        goto fail_session;
    
    if (register_netfilter_hooks() < 0)
        goto fail_netfilter;
    
    return 0;

fail_netfilter:
    cleanup_session_table();
fail_session:
    return -ENOMEM;
}
```

### Userspace Daemon (C++)

- Use RAII for resource management
- Prefer `std::unique_ptr` over raw pointers
- Exceptions for error handling (unlike kernel code)

```cpp
// RAII: File closed automatically
std::unique_ptr<LightGBMPredictor> ml_engine;

try {
    ml_engine = std::make_unique<LightGBMPredictor>("model.txt");
} catch (const std::exception& e) {
    spdlog::error("Failed to load ML model: {}", e.what());
    return EXIT_FAILURE;
}
```

---

## Quick Checklist

Before committing code, verify:

- [ ] Function names clearly describe what they do
- [ ] Variable names are pronounceable and searchable
- [ ] Comments explain "why", not "what"
- [ ] Functions are <50 lines (exceptions for state machines)
- [ ] No magic numbers (use named constants)
- [ ] Error returns are checked
- [ ] No compiler warnings with `-Wall -Wextra`
- [ ] Follows Linux kernel style (use `scripts/checkpatch.pl`)

---

## References

- "The Art of Readable Code" - Boswell & Foucher
- Linux Kernel Coding Style: `Documentation/process/coding-style.rst`
- Stargazer project context document

---

**Last Updated**: February 1, 2026  
**Maintained by**: Stargazer Team
