#ifndef RR_SYSCALL_TREE_H
#define RR_SYSCALL_TREE_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_TREE_NODES 200000      // Max 200,000 nodes
#define MAX_CHILDREN_PER_NODE 16   // Max 16 child nodes per node
#define MAX_SYSCALL_NAME 32
#define MAX_BB_PER_NODE 128        // Max 128 BBs per syscall node

/* TreeNode: Represents a syscall execution node */
typedef struct TreeNode {
    /* Basic information */
    uint32_t id;                           // Node ID (globally unique)
    uint32_t pid;                          // Process ID
    uint32_t syscall_index;                // Index in trace
    uint32_t syscall_nr;                   // Syscall number
    char syscall_name[MAX_SYSCALL_NAME];   // Syscall name

    /* Syscall arguments and return value */
    uint64_t args[6];                      // Max 6 arguments
    int64_t retval;                        // Return value

    /* Timestamp information */
    uint64_t timestamp_enter;              // Entry timestamp (ns)
    uint64_t timestamp_exit;               // Exit timestamp (ns)

    /* Tree structure */
    // Tree structure (Linked List for unlimited children)
    uint32_t parent_id;                    // Parent node ID
    // Linked list implementation for unlimited children
    uint32_t first_child_id;               // First child node ID
    uint32_t last_child_id;                // Last child node ID (for fast append)
    uint32_t next_sibling_id;              // Next sibling node ID

    /* Fork information */
    bool is_fork_node;                     // Whether it's a fork node
    uint32_t fork_child_pid;               // PID of child process created by fork

    /* Coverage information (optional) */
    bool has_new_coverage;                 // Whether new coverage was discovered
    uint32_t new_edges_count;              // Number of new edges

    /* Mutation information (optional) */
    bool is_mutated;                       // Whether it was mutated
    uint8_t mutation_cmd;                  // Mutation command type

    /* Basic Block Trace (Mapping) */
    uint32_t bb_count;
    uint64_t bb_addrs[MAX_BB_PER_NODE];    // Array of BB addresses executed before this syscall

} TreeNode;

/* Syscall Tree global structure */
typedef struct RRSyscallTree {
    /* Node pool */
    TreeNode nodes[MAX_TREE_NODES];
    uint32_t node_count;                   // Current number of nodes

    /* Root node */
    uint32_t root_node_id;

    /* Statistics */
    uint32_t total_syscalls;
    uint32_t total_forks;

    /* Process parent-child relationship mapping (Shared Memory Linkage) */
    // Index: Child PID, Value: Parent Node ID
    #define MAX_TRACKED_PIDS 65536
    uint32_t process_parents[MAX_TRACKED_PIDS];

    /* Enable flag */
    bool enabled;

} RRSyscallTree;

/* Global tree instance (SHARED MEMORY POINTER) */
extern RRSyscallTree *g_syscall_tree_ptr;
// Compatibility Macro to minimize code changes: g_syscall_tree.xxx -> g_syscall_tree_ptr->xxx
#define g_syscall_tree (*g_syscall_tree_ptr)

// Process-Local State (COW ensures each process has its own cursor)
extern uint32_t g_current_tree_node_id;

/* API Functions */
void rr_tree_init(void);
void rr_tree_cleanup(void);

uint32_t rr_tree_add_syscall_node(
    uint32_t pid,
    uint32_t syscall_index,
    int syscall_nr,
    const char *syscall_name,
    uint64_t args[6],
    int64_t retval,
    uint64_t timestamp_enter,
    uint64_t timestamp_exit,
    bool is_mutated           // Whether mutated
);

void rr_tree_add_fork_relation(
    uint32_t parent_node_id,
    uint32_t child_pid
);

void rr_tree_set_node_bbs(
    uint32_t node_id,
    const uint64_t *bbs,
    uint32_t count
);

void rr_tree_export_json(const char *output_file);

/* Helper functions */
const char* rr_tree_get_syscall_name(uint32_t syscall_nr);

#endif /* RR_SYSCALL_TREE_H */
