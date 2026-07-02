/**
 * RR Syscall Tree Builder - C Side Implementation (Shared Memory Aware)
 *
 * High-performance syscall tree construction in C with MAP_SHARED support.
 * Process-aware logic using atomic counters and local cursors.
 * Author: RR-Fuzz Team
 * Date: 2025-12-31 (Updated for Multi-Process)
 */

/* Ensure RR_DEBUG is defined */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_syscall_tree.h"
#include "rr_framework.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

// Global Instance (Shared Memory Implementation)
// Initialize to NULL
RRSyscallTree *g_syscall_tree_ptr = NULL;

// Process-Local ID Tracker (Initialize to -1)
uint32_t g_current_tree_node_id = (uint32_t)-1;

/**
 * g_process_parents resides in SHARED MEMORY (within RRSyscallTree struct).
 * This allows Parent and Child processes to share linkage information across forks,
 * bypassing Copy-on-Write (COW) limitations for parent identification.
 */

/**
 * Initialize syscall tree (Shared Memory)
 */
void rr_tree_init(void) {
    if (g_syscall_tree_ptr != NULL) {
        // Already mapped (inherited or called twice)
        return; 
    }

    // Allocate Shared Memory
    size_t size = sizeof(RRSyscallTree);
    g_syscall_tree_ptr = (RRSyscallTree *)mmap(NULL, size, 
                                               PROT_READ | PROT_WRITE, 
                                               MAP_SHARED | MAP_ANONYMOUS, 
                                               -1, 0);
    
    if (g_syscall_tree_ptr == MAP_FAILED) {
        perror("[RR-Tree] mmap failed");
        g_syscall_tree_ptr = NULL;
        return;
    }

    // Initialize (Only if node_count is 0 aka fresh)
    // How to distinguish fresh from inherited?
    // mmap anonymous is zero-initialized.
    // So `node_count` is 0.
    // If we attach to existing? fork inherits mappings. 
    // Child sees SAME pointer, SAME physical memory.
    // `node_count` will be > 0.
    
    // BUT `rr_tree_init` is called at Startup?
    // In QEMU, `rr_main` calls init.
    // Forked QEMU doesn't re-run main?
    // Fork returns to `syscall.c`.
    // So `rr_tree_init` is called ONCE in Parent.
    // Child inherits initialized pointer.
    
    if (g_syscall_tree.node_count == 0 && g_syscall_tree.root_node_id == 0) {
       // Only First Process initializes
       RR_INFO("[RR-Tree] Initializing Shared Memory Syscall Tree");
       memset(g_syscall_tree_ptr, 0, size);
       g_syscall_tree.enabled = true;
       
       // Init Nodes to -1
       for (uint32_t i = 0; i < MAX_TREE_NODES; i++) {
           g_syscall_tree.nodes[i].parent_id = (uint32_t)-1;
           g_syscall_tree.nodes[i].first_child_id = (uint32_t)-1;
           g_syscall_tree.nodes[i].last_child_id = (uint32_t)-1;
           g_syscall_tree.nodes[i].next_sibling_id = (uint32_t)-1;
           g_syscall_tree.nodes[i].id = i;
       }
       memset(g_syscall_tree_ptr->process_parents, 0, sizeof(g_syscall_tree_ptr->process_parents));
    } else {
       RR_INFO("[RR-Tree] Process attached to existing Shared Syscall Tree (nodes=%u)", g_syscall_tree.node_count);
    }
}

/**
 * Clean up syscall tree
 */
void rr_tree_cleanup(void) {
    // Optional: munmap. But leaving it is fine for quick exit.
    // g_syscall_tree.enabled = false; // Don't disable shared, others might use it!
}

/**
 * Get current monotonic timestamp in microseconds
 */
static uint64_t get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000UL + (uint64_t)ts.tv_nsec / 1000UL;
}

uint32_t rr_tree_add_syscall_node(
    uint32_t pid,
    uint32_t syscall_index,
    int syscall_nr, 
    const char *syscall_name,
    uint64_t args[6], 
    int64_t retval,
    uint64_t timestamp_enter,
    uint64_t timestamp_exit,
    bool is_mutated           
) {
    if (!g_syscall_tree_ptr || !g_syscall_tree.enabled) {
        return (uint32_t)-1;
    }

    // Atomic Increment with Check (Safe CAS version)
    uint32_t current_count;
    do {
        current_count = g_syscall_tree.node_count;
        if (current_count >= MAX_TREE_NODES) {
            // Only warn once per root process session
            if (current_count == MAX_TREE_NODES) {
                fprintf(stderr, "[RR-Tree] Warning: Maximum tree nodes reached (%u). Capped.\n", MAX_TREE_NODES);
            }
            return (uint32_t)-1;
        }
    } while (!__sync_bool_compare_and_swap(&g_syscall_tree.node_count, current_count, current_count + 1));

    uint32_t node_id = current_count;

    TreeNode *node = &g_syscall_tree.nodes[node_id];

    node->id = node_id;
    node->pid = pid;
    node->syscall_index = syscall_index;
    node->syscall_nr = syscall_nr;
    snprintf(node->syscall_name, sizeof(node->syscall_name), "%s", syscall_name ? syscall_name : "unknown");

    for (int i = 0; i < 6; i++) {
        node->args[i] = args[i];
    }
    node->retval = retval;

    node->timestamp_enter = timestamp_enter ? timestamp_enter : get_timestamp_us();
    node->timestamp_exit = timestamp_exit ? timestamp_exit : get_timestamp_us();

    // Init fields
    node->first_child_id = (uint32_t)-1;
    node->last_child_id = (uint32_t)-1;
    node->next_sibling_id = (uint32_t)-1;
    node->is_fork_node = false;
    node->has_new_coverage = false;
    node->is_mutated = is_mutated;

    // Linkage Logic
    uint32_t parent_id;
    
    // Check if I am a child process's first syscall
    if (pid < MAX_TRACKED_PIDS && g_syscall_tree.process_parents[pid] != 0) {
        parent_id = g_syscall_tree.process_parents[pid];
        // Clear linkage to avoid sticking to it forever? No, pid is reused?
        // Keep it.
    } else {
        // Normal sequential sibling: use Process-Local Cursor
        parent_id = g_current_tree_node_id;
    }
    
    // Root check
    if (parent_id == node_id) parent_id = (uint32_t)-1;
    if (node_id == 0) {
         parent_id = (uint32_t)-1;
         g_syscall_tree.root_node_id = 0;
    }

    if (parent_id != (uint32_t)-1 && parent_id < MAX_TREE_NODES) {
        node->parent_id = parent_id;
        /**
         * NOTE: We only store the parent_id in C to avoid atomic data race complexity
         * when maintaining a full linked-list of children across multiple processes.
         * The D3.js visualizer reconstructs the full hierarchy from parent_id.
         */
        node->parent_id = parent_id;
    } else {
        node->parent_id = (uint32_t)-1;
    }

    // Update Process-Local Cursor
    g_current_tree_node_id = node_id;
    
    // Atomic Stats
    __sync_fetch_and_add(&g_syscall_tree.total_syscalls, 1);

    return node_id;
}

/**
 * Add fork relation between parent node and child PID
 */
// New implementation
void rr_tree_set_node_bbs(uint32_t node_id, const uint64_t *bbs, uint32_t count) {
    if (!g_syscall_tree_ptr || !g_syscall_tree.enabled) return;
    if (node_id >= g_syscall_tree.node_count) return;

    TreeNode *node = &g_syscall_tree.nodes[node_id];
    node->bb_count = (count > MAX_BB_PER_NODE) ? MAX_BB_PER_NODE : count;
    
    for (uint32_t i = 0; i < node->bb_count; i++) {
        node->bb_addrs[i] = bbs[i];
    }
}

void rr_tree_add_fork_relation(
    uint32_t parent_node_id,
    uint32_t child_pid
) {
    if (!g_syscall_tree_ptr || !g_syscall_tree.enabled) return;

    if (parent_node_id >= MAX_TREE_NODES) return; // Bounds check

    TreeNode *parent = &g_syscall_tree.nodes[parent_node_id];
    parent->is_fork_node = true;
    parent->fork_child_pid = child_pid;
    
    if (child_pid < MAX_TRACKED_PIDS) {
        // Shared Memory Update: Visible to Child process bypassing COW limitations
        g_syscall_tree.process_parents[child_pid] = parent_node_id;
        RR_VERBOSE("[RR-Tree] Registered Fork Relation: Child PID %u -> Parent Node %u", child_pid, parent_node_id);
    }
    
    __sync_fetch_and_add(&g_syscall_tree.total_forks, 1);
}

/**
 * Get syscall name (simplified version)
 */
const char* rr_tree_get_syscall_name(uint32_t syscall_nr) {

    // Common x86-64 syscalls
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 9: return "mmap";
        case 11: return "munmap";
        case 12: return "brk";
        case 56: return "clone";
        case 57: return "fork";
        case 58: return "vfork";
        case 59: return "execve";
        case 60: return "exit";
        case 231: return "exit_group";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 318: return "getrandom";
        default: return "unknown";
    }
}

// HTML Template Parts - D3.js Interactive Visualization
const char *HTML_HEADER = 
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"    <meta charset=\"UTF-8\">\n"
"    <title>RR-Fuzz Syscall Tree</title>\n"
"    <script src=\"https://d3js.org/d3.v7.min.js\"></script>\n"
"    <style>\n"
"        :root {\n"
"            --bg-color: #0f172a;\n"
"            --text-color: #e2e8f0;\n"
"            --panel-bg: rgba(30, 41, 59, 0.7);\n"
"            --accent: #3b82f6;\n"
"            --mutated: #ef4444;\n"
"            --fork: #d946ef;\n"
"            --success: #22c55e;\n"
"        }\n"
"        body {\n"
"            margin: 0;\n"
"            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);\n"
"            color: var(--text-color);\n"
"            font-family: 'Inter', system-ui, -apple-system, sans-serif;\n"
"            overflow: hidden;\n"
"            height: 100vh;\n"
"        }\n"
"        #header {\n"
"            position: fixed;\n"
"            top: 20px;\n"
"            left: 20px;\n"
"            right: 20px;\n"
"            padding: 15px 25px;\n"
"            background: var(--panel-bg);\n"
"            backdrop-filter: blur(12px);\n"
"            border: 1px solid rgba(255, 255, 255, 0.1);\n"
"            border-radius: 16px;\n"
"            display: flex;\n"
"            justify-content: space-between;\n"
"            align-items: center;\n"
"            z-index: 100;\n"
"            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);\n"
"        }\n"
"        h1 {\n"
"            margin: 0;\n"
"            font-size: 1.2rem;\n"
"            font-weight: 600;\n"
"            background: linear-gradient(to right, #60a5fa, #a855f7);\n"
"            -webkit-background-clip: text;\n"
"            -webkit-text-fill-color: transparent;\n"
"        }\n"
"        #controls {\n"
"            display: flex;\n"
"            gap: 15px;\n"
"            align-items: center;\n"
"        }\n"
"        .stat-badge {\n"
"            background: rgba(255, 255, 255, 0.05);\n"
"            padding: 5px 12px;\n"
"            border-radius: 20px;\n"
"            font-size: 0.85rem;\n"
"            border: 1px solid rgba(255, 255, 255, 0.05);\n"
"        }\n"
"        .stat-value { font-weight: bold; margin-left: 5px; color: var(--accent); }\n"
"        #search-box {\n"
"            background: rgba(0, 0, 0, 0.2);\n"
"            border: 1px solid rgba(255, 255, 255, 0.1);\n"
"            color: white;\n"
"            padding: 6px 12px;\n"
"            border-radius: 8px;\n"
"            outline: none;\n"
"        }\n"
"        #tree-container {\n"
"            width: 100%;\n"
"            height: 100vh;\n"
"            cursor: grab;\n"
"        }\n"
"        .node circle {\n"
"            transition: all 0.3s ease;\n"
"            fill: #1e293b;\n"
"            stroke: #475569;\n"
"            stroke-width: 2px;\n"
"        }\n"
"        .node.normal circle { stroke: #64748b; }\n"
"        .node.mutated circle {\n"
"            stroke: var(--mutated);\n"
"            filter: drop-shadow(0 0 4px rgba(239, 68, 68, 0.5));\n"
"            fill: rgba(239, 68, 68, 0.1);\n"
"        }\n"
"        .node.fork circle {\n"
"            stroke: var(--fork);\n"
"            fill: rgba(217, 70, 239, 0.1);\n"
"        }\n"
"        .node:hover circle {\n"
"            transform: scale(1.4);\n"
"            fill: #fff;\n"
"        }\n"
"        .link {\n"
"            fill: none;\n"
"            stroke: #475569;\n"
"            stroke-width: 1.5px;\n"
"            opacity: 0.4;\n"
"        }\n"
"        .tooltip {\n"
"            position: absolute;\n"
"            background: rgba(15, 23, 42, 0.95);\n"
"            backdrop-filter: blur(8px);\n"
"            border: 1px solid rgba(255, 255, 255, 0.1);\n"
"            padding: 12px;\n"
"            border-radius: 8px;\n"
"            font-size: 12px;\n"
"            pointer-events: none;\n"
"            z-index: 1000;\n"
"            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);\n"
"            max-width: 300px;\n"
"        }\n"
"    </style>\n"
"</head>\n"
"<body>\n"
"    <div id=\"header\">\n"
"        <div style=\"display:flex; align-items:center; gap:15px\">\n"
"            <h1>🌳 RR-Fuzz Tree</h1>\n"
"            <input type=\"text\" id=\"search-box\" placeholder=\"Search syscalls...\" oninput=\"searchNodes(this.value)\">\n"
"        </div>\n"
"        <div id=\"controls\">\n"
"            <div class=\"stat-badge\">Total: <span class=\"stat-value\" id=\"total-syscalls\">0</span></div>\n"
"            <div class=\"stat-badge\" style=\"border-color: var(--mutated)\">Mutated: <span class=\"stat-value\" style=\"color:var(--mutated)\" id=\"mutated-count\">0</span></div>\n"
"            <div class=\"stat-badge\" style=\"border-color: var(--fork)\">Forks: <span class=\"stat-value\" style=\"color:var(--fork)\" id=\"fork-count\">0</span></div>\n"
"        </div>\n"
"    </div>\n"
"    <div id=\"tree-container\">\n"
"        <svg id=\"tree-svg\"></svg>\n"
"    </div>\n"
"    <div class=\"tooltip\" id=\"tooltip\" style=\"display: none;\"></div>\n"
"    <script>\n"
"        const treeData = ";;

const char *HTML_FOOTER = 
";\n"
"        \n"
"        // Stats Init\n"
"        document.getElementById('total-syscalls').textContent = treeData.metadata.total_syscalls;\n"
"        document.getElementById('mutated-count').textContent = treeData.nodes.filter(n => n.is_mutated).length;\n"
"        document.getElementById('fork-count').textContent = treeData.metadata.total_forks;\n"
"        \n"
"        // Data Processing\n"
"        const nodeMap = {};\n"
"        treeData.nodes.forEach(n => {\n"
"            nodeMap[n.id] = { ...n, children: [] };\n"
"        });\n"
"        let hierarchyRoot = null;\n"
"        treeData.nodes.forEach(n => {\n"
"            const node = nodeMap[n.id];\n"
"            if (n.parent_id === 4294967295 || n.parent_id === n.id) { hierarchyRoot = node; }\n"
"            else if (nodeMap[n.parent_id]) { nodeMap[n.parent_id].children.push(node); }\n"
"        });\n"
"        \n"
"        // D3 Setup\n"
"        const width = window.innerWidth, height = window.innerHeight;\n"
"        const svg = d3.select('#tree-svg').attr('width', width).attr('height', height);\n"
"        const g = svg.append('g').attr('transform', 'translate(100,50)');\n"
"        const zoom = d3.zoom().scaleExtent([0.1, 4]).on('zoom', (e) => g.attr('transform', e.transform));\n"
"        svg.call(zoom);\n"
"        \n"
"        // Layout\n"
"        const tree = d3.tree().nodeSize([40, 250]);\n"
"        const root = d3.hierarchy(hierarchyRoot);\n"
"        const treeLayout = tree(root);\n"
"        \n"
"        // Links\n"
"        const links = g.selectAll('.link').data(treeLayout.links()).join('path').attr('class', 'link')\n"
"            .attr('d', d3.linkHorizontal().x(d => d.y).y(d => d.x));\n"
"        \n"
"        // Nodes\n"
"        const nodes = g.selectAll('.node').data(treeLayout.descendants()).join('g')\n"
"            .attr('class', d => {\n"
"                let cls = 'node ';\n"
"                if (d.data.is_fork_node) cls += 'fork';\n"
"                else if (d.data.is_mutated) cls += 'mutated';\n"
"                else if (d.data.retval < 0) cls += 'error';\n"
"                else cls += 'normal';\n"
"                return cls;\n"
"            })\n"
"            .attr('transform', d => `translate(${d.y},${d.x})`);\n"
"        \n"
"        nodes.append('circle').attr('r', 8);\n"
"        \n"
"        // Styling\n"
"        nodes.selectAll('circle').style('fill', d => d.data.is_mutated ? '#ef4444' : (d.data.is_fork_node ? '#d946ef' : '#3b82f6'));\n"
"        \n"
"        nodes.append('text').attr('dy', 4).attr('x', 14)\n"
"            .text(d => d.data.syscall_name)\n"
"            .style('fill', '#cbd5e1').style('font-size', '12px').style('font-family', 'monospace');\n"
"            \n"
"        // Badges for mutated\n"
"        nodes.filter(d => d.data.is_mutated).append('text')\n"
"            .text('⚠')\n"
"            .attr('x', -20).attr('dy', 5).style('fill', '#ef4444').style('font-size', '14px');\n"
"        \n"
"        // Tooltips\n"
"        const tooltip = d3.select('#tooltip');\n"
"        nodes.on('mouseover', (event, d) => {\n"
"            tooltip.style('display', 'block').html(`\n"
"                <div style=\"color:#93c5fd;font-weight:bold;margin-bottom:5px\">${d.data.syscall_name} (${d.data.syscall_nr})</div>\n"
"                <div style=\"color:#cbd5e1\">ID: ${d.data.id} | PID: ${d.data.pid}</div>\n"
"                <div style=\"margin:5px 0;padding:5px;background:rgba(0,0,0,0.3);border-radius:4px;font-family:monospace;font-size:11px\">Args: ${d.data.args.join(', ')}</div>\n"
"                <div style=\"color:${d.data.retval < 0 ? '#fca5a5' : '#86efac'}\">Ret: ${d.data.retval}</div>\n"
"                ${d.data.is_mutated ? '<div style=\"color:#ef4444;margin-top:5px;font-weight:bold\">⚠ MUTATED</div>' : ''}\n"
"            `);\n"
"        }).on('mousemove', e => tooltip.style('left', (e.pageX + 15) + 'px').style('top', (e.pageY + 15) + 'px'))\n"
"          .on('mouseout', () => tooltip.style('display', 'none'));\n"
"          \n"
"        // Search Logic\n"
"        window.searchNodes = (term) => {\n"
"            if (!term) {\n"
"                nodes.style('opacity', 1); links.style('opacity', 0.4);\n"
"                return;\n"
"            }\n"
"            const lower = term.toLowerCase();\n"
"            nodes.style('opacity', d => d.data.syscall_name.toLowerCase().includes(lower) ? 1 : 0.1);\n"
"            links.style('opacity', 0.05);\n"
"        };\n"
"        console.log('Syscall tree loaded:', treeData.metadata.total_syscalls, 'nodes');\n"
"    </script>\n"
"</body>\n"
"</html>\n"
";\n";

/**
 * @brief Export execution tree to HTML (Bundle)
 * 
 * Generates an HTML file containing the full tree data and visualization logic.
 * 
 * @param output_file Output file path
 */
void rr_tree_export_json(const char *output_file) {
    // Shared Memory Check
    if (!g_syscall_tree_ptr || !g_syscall_tree.enabled) {
        return;
    }

    if (output_file == NULL) {
        RR_WARN("[RR-Tree] No output file specified for export, skipping.");
        return;
    }

    // Safety: don't export more than MAX_TREE_NODES
    uint32_t capped_count = g_syscall_tree.node_count;
    if (capped_count > MAX_TREE_NODES) capped_count = MAX_TREE_NODES;

    RR_INFO("[RR-Tree] Exporting UNIFIED tree HTML bundle to %s (nodes=%u)", 
            output_file, capped_count);

    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "[RR-Tree] ERROR: Failed to open %s for writing\n", output_file);
        return;
    }

    // 1. Write HTML Header
    fprintf(fp, "%s", HTML_HEADER);

    // 2. Write JSON Data
    fprintf(fp, "{\n");
    fprintf(fp, "  \"metadata\": {\n");
    fprintf(fp, "    \"total_nodes\": %u,\n", capped_count);
    fprintf(fp, "    \"total_syscalls\": %u,\n", g_syscall_tree.total_syscalls);
    fprintf(fp, "    \"total_forks\": %u,\n", g_syscall_tree.total_forks);
    fprintf(fp, "    \"root_node_id\": %u\n", g_syscall_tree.root_node_id);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"nodes\": [\n");

    // Loop through ALL nodes in shared memory
    for (uint32_t i = 0; i < capped_count; i++) {
        TreeNode *node = &g_syscall_tree.nodes[i];

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"id\": %u,\n", node->id);
        fprintf(fp, "      \"pid\": %u,\n", node->pid);
        fprintf(fp, "      \"syscall_index\": %u,\n", node->syscall_index);
        fprintf(fp, "      \"syscall_nr\": %u,\n", node->syscall_nr);
        fprintf(fp, "      \"syscall_name\": \"%s\",\n", node->syscall_name);
        
        fprintf(fp, "      \"args\": [\"%lu\", \"%lu\", \"%lu\", \"%lu\", \"%lu\", \"%lu\"],\n",
                node->args[0], node->args[1], node->args[2], 
                node->args[3], node->args[4], node->args[5]);

        fprintf(fp, "      \"bb_addresses\": [");
        for (uint32_t k = 0; k < node->bb_count; k++) {
            fprintf(fp, "\"0x%lx\"", node->bb_addrs[k]);
            if (k < node->bb_count - 1) fprintf(fp, ", ");
        }
        fprintf(fp, "],\n");

        fprintf(fp, "      \"retval\": %ld,\n", node->retval);
        fprintf(fp, "      \"timestamp_enter\": %lu,\n", node->timestamp_enter);
        fprintf(fp, "      \"timestamp_exit\": %lu,\n", node->timestamp_exit);
        fprintf(fp, "      \"parent_id\": %u,\n", node->parent_id);

        fprintf(fp, "      \"children_ids\": [],\n"); 

        fprintf(fp, "      \"is_fork_node\": %s,\n", node->is_fork_node ? "true" : "false");
        fprintf(fp, "      \"fork_child_pid\": %u,\n", node->fork_child_pid);
        fprintf(fp, "      \"has_new_coverage\": %s,\n", node->has_new_coverage ? "true" : "false");
        fprintf(fp, "      \"is_mutated\": %s\n", node->is_mutated ? "true" : "false");

        fprintf(fp, "    }");
        if (i < capped_count - 1) {
            fprintf(fp, ",");
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    // 3. Write HTML Footer
    fprintf(fp, "%s", HTML_FOOTER);

    fclose(fp);
    RR_INFO("[RR-Tree] ✅ Exported %u nodes HTML bundle to %s", g_syscall_tree.node_count, output_file);
}
