# RR-Fuzz meson.build
# QEMU构建系统集成

# RR-Fuzz source files (按模块组织)
rr_fuzz_sources = files(
  # Core - 核心框架
  'src/core/rr_main.c',
  'src/core/rr_config.c',
  'src/core/rr_stabilize.c',
  'src/core/rr_debug.c',
  'src/core/rr_bb_trace.c',
  
  # Record - 录制模块
  'src/engine/rr_record.c',
  'src/engine/rr_aux_data.c',
  
  # Replay - 重放模块
  'src/engine/rr_replay.c',              # 二进制 trace Hybrid 重放
  'src/engine/rr_replay_pure.c',         # 二进制 trace Pure 重放（EnvFuzz 风格）
  'src/engine/rr_replay_pure_reapply.c', # Phase 1: Pure Replay 重新应用
  'src/engine/rr_replay_strace_optimized.c',  # Strace 文本重放 (暂时禁用，需要修复类型不匹配)
  
  # Fuzzing - Fuzzing引擎（QEMU集成层）
  'src/engine/rr_fuzz_engine.c',
  'src/engine/rr_fuzz_aux_mutations.c',  # Phase 1: aux_data 变异引擎
  'src/engine/rr_coverage.c',            # Phase 3: 覆盖率追踪（实现完成）
  
  # Utils - 工具模块
  'src/common/rr_mapping_manager.c',
  'src/common/rr_mock_ioctls.c',
  'src/syscall/rr_syscall_info.c',
  'src/syscall/rr_syscall_dispatch.c',
  'src/syscall/rr_syscallparser.c',
  'src/runtime/rr_ipc.c',
  'src/syscall/rr_dynamic_trace.c',
  'src/runtime/rr_snapshot.c',
  'src/runtime/rr_checkpoint.c',       # ✅ checkpoint机制
  'src/runtime/rr_fork_server.c',
  'src/runtime/rr_nested_fork.c',      # ✅ autonomous nested fork
  'src/syscall/rr_syscall_tree.c',     # ✅ C-Tree-P2: syscall tree builder
  
)

# RR-Fuzz configuration option
rr_fuzzing = get_option('rr_fuzzing')

if rr_fuzzing.enabled()
  # Add RR-Fuzz sources to linux-user build
  linux_user_ss.add(rr_fuzz_sources)
  # Include headers from the centralized include directory
  linux_user_ss.add(declare_dependency(include_directories: include_directories('include')))

  # Install header file
  install_headers('include/rr_framework.h', subdir: 'qemu/fuzzing')

  message('RR-Fuzz support enabled')
else
  message('RR-Fuzz support disabled')
endif

