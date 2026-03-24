project('netflow_fwd', 'C', 'CPP',
    version: '1.0',
    default_options: ['buildtype=debugoptimized', 'c_std=gnu11']
)

# 1. Find the required system libraries
deps = [
    dependency('libdpdk'),
    dependency('doca-common'),
    dependency('doca-flow'),
    dependency('doca-argp'),
    dependency('threads')
]

# 2. Define where the header files (.h) are located
# This links your local app to the common folder you copied
inc_dirs = include_directories(
    '.',
    '../common/'
)

# 3. List the C source files to compile
# (Check your src/ and ../common/src/ folders to ensure these names match exactly)
src_files = files(
  'doca_netflow.c',
  'simple_fwd.c',
  'simple_fwd_ft.c',
  'simple_fwd_pkt.c',
  'simple_fwd_port.c',
  'simple_fwd_vnf_core.c',
  '../common/dpdk_utils.c',
  '../common/utils.c'
)

# 4. Build the final executable
executable('doca_netflow_app',
    src_files,
    include_directories : inc_dirs,
    dependencies : deps,
    install: false
)
