#
# Copyright (C) 2015-2018,  Netronome Systems, Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# @file         apps/packet_steer/Makefile
# @brief        Makefile for the packet steer app
#

# Define src_dir FIRST - it is the directory that this makefile resides in
# MUST OCCUR BEFORE ANY include's (which will change MAKEFILE_LIST)
app_src_dir     := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT_SRC_DIR  ?= $(realpath $(app_src_dir)/../..)
base_dir        := $(ROOT_SRC_DIR)
BUILD_DIR       := build

microc_blocks_dir   := $(base_dir)/external/flowenv/me/blocks
microc_libs_dir     := $(base_dir)/external/flowenv/me/lib
microc_inc_dir      := $(base_dir)/external/flowenv/me/include
scripts_dir         := $(base_dir)/scripts
libmalloc_dir   	:= $(app_src_dir)/dependencies/hash-table/dependencies/libmalloc
flow_table_dir   	:= $(app_src_dir)/dependencies/hash-table

include $(scripts_dir)/Makefile.nfp.config
-include Makefile.nfp.config

include $(scripts_dir)/Makefile.templates

PKT_NBI_OFFSET ?= 64

# Create build directory
$(shell mkdir -p $(BUILD_DIR))

# Override output directory
FW_BUILD_DIR := $(BUILD_DIR)

# BLM
$(eval $(call microcode.assemble,blm_obj,$(microc_blocks_dir)/blm,blm_main.uc))
$(eval $(call microcode.add_flags,blm_obj,-DBLM_CUSTOM_CONFIG -DSINGLE_NBI -DPKT_NBI_OFFSET=$(PKT_NBI_OFFSET)))
$(eval $(call microcode.add_flags,blm_obj,-DBLM_BLQ_EMEM_TYPE=emem -DNBII=8 -DBLM_INSTANCE_ID=0))
$(eval $(call microcode.add_flags,blm_obj,-DBLM_INIT_EMU_RINGS))
$(eval $(call microcode.add_flags,blm_obj,-DNFP_LIB_ANY_NFAS_VERSION))
$(eval $(call microcode.add_flags,blm_obj,-I$(microc_blocks_dir)/blm))
$(eval $(call microcode.add_flags,blm_obj,-I$(microc_blocks_dir)/blm/_h))
$(eval $(call microcode.add_flags,blm_obj,-I$(microc_blocks_dir)/blm/_uc))
$(eval $(call microcode.add_flags,blm_obj,-Isrc))

#
# Steer definition
#
$(eval $(call micro_c.compile_with_rtl,steer_obj,src/steer.c))
$(eval $(call micro_c.add_fw_libs,steer_obj,nfp pkt std net))
$(eval $(call micro_c.add_flags,steer_obj,-I$(microc_blocks_dir)/blm))
$(eval $(call micro_c.add_flags,steer_obj,-Isrc))
$(eval $(call micro_c.add_src_lib,steer_obj,libblm,$(microc_blocks_dir)/blm))
$(eval $(call micro_c.force_include,steer_obj,config))

#
# Worker definition {
$(eval $(call micro_c.compile_with_rtl,worker_obj,main.c))
$(eval $(call micro_c.add_fw_libs,worker_obj,nfp std pkt net))
$(eval $(call micro_c.add_flags,worker_obj,-Isrc))
#hash table stuff {
$(eval $(call micro_c.add_src_lib,worker_obj,flow_table,${flow_table_dir}))
#libmalloc stuff
THREADS_PER_ME = 8
NUM_ME = 48
NUM_THREADS = $(shell echo $$(( $(THREADS_PER_ME) * $(NUM_ME) )))
I32_ME_LIST = i32.me0 i32.me1 i32.me2 i32.me3 i32.me4 i32.me5 i32.me6 i32.me7 i32.me8 i32.me9 i32.me10 i32.me11
I33_ME_LIST = i33.me0 i33.me1 i33.me2 i33.me3 i33.me4 i33.me5 i33.me6 i33.me7 i33.me8 i33.me9 i33.me10 i33.me11
I34_ME_LIST = i34.me0 i34.me1 i34.me2 i34.me3 i34.me4 i34.me5 i34.me6 i34.me7 i34.me8 i34.me9 i34.me10 i34.me11
I35_ME_LIST = i35.me0 i35.me1 i35.me2 i35.me3 i35.me4 i35.me5 i35.me6 i35.me7 i35.me8 i35.me9 i35.me10 i35.me11
I36_ME_LIST = i36.me0 i36.me1 i36.me2 i36.me3 i36.me4 i36.me5 i36.me6 i36.me7 i36.me8 i36.me9 i36.me10 i36.me11
$(eval $(call micro_c.add_src_lib,worker_obj,libmalloc,$(libmalloc_dir)))
$(eval $(call micro_c.add_src_lib,worker_obj,mem40_barrier,${libmalloc_dir}/dependencies/mem40_barrier))
$(eval $(call micro_c.add_src_lib,worker_obj,mem40_mutex,$(libmalloc_dir)/dependencies/mem40_mutex))
$(eval $(call micro_c.add_src_lib,worker_obj,libc,$(NFP_STD_LIB)/microc/src))
$(eval $(call micro_c.add_src_lib,worker_obj,intrinsic,$(NFP_STD_LIB)/microc/src))
$(eval $(call micro_c.add_flags,worker_obj,-Od)) #don't optimize
$(eval $(call micro_c.add_flags,worker_obj,-Qspill=1)) #spill registers

$(eval $(call micro_c.add_flags,worker_obj,-Qnctx=$(THREADS_PER_ME)))
$(eval $(call micro_c.add_defines,worker_obj,NUM_THREADS=$(NUM_THREADS)))
# hash table stuff }
# worker definition }


$(eval $(call fw.add_obj,steer,steer_obj,${I32_ME_LIST}))
$(eval $(call fw.add_obj,steer,worker_obj,${I33_ME_LIST}))
$(eval $(call fw.add_obj,steer,worker_obj,${I34_ME_LIST}))
$(eval $(call fw.add_obj,steer,worker_obj,${I35_ME_LIST}))
$(eval $(call fw.add_obj,steer,worker_obj,${I36_ME_LIST}))
$(eval $(call fw.add_obj,steer,blm_obj,i48.me0))
$(eval $(call fw.link_with_rtsyms,steer))
$(eval $(call fw.add_ppc,steer,i8,$(PICO_CODE)))

# Default target with organized output
.PHONY: all
all:
	@$(MAKE) all_fw
	@echo "Moving build artifacts to $(BUILD_DIR)..."
	@mv -f *.obj *.list *.uci *.ucp *.fw *.map *1 $(BUILD_DIR)/ 2>/dev/null || true
	@echo "Build complete. Firmware is in $(BUILD_DIR)/steer.fw"

#
# Debug
#
-include $(scripts_dir)/Makefile.debug
-include Makefile.debug

#
# Additional clean rules to remove all build artifacts
#
FW_steer__FILES_TO_CLEAN += $(wildcard *.obj) $(wildcard *.list) $(wildcard *.uci) $(wildcard *.ucp) $(wildcard *.map) $(wildcard $(BUILD_DIR)/*.obj) $(wildcard $(BUILD_DIR)/*.list) $(wildcard $(BUILD_DIR)/*.uci) $(wildcard $(BUILD_DIR)/*.ucp) $(wildcard $(BUILD_DIR)/*.fw) $(wildcard $(BUILD_DIR)/*.map) 1

#
# Load firmware target
#
.PHONY: load
load:
	@echo "Cleaning previous build..."
	$(MAKE) clean
	@echo "Building firmware..."
	$(MAKE) all
	@echo "Loading firmware..."
	sudo ./init/load.sh restart build/steer.fw
	@echo "Bringing up network interfaces..."
	sudo nfp -m mac -e set port ifup 0 0
	sudo nfp -m mac -e set port ifup 0 4
	@echo "Firmware loaded and interfaces are up"