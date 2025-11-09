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

microc_blocks_dir   := $(base_dir)/external/flowenv/me/blocks
microc_libs_dir     := $(base_dir)/external/flowenv/me/lib
microc_inc_dir      := $(base_dir)/external/flowenv/me/include
scripts_dir         := $(base_dir)/scripts

include $(scripts_dir)/Makefile.nfp.config
-include Makefile.nfp.config

include $(scripts_dir)/Makefile.templates

PKT_NBI_OFFSET ?= 64

# BLM
$(eval $(call microcode.assemble,blm_obj,$(microc_blocks_dir)/blm,blm_main.uc))
$(eval $(call microcode.add_flags,blm_obj,-DBLM_CUSTOM_CONFIG -DSINGLE_NBI -DPKT_NBI_OFFSET=$(PKT_NBI_OFFSET)))
$(eval $(call microcode.add_flags,blm_obj,-DBLM_BLQ_EMEM_TYPE=emem -DNBII=8 -DBLM_INSTANCE_ID=0))
$(eval $(call microcode.add_flags,blm_obj,-DBLM_INIT_EMU_RINGS))
$(eval $(call microcode.add_flags,blm_obj,-DNFP_LIB_ANY_NFAS_VERSION))
$(eval $(call microcode.add_flags,blm_obj,-I$(microc_blocks_dir)/blm))
$(eval $(call microcode.add_flags,blm_obj,-I$(microc_blocks_dir)/blm/_h))
$(eval $(call microcode.add_flags,blm_obj,-I$(microc_blocks_dir)/blm/_uc))

#
# Steer definition
#
$(eval $(call micro_c.compile_with_rtl,steer_obj,steer.c))
$(eval $(call micro_c.add_fw_libs,steer_obj,nfp pkt std net))
$(eval $(call micro_c.add_flags,steer_obj,-I$(microc_blocks_dir)/blm))
$(eval $(call micro_c.add_src_lib,steer_obj,libblm,$(microc_blocks_dir)/blm))
$(eval $(call micro_c.force_include,steer_obj,config))

#
# NAT worker definition
#
$(eval $(call micro_c.compile_with_rtl,nat_obj,nat_worker.c))
$(eval $(call micro_c.add_fw_libs,nat_obj,nfp std pkt net))

$(eval $(call micro_c.compile_with_rtl,syn_obj,syn_worker.c))
$(eval $(call micro_c.add_fw_libs,syn_obj,nfp std pkt net))

$(eval $(call fw.add_obj,steer,steer_obj,i32.me0 i32.me1 i32.me2 i32.me3 i32.me4 i32.me5 i32.me6 i32.me7 i32.me8 i32.me9 i32.me10 i32.me11))
$(eval $(call fw.add_obj,steer,nat_obj,i33.me0 i33.me1 i33.me2 i33.me3 i33.me4 i33.me5 i33.me6 i33.me7 i33.me8 i33.me9 i33.me10 i33.me11 i34.me0 i34.me1 i34.me2 i34.me3 i34.me4 i34.me5 i34.me6 i34.me7 i34.me8 i34.me9 i34.me10 i34.me11 i35.me0 i35.me1 i35.me2 i35.me3 i35.me4 i35.me5 i35.me6 i35.me7 i35.me8 i35.me9 i35.me10 i35.me11 i36.me0 i36.me1 i36.me2 i36.me3 i36.me4 i36.me5 i36.me6 i36.me7 i36.me8 i36.me9 i36.me10 i36.me11))
$(eval $(call fw.add_obj,steer,blm_obj,i48.me0))
$(eval $(call fw.link_with_rtsyms,steer))
$(eval $(call fw.add_ppc,steer,i8,$(PICO_CODE)))

#
# Debug
#
-include $(scripts_dir)/Makefile.debug
-include Makefile.debug
