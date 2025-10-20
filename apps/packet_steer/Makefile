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
# Preproc definition
#
$(eval $(call micro_c.compile_with_rtl,steer_obj,steer.c))
$(eval $(call micro_c.add_fw_libs,steer_obj,nfp pkt std net))
$(eval $(call micro_c.add_flags,steer_obj,-I$(microc_blocks_dir)/blm))
$(eval $(call micro_c.add_src_lib,steer_obj,libblm,$(microc_blocks_dir)/blm))
$(eval $(call micro_c.force_include,steer_obj,config))

# proc definition
$(eval $(call micro_c.compile_with_rtl,simple_tx_obj,simple_tx.c))
$(eval $(call micro_c.add_fw_libs,simple_tx_obj,nfp std pkt))

$(eval $(call fw.add_obj,steer,steer_obj,i32.me0))
$(eval $(call fw.add_obj,steer,simple_tx_obj,i33.me0))
$(eval $(call fw.add_obj,steer,blm_obj,i48.me0))
$(eval $(call fw.link_with_rtsyms,steer))
$(eval $(call fw.add_ppc,steer,i8,$(PICO_CODE)))

#
# Debug
#
-include $(scripts_dir)/Makefile.debug
-include Makefile.debug
