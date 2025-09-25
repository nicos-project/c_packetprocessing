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
# @file         apps/nat/Makefile
# @brief        Makefile for the ME nat app
#

# Define src_dir FIRST - it is the directory that this makefile resides in
# MUST OCCUR BEFORE ANY include's (which will change MAKEFILE_LIST)
app_src_dir     := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT_SRC_DIR  ?= $(realpath $(app_src_dir)/../..)
base_dir        := $(ROOT_SRC_DIR)

me_blocks_dir   := $(base_dir)/microc/blocks
me_libs_dir     := $(base_dir)/microc/lib
me_inc_dir      := $(base_dir)/microc/include
scripts_dir     := $(base_dir)/scripts

include $(scripts_dir)/Makefile.nfp.config
-include Makefile.nfp.config

all: nat.fw

#
# Flags and Options
#
# blm_custom. This should be removed once BLM and NFD have default config.
# Common NFAS flags
nat_NFASFLAGS += $(NFASFLAGS)
nat_NFASFLAGS +=  $(nat_APPDEFS) -DBLM_CUSTOM_CONFIG
nat_NFASFLAGS += -DNFP_LIB_ANY_NFAS_VERSION
nat_NFASFLAGS += \
	-I. \
	-I$(me_blocks_dir) \
	-I$(me_inc_dir) \
	-I$(me_libs_dir) \
	-I$(NFP_STD_LIB)/include \
	-I$(NFP_STD_LIB)/microcode/include \
	-I$(NFP_STD_LIB)/microcode/src

# Common NFCC flags
nat_NFCCFLAGS += $(NFCCFLAGS)
nat_NFCCFLAGS += -Qnctx_mode=8
nat_NFCCFLAGS += -FI config.h
nat_NFCCFLAGS += $(nat_APPDEFS) -DBLM_CUSTOM_CONFIG
nat_NFCCFLAGS += \
	-I. \
	-I$(app_src_dir) \
	-I$(me_inc_dir) \
	-I$(me_libs_dir) \
	-I$(me_blocks_dir)/blm \
	-I$(me_blocks_dir)/blm/_h \
	-I$(NFP_STD_LIB)/include \
	-I$(NFP_STD_LIB)/microcode/include

# Additional MicroC source files (libraries)
nat_NFCCSRCS := \
	$(me_libs_dir)/nfp/libnfp.c \
	$(me_libs_dir)/pkt/libpkt.c \
	$(me_libs_dir)/std/libstd.c \
	$(me_libs_dir)/net/libnet.c \
	$(NFP_STD_LIB)/microc/src/rtl.c

# Common NFLD flags
nat_NFLDFLAGS += -rtsyms -mip -chip $(CHIP)

nat_LIST_FILES :=

#
# Infrastructure blocks
#

# BLM
BLM_DEFS := -DBLM_CUSTOM_CONFIG -DSINGLE_NBI -DPKT_NBI_OFFSET=$(PKT_NBI_OFFSET)
BLM_DEFS += -DBLM_BLQ_EMEM_TYPE=emem -DNBII=8 -DBLM_INSTANCE_ID=0
BLM_DEFS += -DBLM_INIT_EMU_RINGS

ME_BLM_SRC  := $(me_blocks_dir)/blm/blm_main.uc
ME_BLM_LIST := blm.list
ME_BLM_DEFS := $(nat_NFASFLAGS) $(BLM_DEFS) -I. \
	-I$(app_src_dir) \
	-I$(me_blocks_dir)/blm/ \
	-I$(me_blocks_dir)/blm/_h \
	-I$(me_blocks_dir)/blm/_uc
$(ME_BLM_LIST): $(ME_BLM_SRC)
	@echo "--- Building $@"
	$(Q) $(NFAS) $(ME_BLM_DEFS) -o $@ $<
nat_LIST_FILES += $(ME_BLM_LIST)


#
# Application
#
NAT_SRCS := $(app_src_dir)/nat_main.c
NAT_LIST := nat_main.list
NAT_DEFS := $(nat_NFCCFLAGS)
$(NAT_LIST): $(nat_NFCCSRCS) $(NAT_SRCS)
	@echo "--- Building $@"
	$(Q) $(NFCC) $(NAT_DEFS) -Fe$@ $(NAT_SRCS) $(nat_NFCCSRCS)
nat_LIST_FILES += $(NAT_LIST)


#
# Help
#
.PHONY : app_nat_help
app_nat_help:
	@echo "Build Options:"
	@echo "   Q                unset to print compiler output"
	@echo ""
	@echo "Path Settings:"
	@echo "   NFP_SDK_DIR      SDK installation directory"
	@echo ""
	@echo "Targets:"
	@echo "   help             this text"
	@echo "   clean            removes compiled binaries"
	@echo ""
	@echo "   nat.fw          nat application (default)"
	@echo "   nat_dbg.fw      nat application with single app ME"
	@echo ""

#
# Build
#
nat_dbg.fw: $(nat_LIST_FILES)
	@echo "--- Linking $@"
	$(NFLD) $(nat_NFLDFLAGS) \
	-elf $@ \
	-u mei0.me0 -l $(NAT_LIST) \
	-u mei1.me0 -l $(NAT_LIST) \
	-u ila0.me0 -l $(ME_BLM_LIST) \
	-i i8 -e $(PICO_CODE)

nat.fw: $(nat_LIST_FILES)
	@echo "--- Linking $@"
	$(NFLD) $(nat_NFLDFLAGS) \
	-elf $@ \
	-u mei0.me0 -l $(NAT_LIST) \
	-u ila0.me0 -l $(ME_BLM_LIST) \
	-i i8 -e $(PICO_CODE)

clean:
	rm -f *.list
	rm -f *.uci
	rm -f *.ucp
	rm -f *.obj
	rm -f nat.fw
	rm -f nat_dbg.fw
	rm -f 1

distclean: clean
