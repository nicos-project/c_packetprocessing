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
# @file         apps/firewall/Makefile
# @brief        Makefile for the ME firewall app
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

all: firewall.fw

#
# Flags and Options
#
# blm_custom. This should be removed once BLM and NFD have default config.
# Common NFAS flags
FIREWALL_NFASFLAGS += $(NFASFLAGS)
FIREWALL_NFASFLAGS +=  $(FIREWALL_APPDEFS) -DBLM_CUSTOM_CONFIG
FIREWALL_NFASFLAGS += -DNFP_LIB_ANY_NFAS_VERSION
FIREWALL_NFASFLAGS += \
	-I. \
	-I$(me_blocks_dir) \
	-I$(me_inc_dir) \
	-I$(me_libs_dir) \
	-I$(NFP_STD_LIB)/include \
	-I$(NFP_STD_LIB)/microcode/include \
	-I$(NFP_STD_LIB)/microcode/src

# Common NFCC flags
FIREWALL_NFCCFLAGS += $(NFCCFLAGS)
FIREWALL_NFCCFLAGS += -Qnctx_mode=8
FIREWALL_NFCCFLAGS += -FI config.h
FIREWALL_NFCCFLAGS += $(FIREWALL_APPDEFS) -DBLM_CUSTOM_CONFIG
FIREWALL_NFCCFLAGS += \
	-I. \
	-I$(app_src_dir) \
	-I$(me_inc_dir) \
	-I$(me_libs_dir) \
	-I$(me_blocks_dir)/blm \
	-I$(me_blocks_dir)/blm/_h \
	-I$(NFP_STD_LIB)/include \
	-I$(NFP_STD_LIB)/microcode/include

# Additional MicroC source files (libraries)
FIREWALL_NFCCSRCS := \
	$(me_libs_dir)/nfp/libnfp.c \
	$(me_libs_dir)/pkt/libpkt.c \
	$(me_libs_dir)/std/libstd.c \
	$(me_libs_dir)/net/libnet.c \
	$(NFP_STD_LIB)/microc/src/rtl.c

# Common NFLD flags
FIREWALL_NFLDFLAGS += -rtsyms -mip -chip $(CHIP)

FIREWALL_LIST_FILES :=

#
# Infrastructure blocks
#

# BLM
BLM_DEFS := -DBLM_CUSTOM_CONFIG -DSINGLE_NBI -DPKT_NBI_OFFSET=$(PKT_NBI_OFFSET)
BLM_DEFS += -DBLM_BLQ_EMEM_TYPE=emem -DNBII=8 -DBLM_INSTANCE_ID=0
BLM_DEFS += -DBLM_INIT_EMU_RINGS

ME_BLM_SRC  := $(me_blocks_dir)/blm/blm_main.uc
ME_BLM_LIST := blm.list
ME_BLM_DEFS := $(FIREWALL_NFASFLAGS) $(BLM_DEFS) -I. \
	-I$(app_src_dir) \
	-I$(me_blocks_dir)/blm/ \
	-I$(me_blocks_dir)/blm/_h \
	-I$(me_blocks_dir)/blm/_uc
$(ME_BLM_LIST): $(ME_BLM_SRC)
	@echo "--- Building $@"
	$(Q) $(NFAS) $(ME_BLM_DEFS) -o $@ $<
FIREWALL_LIST_FILES += $(ME_BLM_LIST)


#
# Application
#
FIREWALL_SRCS := $(app_src_dir)/fw_main.c
FIREWALL_LIST := fw.list
FIREWALL_DEFS := $(FIREWALL_NFCCFLAGS)
$(FIREWALL_LIST): $(FIREWALL_NFCCSRCS) $(FIREWALL_SRCS)
	@echo "--- Building $@"
	$(Q) $(NFCC) $(FIREWALL_DEFS) -Fe$@ $(FIREWALL_SRCS) $(FIREWALL_NFCCSRCS)
FIREWALL_LIST_FILES += $(FIREWALL_LIST)


#
# Help
#
.PHONY : app_firewall_help
app_firewall_help:
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
	@echo "   firewall.fw          firewall application (default)"
	@echo "   firewall_dbg.fw      firewall application with single app ME"
	@echo ""

#
# Build
#
firewall_dbg.fw: $(FIREWALL_LIST_FILES)
	@echo "--- Linking $@"
	$(NFLD) $(FIREWALL_NFLDFLAGS) \
	-elf $@ \
	-u mei0.me0 -l $(FIREWALL_LIST) \
	-u mei1.me0 -l $(FIREWALL_LIST) \
	-u ila0.me0 -l $(ME_BLM_LIST) \
	-i i8 -e $(PICO_CODE)

firewall.fw: $(FIREWALL_LIST_FILES)
	@echo "--- Linking $@"
	$(NFLD) $(FIREWALL_NFLDFLAGS) \
	-elf $@ \
	-u mei0.me0 -l $(FIREWALL_LIST) \
	-u ila0.me0 -l $(ME_BLM_LIST) \
	-i i8 -e $(PICO_CODE)

clean:
	rm -f *.list
	rm -f *.uci
	rm -f *.ucp
	rm -f *.obj
	rm -f firewall.fw
	rm -f firewall_dbg.fw
	rm -f 1

distclean: clean
