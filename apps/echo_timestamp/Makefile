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
# @file         apps/echo/Makefile
# @brief        Makefile for the ME echo app
#

# Define src_dir FIRST - it is the directory that this makefile resides in
# MUST OCCUR BEFORE ANY include's (which will change MAKEFILE_LIST)
app_src_dir     := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT_SRC_DIR  ?= $(realpath $(app_src_dir)/../..)
base_dir        := $(ROOT_SRC_DIR)

me_blocks_dir   := $(base_dir)/external/flowenv/me/blocks
me_libs_dir     := $(base_dir)/external/flowenv/me/lib
me_inc_dir      := $(base_dir)/external/flowenv/me/include
scripts_dir     := $(base_dir)/scripts

include $(scripts_dir)/Makefile.nfp.config
-include Makefile.nfp.config

all: echo.fw

#
# Flags and Options
#
# blm_custom. This should be removed once BLM and NFD have default config.
# Common NFAS flags
echo_NFASFLAGS += $(NFASFLAGS)
echo_NFASFLAGS +=  $(echo_APPDEFS) -DBLM_CUSTOM_CONFIG
echo_NFASFLAGS += -DNFP_LIB_ANY_NFAS_VERSION
echo_NFASFLAGS += \
	-I. \
	-I$(me_blocks_dir) \
	-I$(me_inc_dir) \
	-I$(me_libs_dir) \
	-I$(NFP_STD_LIB)/include \
	-I$(NFP_STD_LIB)/microcode/include \
	-I$(NFP_STD_LIB)/microcode/src

# Common NFCC flags
echo_NFCCFLAGS += $(NFCCFLAGS)
echo_NFCCFLAGS += -Qnctx_mode=8
echo_NFCCFLAGS += -FI config.h
echo_NFCCFLAGS += $(echo_APPDEFS) -DBLM_CUSTOM_CONFIG
echo_NFCCFLAGS += \
	-I. \
	-I$(app_src_dir) \
	-I$(me_inc_dir) \
	-I$(me_libs_dir) \
	-I$(me_blocks_dir)/blm \
	-I$(me_blocks_dir)/blm/_h \
	-I$(NFP_STD_LIB)/include \
	-I$(NFP_STD_LIB)/microcode/include

# Additional MicroC source files (libraries)
echo_NFCCSRCS := \
	$(me_libs_dir)/nfp/libnfp.c \
	$(me_libs_dir)/pkt/libpkt.c \
	$(me_libs_dir)/std/libstd.c \
	$(me_libs_dir)/net/libnet.c \
	$(NFP_STD_LIB)/microc/src/rtl.c

# Common NFLD flags
echo_NFLDFLAGS += -rtsyms -mip -chip $(CHIP)

echo_LIST_FILES :=

#
# Infrastructure blocks
#

# BLM
BLM_DEFS := -DBLM_CUSTOM_CONFIG -DSINGLE_NBI -DPKT_NBI_OFFSET=$(PKT_NBI_OFFSET)
BLM_DEFS += -DBLM_BLQ_EMEM_TYPE=emem -DNBII=8 -DBLM_INSTANCE_ID=0
BLM_DEFS += -DBLM_INIT_EMU_RINGS

ME_BLM_SRC  := $(me_blocks_dir)/blm/blm_main.uc
ME_BLM_LIST := blm.list
ME_BLM_DEFS := $(echo_NFASFLAGS) $(BLM_DEFS) -I. \
	-I$(app_src_dir) \
	-I$(me_blocks_dir)/blm/ \
	-I$(me_blocks_dir)/blm/_h \
	-I$(me_blocks_dir)/blm/_uc
$(ME_BLM_LIST): $(ME_BLM_SRC)
	@echo "--- Building $@"
	$(Q) $(NFAS) $(ME_BLM_DEFS) -o $@ $<
echo_LIST_FILES += $(ME_BLM_LIST)


#
# Application
#
echo_SRCS := $(app_src_dir)/echo_main.c
echo_LIST := echo_main.list
echo_DEFS := $(echo_NFCCFLAGS)
$(echo_LIST): $(echo_NFCCSRCS) $(echo_SRCS)
	@echo "--- Building $@"
	$(Q) $(NFCC) $(echo_DEFS) -Fe$@ $(echo_SRCS) $(echo_NFCCSRCS)
echo_LIST_FILES += $(echo_LIST)


#
# Help
#
.PHONY : app_echo_help
app_echo_help:
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
	@echo "   echo.fw          echo application (default)"
	@echo "   echo_dbg.fw      echo application with single app ME"
	@echo ""

#
# Build
#
echo_dbg.fw: $(echo_LIST_FILES)
	@echo "--- Linking $@"
	$(NFLD) $(echo_NFLDFLAGS) \
	-elf $@ \
	-u mei0.me0 -l $(echo_LIST) \
	-u mei1.me0 -l $(echo_LIST) \
	-u ila0.me0 -l $(ME_BLM_LIST) \
	-i i8 -e $(PICO_CODE)

echo.fw: $(echo_LIST_FILES)
	@echo "--- Linking $@"
	$(NFLD) $(echo_NFLDFLAGS) \
	-elf $@ \
	-u mei0.me0 -l $(echo_LIST) \
	-u mei0.me1 -l $(echo_LIST) \
	-u mei0.me2 -l $(echo_LIST) \
	-u mei0.me3 -l $(echo_LIST) \
	-u mei0.me4 -l $(echo_LIST) \
	-u mei0.me5 -l $(echo_LIST) \
	-u mei0.me6 -l $(echo_LIST) \
	-u mei0.me7 -l $(echo_LIST) \
	-u mei0.me8 -l $(echo_LIST) \
	-u mei0.me9 -l $(echo_LIST) \
	-u mei0.me10 -l $(echo_LIST) \
	-u mei0.me11 -l $(echo_LIST) \
	-u mei1.me0 -l $(echo_LIST) \
	-u mei1.me1 -l $(echo_LIST) \
	-u mei1.me2 -l $(echo_LIST) \
	-u mei1.me3 -l $(echo_LIST) \
	-u mei1.me4 -l $(echo_LIST) \
	-u mei1.me5 -l $(echo_LIST) \
	-u mei1.me6 -l $(echo_LIST) \
	-u mei1.me7 -l $(echo_LIST) \
	-u mei1.me8 -l $(echo_LIST) \
	-u mei1.me9 -l $(echo_LIST) \
	-u mei1.me10 -l $(echo_LIST) \
	-u mei1.me11 -l $(echo_LIST) \
	-u mei2.me0 -l $(echo_LIST) \
	-u mei2.me1 -l $(echo_LIST) \
	-u mei2.me2 -l $(echo_LIST) \
	-u mei2.me3 -l $(echo_LIST) \
	-u mei2.me4 -l $(echo_LIST) \
	-u mei2.me5 -l $(echo_LIST) \
	-u mei2.me6 -l $(echo_LIST) \
	-u mei2.me7 -l $(echo_LIST) \
	-u mei2.me8 -l $(echo_LIST) \
	-u mei2.me9 -l $(echo_LIST) \
	-u mei2.me10 -l $(echo_LIST) \
	-u mei2.me11 -l $(echo_LIST) \
	-u ila0.me0 -l $(ME_BLM_LIST) \
	-i i8 -e $(PICO_CODE)

clean:
	rm -f *.list
	rm -f *.uci
	rm -f *.ucp
	rm -f *.obj
	rm -f echo.fw
	rm -f echo_dbg.fw
	rm -f 1

distclean: clean
