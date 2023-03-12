#Compiler and Linker (LLVM)
DPU_CC      := dpu-upmem-dpurte-clang
#pkg-config configuration helper tool
PKG_CONFIG  ?= dpu-pkg-config

BUILDDIR ?= build

DPU_SRCS    := bench_keccakf_dpu.c
HOST_SRCS   := app_host.c
COMMON_INC  := keccakf_dpu_params.h

#The DPU target binary
DPU_EXE     := $(BUILDDIR)/dpu_keccakf
#The Host launcher binary
HOST_EXE    := $(BUILDDIR)/host_keccakf

LDFLAGS :=-lssl -lcrypto

OUTPUT_FILE := $(BUILDDIR)/output.txt
PLOTDATA_FILE := $(BUILDDIR)/plotdata.csv

NR_TASKLETS := 16

#Flags, Libraries and Includes
DPU_CFLAGS  := -Wall -O2 -g -DNR_TASKLETS=$(NR_TASKLETS)
HOST_CFLAGS := -std=c11 -Wall -O3 -g -DNR_TASKLETS=$(NR_TASKLETS) -DDPU_BINARY="\"$(DPU_EXE)\"" $(shell $(PKG_CONFIG) --cflags dpu)
HOST_LIB    := $(shell $(PKG_CONFIG) --libs dpu)

# Ensure directories exist
__dirs := $(shell mkdir -p $(BUILDDIR))

.DEFAULT_GOAL := all

all: $(HOST_EXE) $(DPU_EXE)

run: all
	@$(shell readlink -f $(HOST_EXE)) 0 256 128 > ${OUTPUT_FILE}
	cat ${OUTPUT_FILE}

check:
	cat ${OUTPUT_FILE} | grep "DPU fkey" | sed 's/^.*SUM= \([^ ]*\) .*$$/\1/' | diff -y --suppress-common-lines ./keccakf_ref_sum.txt -

plotdata:
	echo "Mks/dpu" > ${PLOTDATA_FILE}
	cat ${OUTPUT_FILE} | grep "DPU fkey" | sed 's/^.*Mks= \(.*\)$$/\1/' >> ${PLOTDATA_FILE}

CHECK_FORMAT_FILES=$(DPU_SRCS) $(HOST_SRCS) $(COMMON_INC)
CHECK_FORMAT_DEPENDENCIES=$(addsuffix -check-format,${CHECK_FORMAT_FILES})

%-check-format: %
	clang-format $< | diff -y --suppress-common-lines $< -

check-format: ${CHECK_FORMAT_DEPENDENCIES}

#Dpu binary
$(DPU_EXE): $(DPU_SRCS) $(COMMON_INC)
	$(DPU_CC) $(DPU_CFLAGS) -o $@ $(DPU_SRCS)

#Host binary
$(HOST_EXE): $(HOST_SRCS) $(COMMON_INC)
	$(CC) $(HOST_CFLAGS) -o $@ $(HOST_SRCS) $(HOST_LIB) $(LDFLAGS)

clean:
	@$(RM) -rf $(BUILDDIR)

.PHONY: all clean run check plotdata check-format
