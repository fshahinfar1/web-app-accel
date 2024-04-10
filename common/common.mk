CC ?= g++
CFLAGS ?= -g -O2 -Wall -std=c++20
LINK ?= -lpthread
SOURCE ?= $(wildcard *.cpp)
OUTDIR ?= ./build/
BINARY ?= main
OUTPUT := $(addprefix ${OUTDIR}, ${BINARY})

ifndef YAML
$(error the YAML variable pointing to the file describing build config is not defined)
endif

ifndef KASHK_DIR
$(error the KASHK_DIR variable is not set)
endif
BPF_GEN_DIR=$(KASHK_DIR)
BPF_GEN=$(KASHK_DIR)/bpf_gen.sh
BPF_COMPILE_SCRIPT=$(BPF_GEN_DIR)/compile_scripts/compile_bpf_source.sh

$(info "output dir: ${OUTPUT}")

BPF_GENERATED_FILE=$(shell cat $(YAML) | grep out_bpf | cut -d ':' -f 2 | tr -d "[ ']" )
BPF_BINARY=$(BPF_GENERATED_FILE:.c=.o)
# $(info "bpf binary: $(BPF_BINARY)")

default: ${OUTPUT}

${OUTDIR}:
	mkdir -p ${OUTDIR}

${OUTPUT}: ${OUTDIR} ${SOURCE}
	${CC} ${CFLAGS} ${SOURCE} -o $@ ${LINK}

clean:
	rm -r ${OUTDIR}/

# Generate BPF program automatically
bpf_gen: ${OUTDIR}
	bash $(BPF_GEN) $(YAML)

# Compile the auto-generate BPF program
bpf_comp:
	export CFLAGS="$(BPF_CFLAGS)" && bash $(BPF_COMPILE_SCRIPT) $(BPF_GENERATED_FILE) $(BPF_BINARY)

bpf_load:
	bash $(BPF_GEN_DIR)/compile_scripts/load.sh $(BPF_BINARY)

bpf_run: $(BPF_BINARY)
	@if [ -z "$(NET_IFACE)" ]; then echo "Missing the NET_IFACE"; exit 1; fi
	@# TODO: check if it is xdp/skskb from the $(YAML) file
	sudo $(BPF_GEN_DIR)/compile_scripts/loader -b $(BPF_BINARY) -i $(NET_IFACE) --xdp xdp_prog

bpf_crun: bpf_comp bpf_run

