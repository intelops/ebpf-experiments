SRC=cmd
exe=execve
OUTPUT=exec
HEADERS=headers
VMLINUX=vmlinux.h
INCLUDE=/usr/include

install:
	sudo apt update && sudo apt install golang clang llvm libelf-dev linux-tools-$(uname -r)

run: clear build
	sudo ./$(OUTPUT)/$(exe)

build: gen
	go build -o ./$(OUTPUT)/ ./$(SRC)/...

headers: cleanheaders bpf_helpers vmlinux

gen: 
	go generate ./...

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS)/$(VMLINUX)

bpf_helpers:
	cp $(INCLUDE)/bpf/bpf_helpers.h $(HEADERS)/bpf_helpers.h && cp $(INCLUDE)/bpf/bpf_helper_defs.h $(HEADERS)/bpf_helper_defs.h

cleanheaders:
	rm -f $(HEADERS)/*

clear:
	clear

.PHONY: clean

clean:
	rm -rf $(SRC)/*/*_bpfel.* $(SRC)/*/*_bpfeb.* $(SRC)/*/*.o ./$(OUTPUT)