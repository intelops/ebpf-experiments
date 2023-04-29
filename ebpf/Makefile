SRC=pkg/ebpf
exe=main
EXECUTABLE=bin
HEADERS_PATH=headers
VMLINUX=vmlinux.h
INCLUDE=/usr/include
DEPENDENCIEs= golang clang llvm libelf-dev linux-tools-$(uname -r)
HEADERS_FILES = bpf_helpers bpf_helper_defs bpf_endian

run: clear execute

dev_run: clear build execute

install:
	sudo apt update && sudo apt install $(DEPENDENCIEs)

uninstall:
	sudo apt remove $(DEPENDENCIEs)

build: gen
	go build -o ./$(EXECUTABLE)/ ./...

restore_config: 
	go run pkg/config/config/main.go

headers: cleanheaders bpf_helpers vmlinux

gen: 
	go generate ./...

execute:
	sudo ./$(EXECUTABLE)/$(exe)

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS_PATH)/$(VMLINUX)

bpf_helpers:
	for file in $(HEADERS_FILES) ; do \
		cp $(INCLUDE)/bpf/$${file}.h $(HEADERS_PATH)/$${file}.h; \
	done

cleanheaders:
	rm -f $(HEADERS_PATH)/*

clear:
	clear

.PHONY: clean clean_obj

clean:
	rm -rf $(SRC)/*/*/*_bpfel.* $(SRC)/*/*/*_bpfeb.* $(SRC)/*/*.o ./$(EXECUTABLE)

clean_obj:
	rm -rf ./$(EXECUTABLE) && \
	find -type f -name *.o -delete