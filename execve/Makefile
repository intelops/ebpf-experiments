SRC=cmd
exe=execve
OUTPUT=exec

run: build
	sudo ./$(OUTPUT)/$(exe)

build: gen
	go build -o ./$(OUTPUT)/ ./$(SRC)/...

gen: 
	go generate ./...

.PHONY: clean


clean:
	rm -rf $(SRC)/*/*_bpfel.* $(SRC)/*/*_bpfeb.* $(SRC)/*/*.o ./$(OUTPUT)