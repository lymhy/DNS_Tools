# dnspick 构建脚本（Windows Git Bash / Linux / macOS）
# 需要本机有 go 1.22+（或修改 GO 指向便携版路径）

GO ?= go

.PHONY: build test full quick vet clean

build:
	$(GO) build -o dnspick$(shell $(GO) env GOEXE 2>/dev/null || echo "") ./cmd/dnspick

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# 完整模式（写死 exe 名，Windows 友好）
full: build
	./dnspick.exe --full

quick: build
	./dnspick.exe

clean:
	rm -f dnspick.exe dnspick r.json r.csv
