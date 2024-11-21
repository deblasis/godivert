# Detect the operating system
ifeq ($(OS),Windows_NT)
    SHELL := powershell.exe
    .SHELLFLAGS := -NoProfile -Command
endif

OLD := bench_baseline.txt
NEW := bench_new.txt

.PHONY: bench-compare
bench-compare:
ifeq ($(OS),Windows_NT)
	@if (-not (Test-Path $(OLD))) { \
		Write-Host "Missing old benchmark file. Run: make bench-save first"; \
		exit 1; \
	}
else
	@if [ ! -f $(OLD) ]; then \
		echo "Missing old benchmark file. Run: make bench-save first"; \
		exit 1; \
	fi
endif
	@go test -run=^$$ -bench=BenchmarkSuite -count=20 > $(NEW)
	@dos2unix $(OLD)
	@dos2unix $(NEW)
	@benchstat $(OLD) $(NEW)

.PHONY: bench-save
bench-save:
	@go test -run=^$$ -bench=BenchmarkSuite -count=20 > $(OLD)
	@dos2unix $(OLD)
	@echo "Saved benchmark results to $(OLD)"

.PHONY: test
test:
	@go test -v ./...
