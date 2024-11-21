.PHONY: bench-compare
bench-compare:
	@if [ ! -f $(OLD) ]; then \
		echo "Missing old benchmark file. Run: make bench-save first"; \
		exit 1; \
	fi
	@go test -run=^$$ -bench=BenchmarkSuite > $(NEW)
	@benchstat $(OLD) $(NEW)

.PHONY: bench-save
bench-save:
	@go test -run=^$$ -bench=BenchmarkSuite > bench_baseline.txt
	@echo "Saved benchmark results to bench_baseline.txt"

# Add a Windows-specific target
.PHONY: bench-save-win
bench-save-win:
	@go test -run=^$$ -bench=BenchmarkSuite > bench_baseline.txt
	@echo "Saved benchmark results to bench_baseline.txt"