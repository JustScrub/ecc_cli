import inspect as i
import benchmarks

if __name__ == "__main__":
    benches = i.getmembers(benchmarks, i.isfunction)
    for name, func in benches:
        print(f"Running {name}...")
        func()
        print()