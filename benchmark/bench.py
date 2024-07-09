import inspect as i
import time_benchmarks as time_benchmarks
import sys

def data_to_latex_table(data):
    # data: { "benchmark": [ecpy_time, ecc_time] }
    tab_templ = """
    \\begin{table}[!ht]
        \\centering
        \\begin{tabular}{|c|c|c|}
            \\hline
%s
        \\end{tabular}
    \\end{table}"""

    header = "benchmark & ecpy [ns] & ecc [ns] \\\\ \\hline"
    rows = []
    for k,v in data.items():
        rows.append(f"{k} & {v[0]:,.2f} & {v[1]:,.2f} \\\\")
    return tab_templ % ('\n'.join([header] + rows))

def data_to_csv(data):
    res = "benchmark;ecpy [ns];ecc [ns]\n"
    for k,v in data.items():
        res += f"{k};{v[0]:,.2f};{v[1]:,.2f}\n"
    return res
    

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python bench.py <n_reps> [-c=csv_file] [-l=latex_file]")
        print("<n_reps> is the number of repetitions for each benchmark.")
        print("Optional arguments:")
        print("  -c=csv_file: write the results to a csv file.")
        print("  -l=latex_file: write the results to a latex table.")
        print("If no optional arguments are provided, the results are printed to the console.")
        sys.exit(1)

    try:
        reps = int(sys.argv[1])
    except ValueError:
        print("Invalid number of repetitions.")
        sys.exit(1)

    benches = i.getmembers(time_benchmarks, i.isfunction)
    res = ""
    for name, func in benches:
        res += func(reps=reps)

    res2 = {}
    ind = ["ecpy","ecc"]
    for r in res.strip().split('\n'):
        lib,bench,t = r.split(',')
        if bench not in res2:
            res2[bench] = ['','']
        res2[bench][ind.index(lib)] = float(t)

    if len(sys.argv) == 2:
        print(data_to_csv(res2))

    csv_files = [f for f in sys.argv[2:] if f.startswith('-c=')]
    latex_files = [f for f in sys.argv[2:] if f.startswith('-l=')]
    for f in csv_files:
        with open(f[3:], 'w') as file:
            file.write(data_to_csv(res2))
    for f in latex_files:
        with open(f[3:], 'w') as file:
            file.write(data_to_latex_table(res2))

