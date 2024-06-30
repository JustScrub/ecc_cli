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
    benches = i.getmembers(time_benchmarks, i.isfunction)
    res = ""
    for name, func in benches:
        res += func(reps=100_000)

    res2 = {}
    ind = ["ecpy","ecc"]
    for r in res.strip().split('\n'):
        lib,bench,t = r.split(',')
        if bench not in res2:
            res2[bench] = ['','']
        res2[bench][ind.index(lib)] = float(t)

    if len(sys.argv) > 1 and sys.argv[1] == "csv":
        print(data_to_csv(res2))

    print(data_to_latex_table(res2))

