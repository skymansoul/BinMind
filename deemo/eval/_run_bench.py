import os,sys,time,json
sys.path.insert(0,".")
try:
    from analysis.taint_propagation import detect_heap_overflow
    from analysis.int_overflow_detector import detect_int_overflow
    from analysis.double_free_analyzer import detect_double_free
    from analysis.uaf_alias_analyzer import detect_uaf_with_aliases
except ImportError:
    print("analysis modules not available")
    sys.exit(1)
results=[]
for sd in ["tests/heap_samples","tests/integer_samples"]:
    if not os.path.isdir(sd): continue
    for d in sorted(os.listdir(sd)):
        dp=os.path.join(sd,d)
        if not os.path.isdir(dp): continue
        sp=os.path.join(dp,"vuln.c")
        if not os.path.isfile(sp): continue
        with open(sp) as fh: src=fh.read()
        t0=time.time()
        hf=detect_heap_overflow(src,d)
        inf=detect_int_overflow(src,d)
        df=detect_double_free(src,d)
        uf=detect_uaf_with_aliases(src,d)
        dt=round(time.time()-t0,3)
        results.append({"sample":d,"heap":len(hf),"int_ovf":len(inf),"df":len(df),"uaf":len(uf),"time_s":dt})
total=len(results)
det=sum(1 for r in results if r["heap"]+r["int_ovf"]+r["df"]+r["uaf"]>0)
print(f"Scanned {total}: {det} with findings ({100*det//max(total,1)}%)")
with open("eval/benchmark_results.csv","w") as fh:
    fh.write("sample,heap,int_overflow,double_free,uaf,time_s" + chr(10))
    for r in results:
        ln = r["sample"]+","+str(r["heap"])+","+str(r["int_ovf"])+","+str(r["df"])+","+str(r["uaf"])+","+str(r["time_s"])
        fh.write(ln + chr(10))
print("Saved CSV")
