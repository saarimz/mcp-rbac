import json,sys,collections,os
for f in sys.argv[1:]:
    d=json.load(open(f))
    nodes={n['id']:n for n in d['nodes']}
    dt=collections.Counter()
    for s,t in zip(d['samples'],d['timeDeltas']): dt[s]+=t
    total=sum(dt.values())
    self_=collections.Counter(); byfile=collections.Counter()
    for nid,t in dt.items():
        cf=nodes[nid]['callFrame']; u=cf['url'].split('/node_modules/')[-1] if '/node_modules/' in cf['url'] else cf['url'].replace('file:///workspace/mcp-guard/','')
        self_[(cf['functionName'] or '(anon)')+' '+u+':'+str(cf['lineNumber'])]+=t
        pkg=u.split('/')[0] if '/node_modules/' in cf['url'] else (u or cf['functionName'])
        if u.startswith('@'): pkg='/'.join(u.split('/')[:2])
        byfile[pkg]+=t
    idle=self_.most_common()
    print("=====",os.path.basename(f), "total ms",total//1000)
    for k,v in byfile.most_common(14): print(f"  {100*v/total:5.1f}% {k}")
    print("  -- top self")
    for k,v in self_.most_common(22): print(f"  {100*v/total:5.1f}% {k[:150]}")
