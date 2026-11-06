"""Recalculate article-2 statistics from archived data; no simulations."""
from pathlib import Path
import json, hashlib, itertools, ast
import numpy as np
import pandas as pd
from scipy.stats import wilcoxon, rankdata
import os
R=Path(os.environ.get('AUDIT_RESEARCH_ROOT',str(Path(__file__).resolve().parents[1]/'source')))
O=Path(os.environ.get('AUDIT_OUTPUT_DIR', str(Path(__file__).resolve().parents[1]/'generated/audit'))).resolve(); O.mkdir(parents=True,exist_ok=True)
summary={}; tests=[]; curves={}; raw={}; manifest=[]
for s in ['S3','S3B_irreversibility','S3C_attack_rules']:
 d=pd.read_csv(R/f'results/raw/{s}/raw_results.csv'); q=pd.read_parquet(R/f'results/raw/{s}/Q_curves.parquet'); raw[s]=d
 w=q.pivot(index='run_id',columns='t',values='Q').sort_index(axis=1);curves[s]=w
 expected=w.mean(axis=1).reindex(d.run_id).to_numpy()
 rb=w.min(axis=1).reindex(d.run_id).to_numpy()
 final=w[100].reindex(d.run_id).to_numpy()
 summary[s]={'rows':len(d),'valid':int(d.valid.sum()),'q_rows':len(q),'points_per_run':q.groupby('run_id').size().unique().tolist(),'rho_max_error':float(np.max(abs(expected-d.rho))),'R_rb_max_error':float(np.max(abs(rb-d.R_rb))),'R_inf_vs_final_max_error':float(np.max(abs(final-d.R_inf))),'Q0_range':[float(w[0].min()),float(w[0].max())],'nonrec_mismatch':int(((final<.95)!=d.non_recovered).sum()),'k_values':d.groupby('attack_fraction').k_attack.unique().apply(list).to_dict()}
 # numerical paired checks
 cols=['seed','F0','k_attack'] if s=='S3' else ['network_seed','damage_seed','recovery_seed','irreversible_seed','F0','k_attack']
 groups=['paired_id'] if s!='S3B_irreversibility' else ['paired_id','w']
 summary[s]['paired_mismatches']={c:int((d.groupby(groups)[c].nunique()>1).sum()) for c in cols}
 summary[s]['duplicate_rows']=int(d.duplicated(['paired_id','w','disruption_mode','attack_rule']).sum())
 if s=='S3B_irreversibility':
  summary[s]['damage_sets_vary_across_w']=int((d.groupby(['paired_id','disruption_mode']).damaged_nodes.nunique()>1).sum())
  z=d[['attack_fraction','w','k_attack','n_irreversible','irreversible_fraction_realized']].drop_duplicates().sort_values(['attack_fraction','w']);z.to_csv(O/'realized_irreversibility.csv',index=False)
  summary[s]['rounding_mismatch']=int((d.n_irreversible!=np.floor(d.w*d.k_attack+.5)).sum())
 for p in [R/f'results/raw/{s}/raw_results.csv',R/f'results/raw/{s}/Q_curves.parquet',R/f'results/raw/{s}/run_metadata.json']:
  manifest.append({'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})

def testrow(left,right,metric,meta,family):
 a=left.set_index('paired_id')[metric];b=right.set_index('paired_id')[metric];a,b=a.align(b,join='inner');delta=a.to_numpy()-b.to_numpy()
 nz=delta[delta!=0]; ranks=rankdata(abs(nz))
 p=1. if np.allclose(delta,0) else float(wilcoxon(a,b,alternative='greater',zero_method='wilcox').pvalue)
 rb=0. if not len(nz) else float(np.sum(ranks*np.sign(nz))/sum(ranks))
 rng=np.random.default_rng(20261105); boot=np.median(rng.choice(delta,(5000,len(delta)),replace=True),axis=1)
 tests.append(dict(family=family,metric=metric,n_pairs=len(delta),n_nonzero=len(nz),p_value=p,median_delta=float(np.median(delta)),ci_low=float(np.quantile(boot,.025)),ci_high=float(np.quantile(boot,.975)),rank_biserial=rb,legacy_effect=float(np.median(delta)/np.std(delta,ddof=1)) if np.std(delta,ddof=1)>0 else 0.,**meta))
# base tests
for (h,q),g in raw['S3'].groupby(['h_hubs','attack_fraction']):
 testrow(g[g.disruption_mode=='random_fixed_k'],g[g.disruption_mode=='targeted'],'rho',{'h':h,'q':q},'B1')
# B2 from trajectories, independent of saved derived CSV
b2=[]
for T in [5,10,20,50,100]:
 d=raw['S3'].copy(); d['rho_early']=curves['S3'].loc[d.run_id,range(T+1)].mean(axis=1).to_numpy();d['Q0']=1.
 for (h,q),g in d.groupby(['h_hubs','attack_fraction']):
  l=g[g.disruption_mode=='random_fixed_k'];r=g[g.disruption_mode=='targeted']
  for m in ['rho_early','R_rb','Q0']:testrow(l,r,m,{'h':h,'q':q,'T':T},'B2')
  cv=lambda v: np.mean(np.sort(v)[:20])
  b2.append({'T':T,'h':h,'q':q,'VI_rho':1-r.rho_early.median()/l.rho_early.median(),'VI_CVaR':1-cv(r.rho_early)/cv(l.rho_early),'VI_Rrb':1-r.R_rb.median()/l.R_rb.median()})
b2=pd.DataFrame(b2);b2.to_csv(O/'B2_recomputed_indices.csv',index=False);summary['B2_means']=b2.groupby('T')[['VI_rho','VI_CVaR','VI_Rrb']].mean().round(9).to_dict('index')
for family,s,metrics in [('B3','S3B_irreversibility',['rho','rho_early_10','R_rb','R_inf']),('B4','S3C_attack_rules',['rho','rho_early_10','R_rb'])]:
 d=raw[s]
 groups=['h_hubs','attack_fraction','w'] if family=='B3' else ['h_hubs','attack_fraction']
 for key,g in d.groupby(groups):
  h,q=key[:2];l=g[g.disruption_mode=='random_fixed_k']
  for rule,r in g[g.disruption_mode=='targeted'].groupby('attack_rule'):
   for m in metrics:testrow(l,r,m,{'h':h,'q':q,'w':key[2] if family=='B3' else 0.,'rule':rule},family)
t=pd.DataFrame(tests)
t['p_adj']=t.p_value*t.family.map(t.family.value_counts());t.p_adj=t.p_adj.clip(upper=1);t.to_csv(O/'recomputed_paired_tests.csv',index=False)
summary['tests']={f:{'n':len(g),'significant':int((g.p_adj<.05).sum()),'p_adj_min':float(g.p_adj.min()),'p_adj_max':float(g.p_adj.max())} for f,g in t.groupby('family')}
# Compare existing extended statistical tables by h q w metric rule
for f,rel in [('B2','results/derived/S3A_early_metrics/early_metric_tests.csv'),('B3','results/aggregated/S3B_irreversibility/statistical_tests.csv'),('B4','results/aggregated/S3C_attack_rules/statistical_tests.csv')]:
 saved=pd.read_csv(R/rel);calc=t[t.family==f].copy();calc=calc.rename(columns={'h':'h_hubs','q':'attack_fraction','T':'T_eff','rule':'right'})
 keys=['h_hubs','attack_fraction','metric']+(['T_eff'] if f=='B2' else ['w'] if f=='B3' else ['right'])
 z=saved.merge(calc,on=keys,suffixes=('_saved','_calc'))
 summary[f+'_test_recheck']={'matched_rows':len(z),'max_p_error':float(abs(z.p_value_saved-z.p_value_calc).max()),'max_p_adj_error':float(abs(z.p_value_adj_bonferroni-z.p_adj).max())}
# Raw set Jaccard
c=raw['S3C_attack_rules'];p=c[c.disruption_mode=='targeted'].pivot(index='paired_id',columns='attack_rule',values='damaged_nodes'); jr=[]
for A,B in itertools.combinations(p.columns,2):
 for pid,row in p.iterrows():
  a=set(map(int,row[A].split(';')));b=set(map(int,row[B].split(';')));jr.append({'paired_id':pid,'A':A,'B':B,'J':len(a&b)/len(a|b),'identical':a==b})
jr=pd.DataFrame(jr);jr.to_csv(O/'jaccard_per_pair.csv',index=False)
j=jr.groupby(['A','B']).agg(n=('J','size'),mean=('J','mean'),median=('J','median'),minimum=('J','min'),identical_fraction=('identical','mean')).reset_index();j.to_csv(O/'jaccard_summary.csv',index=False);summary['jaccard']=j.to_dict('records')
# recompute config aggregates and VI to verify manuscript tables
for s in ['S3','S3B_irreversibility','S3C_attack_rules']:
 d=raw[s]; groups=['h_hubs','attack_fraction','w','disruption_mode','attack_rule'];rows=[]
 for key,g in d.groupby(groups):
  z=dict(zip(groups,key));z['rho_med']=g.rho.median();z['rho_CVaR']=np.sort(g.rho)[:20].mean();z['R_rb_med']=g.R_rb.median();z['R_inf_med']=g.R_inf.median();z['non_rec']=g.non_recovered.mean();rows.append(z)
 a=pd.DataFrame(rows);a.to_csv(O/(s+'_recomputed_aggregates.csv'),index=False)
 l=a[a.disruption_mode=='random_fixed_k'];r=a[a.disruption_mode=='targeted'];v=l.merge(r,on=['h_hubs','attack_fraction','w'],suffixes=('_random','_targeted'))
 for m in ['rho_med','rho_CVaR','R_rb_med','R_inf_med']:v['VI_'+m]=1-v[m+'_targeted']/v[m+'_random']
 v.to_csv(O/(s+'_VI.csv'),index=False)
 gb='attack_fraction' if s=='S3' else 'w' if s.startswith('S3B') else 'attack_rule_targeted'
 summary[s+'_VI']=v.groupby(gb)[['VI_rho_med','VI_rho_CVaR','VI_R_rb_med','VI_R_inf_med']].mean().to_dict('index')
 if s.startswith('S3B'):summary['B3_metric_means']=a.groupby(['w','disruption_mode'])[['rho_med','rho_CVaR','R_rb_med','R_inf_med','non_rec']].mean().reset_index().to_dict('records')
pd.DataFrame(manifest).to_csv(O/'source_manifest.csv',index=False)
(O/'audit_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2,default=lambda x:int(x) if isinstance(x,np.integer) else float(x)))
print(json.dumps(summary,ensure_ascii=False,indent=2,default=lambda x:int(x) if isinstance(x,np.integer) else float(x)))
