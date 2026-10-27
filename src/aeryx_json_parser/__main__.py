from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .pipeline import run_pipeline, DEFAULT_CONFIG, DEFAULT_SOURCES

def main() -> int:
    p=argparse.ArgumentParser(prog="AeryxJSON-Parser",description="AeryxVPN single JSON subscription parser with country groups and native balancers")
    p.add_argument("--config",type=Path,default=DEFAULT_CONFIG,help="settings YAML")
    p.add_argument("--sources",type=Path,default=DEFAULT_SOURCES,help="source list (TXT: URL per line, optional | Header: value) or legacy YAML")
    p.add_argument("--check",choices=("proxy","tcp","none"),default=None,help="proxy=tunnel test (requires Xray/sing-box), tcp=diagnostic only, none=parse only")
    p.add_argument("--workers",type=int,default=None,help="validation workers (1..96)")
    p.add_argument("--max-runtime",type=int,default=None,help="hard global runtime budget in seconds")
    p.add_argument("--skip-blocklist",action="store_true",help="skip optional external CIDR feeds; non-public IPs remain filtered")
    p.add_argument("--force-publish",action="store_true",help="override output safety threshold; use only after reviewing report")
    p.add_argument("--no-routing-refresh",action="store_true",help="do not update Happ routing timestamp/deeplink")
    args=p.parse_args()
    try:
        report=run_pipeline(args.config,args.sources,args.check,args.workers,args.max_runtime,args.skip_blocklist,args.force_publish,not args.no_routing_refresh)
    except KeyboardInterrupt:
        print("Interrupted; existing final subscription is preserved.",file=sys.stderr); return 130
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}",file=sys.stderr); return 2
    counts=report.get("counts",{})
    print(json.dumps({"publish":report.get("publish",{}).get("status","not_published"),"unique_nodes":counts.get("unique_nodes",0),
                      "candidate_nodes":counts.get("candidate_nodes",0),"elapsed_seconds":counts.get("total_elapsed_seconds"),
                      "report":"output/validation_report.json"},ensure_ascii=False,indent=2))
    if not counts.get("unique_nodes"): return 1
    if report.get("publish",{}).get("status","").startswith("safety_stop"): return 3
    return 0

if __name__=="__main__": raise SystemExit(main())
