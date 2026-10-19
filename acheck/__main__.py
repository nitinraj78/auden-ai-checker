"""Run: python3 -m acheck URL QUESTION --output ./review"""
import argparse,json,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
from .analyze import analyze,validate_question
from .fetch import Fetcher,CheckError,validate_url
from .report import render_html,render_text

def worker():
 try:
  data=json.loads(sys.stdin.read(8192));validate_url(data['url']);validate_question(data['question'])
  fetched=Fetcher().fetch(data['url']);body=fetched.pop('body')
  report={'captured_at':datetime.now(timezone.utc).isoformat(),'fetch':fetched,'analysis':analyze(body,data['question'])}
  print(json.dumps({'report':report},ensure_ascii=True));return 0
 except Exception:
  print(json.dumps({'error':'Fetch stopped: URL, DNS, robots, response, TLS or network validation failed. No report produced.'}));return 1

def main():
 if sys.argv[1:]==['--worker']:return worker()
 ap=argparse.ArgumentParser(description='Inspect one public HTTPS page against a question. No model or visibility score.')
 ap.add_argument('url');ap.add_argument('question');ap.add_argument('--output',default='page-check-review');args=ap.parse_args()
 try:validate_url(args.url);validate_question(args.question)
 except (CheckError,ValueError) as e:print(str(e),file=sys.stderr);return 2
 try:
  done=subprocess.run([sys.executable,'-m','acheck','--worker'],input=json.dumps({'url':args.url,'question':args.question}),capture_output=True,text=True,timeout=20)
 except subprocess.TimeoutExpired:print('Fetch stopped at the 20-second deadline.',file=sys.stderr);return 2
 try:payload=json.loads(done.stdout)
 except (ValueError,TypeError):print('Worker failed without a valid report.',file=sys.stderr);return 2
 if 'error'in payload:print(payload['error'],file=sys.stderr);return 2
 report=payload['report'];out=Path(args.output)
 try:out.mkdir(parents=False,exist_ok=False)
 except OSError:print('Choose a new output directory under an existing parent.',file=sys.stderr);return 2
 (out/'report.json').write_text(json.dumps(report,indent=2,ensure_ascii=True),encoding='utf-8')
 (out/'report.txt').write_text(render_text(report),encoding='utf-8')
 (out/'report.html').write_text(render_html(report),encoding='utf-8')
 print('Saved report.json, report.txt and report.html in the requested local output directory.');return 0
if __name__=='__main__':raise SystemExit(main())
