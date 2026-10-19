"""Generate a synthetic report without networking. Safe prospective-public fixture."""
import json
from pathlib import Path
from acheck.analyze import analyze
from acheck.report import render_html,render_text
body=b'''<!doctype html><title>Example workshop</title><h1>Solar panel workshop</h1><p>Learn how solar panels use sunlight to generate electricity.</p><h2>Who can join?</h2><p>The introductory workshop is designed for beginners. Bring your questions.</p><script>not extracted</script>'''
report={'captured_at':'2000-01-01T00:00:00Z (synthetic fixture; not a live fetch)','fetch':{'url':'https://example.com/workshop','status':200,'robots':[{'status':200,'allowed_for_checker':True,'policy':'synthetic fixture','user_agent':'AudenPageCheck'}]},'analysis':analyze(body,'Is this solar workshop for beginners and what does it cost?')}
out=Path('demo-report');out.mkdir(exist_ok=True)
(out/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
(out/'report.txt').write_text(render_text(report),encoding='utf-8')
(out/'report.html').write_text(render_html(report),encoding='utf-8')
print('Synthetic report generated; no network request made.')
