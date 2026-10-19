"""Escaped data only. HTML has no scripts or external assets."""
from html import escape
import json

def render_text(report):
 a=report['analysis'];o=a['observed'];i=a['inferred'];f=report.get('fetch',{})
 lines=['Auden public-page check — local prototype','Captured: '+report.get('captured_at',''),'Source: '+f.get('url','Synthetic fixture'),'Question: '+a['question'],'','Observed','Title: '+o['title'],'HTTP status: '+str(f.get('status','not fetched'))]
 lines+=['Heading '+str(h['level'])+': '+h['text'] for h in o['headings']]
 lines+=['Robots: '+json.dumps(r,sort_keys=True) for r in f.get('robots',[])]
 lines+=['','Short source excerpts']+[p['id']+': '+p['text']+(' …' if p['truncated'] else '')+' | matching terms in block: '+', '.join(p['matching_terms']) for p in o['passages']]
 lines+=['','Inferred — lexical overlap only',i['method'],'Matching terms: '+', '.join(i['matching_terms']),'Not found in fetched content: '+', '.join(i['not_found_terms']),'This is not an AI visibility, quality or factual-accuracy score.','','Not tested']+a['not_tested']
 return '\n'.join(lines)+'\n'

def render_html(report):
 text=render_text(report)
 source=report.get('fetch',{}).get('url','')
 source_link=('<a href="'+escape(source,quote=True)+'" rel="noreferrer">Open source page</a> · ') if source.startswith('https://') else ''
 links='<nav>'+source_link+'<a href="report.json" download>Download JSON</a> · <a href="report.txt" download>Download text</a></nav>' 
 return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>Public-page check</title><style>body{max-width:850px;margin:40px auto;padding:0 24px;font:18px/1.6 system-ui;color:#182637;background:#f5f7fa}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}h1{font-size:30px}</style><h1>What does this page tell a buyer?</h1><p>Local evidence report. No AI model, ranking prediction or telemetry.</p>'+links+'<pre>'+escape(text)+'</pre></html>'
