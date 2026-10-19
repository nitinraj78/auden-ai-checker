"""Deterministic lexical observations, not a model or an AI-visibility score."""
from html.parser import HTMLParser
import hashlib,re,unicodedata
from . import VERSION
STOP=set('a an the and or to of in on for with is are was be do does how what which who your you my i it this that can'.split())
BLOCKS={'title','h1','h2','h3','h4','h5','h6','p','li','dt','dd','blockquote'}
VOID={'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
def clean(value):return ' '.join(''.join(c for c in value if c in '\n\t' or unicodedata.category(c)[0]!='C').split())
def terms(value):return sorted(set(re.findall(r'[^\W_]+',unicodedata.normalize('NFKC',value).casefold()))-STOP)
def validate_question(question):
 if not isinstance(question,str) or not question.strip() or len(question)>1000 or any(ord(c)<32 and c not in '\n\t' for c in question):raise ValueError('Question must contain 1–1000 ordinary text characters.')
 if not terms(question):raise ValueError('Question needs at least one substantive term.')
 return clean(question)
class Extractor(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True)
  self.stack=[];self.items=[];self.active=None;self.parts=[]
 def flush(self):
  text=clean(''.join(self.parts))
  if text:self.items.append((self.active or 'text',text))
  self.active=None;self.parts=[]
 def handle_starttag(self,tag,attrs):
  d=dict(attrs);style=re.sub(r"\s+",'',d.get('style') or '').lower()
  hidden=(self.stack[-1][1] if self.stack else False) or tag in {'script','style','template','noscript','svg','canvas','iframe'} or 'hidden'in d or (d.get('aria-hidden') or '').lower()=='true' or 'display:none'in style or 'visibility:hidden'in style
  boundary=tag in BLOCKS or tag in {'div','section','article','main','header','footer','nav','table','tr','td','th','ul','ol','body','hr'}
  if boundary and not hidden:self.flush()
  if tag not in VOID:self.stack.append((tag,hidden))
  if not hidden and tag=='br':self.parts.append(' ')
 def handle_endtag(self,tag):
  hidden=self.stack[-1][1] if self.stack else False
  if not hidden and (tag in BLOCKS or tag in {'div','section','article','main','header','footer','nav','table','tr','td','th','ul','ol','body'}):self.flush()
  for i in range(len(self.stack)-1,-1,-1):
   if self.stack[i][0]==tag:self.stack=self.stack[:i];break
 def handle_data(self,data):
  if self.stack and self.stack[-1][1]:return
  tags=[tag for tag,_ in self.stack]
  if 'head'in tags and 'title'not in tags:return
  if self.active is None:self.active=next((tag for tag in reversed(tags) if tag in BLOCKS),'text')
  self.parts.append(data)

def analyze(body,question):
 question=validate_question(question);p=Extractor();p.feed(body.decode('utf-8-sig'));p.flush();qterms=terms(question)
 title=next((text for tag,text in p.items if tag=='title'),'');allterms=set();candidates=[]
 for index,(tag,text) in enumerate(p.items):
  found=sorted(set(terms(text))&set(qterms));allterms.update(found)
  if tag!='title':candidates.append({'id':f'P{index+1}','tag':tag,'text':text,'matching_terms':found})
 selected=sorted(candidates,key=lambda x:(-len(x['matching_terms']),int(x['id'][1:])))[:6]
 budget=60;passages=[]
 for item in selected:
  words=item['text'].split();take=min(10,budget,len(words))
  if take==0:break
  first=next((i for i,w in enumerate(words) if set(terms(w))&set(item['matching_terms'])),0);start=max(0,first-3)
  excerpt=' '.join(words[start:start+take]);budget-=len(excerpt.split())
  passages.append({**item,'text':excerpt,'matching_terms_in_excerpt':sorted(set(terms(excerpt))&set(qterms)),'truncated':len(words)>take})
 headings=[{'level':int(t[1]),'text':x[:160]} for t,x in p.items if re.fullmatch('h[1-6]',t)][:12]
 missing=sorted(set(qterms)-allterms)
 return {'version':VERSION,'content_sha256':hashlib.sha256(body).hexdigest(),'question':question,
  'observed':{'title':title[:160],'headings':headings,'passages':passages,'static_text_blocks':len(candidates),'extraction_limit':'Static HTML text; external CSS and JavaScript not evaluated.'},
  'inferred':{'method':'Case-folded exact word overlap, stop words removed; no semantic or quality judgment.','question_terms':qterms,'matching_terms':sorted(allterms),'not_found_terms':missing,'lexical_coverage':{'matched':len(allterms),'total':len(qterms)},'gaps':[{'term':x,'status':'not found in fetched content'} for x in missing]},
  'not_tested':['Indexing','Ranking','AI citation or recommendation','Factual accuracy','JavaScript rendering','External CSS visibility','Other pages','Private content','Conversions']}
