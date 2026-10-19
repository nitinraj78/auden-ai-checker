"""Bounded HTTPS fetch. Call through the CLI's isolated 20-second worker."""
from dataclasses import dataclass
import http.client,ipaddress,re,socket,ssl,time,zlib
from urllib.parse import urlsplit,urljoin,unquote,quote

AGENT='AudenPageCheck'
WIRE_LIMIT=131072
BODY_LIMIT=524288
class CheckError(Exception):pass

def validate_url(url):
 if not isinstance(url,str) or len(url)>2048 or re.search(r'[\x00-\x20\x7f\\]',url):raise CheckError('Invalid URL characters or length.')
 try:
  u=urlsplit(url);host=u.hostname;port=u.port
 except ValueError:raise CheckError('Invalid URL.') from None
 if u.scheme!='https' or not host or port not in (None,443) or u.username is not None or u.password is not None or u.query or u.fragment:raise CheckError('Use public HTTPS port 443 without credentials, query or fragment.')
 try:ipaddress.ip_address(host)
 except ValueError:pass
 else:raise CheckError('IP-literal URLs are not accepted.')
 if not host.isascii() or '.' not in host or host.endswith('.') or not re.fullmatch(r'[a-z0-9.-]+',host) or any(not x or len(x)>63 or x.startswith('-') or x.endswith('-') for x in host.split('.')):raise CheckError('Use a public ASCII DNS hostname.')
 if host.endswith(('.localhost','.local','.internal','.test','.invalid','.example','.onion')):raise CheckError('Non-public hostname.')
 path=u.path
 for _ in range(3):path=unquote(path)
 if re.search(r'[\x00-\x20\x7f\\?@#]',path) or re.search(r'(?i)(token|secret|password|passwd|session|credential|auth|api[-_]?key|signature|invite|reset)',path) or any(len(s)>48 for s in path.split('/')):raise CheckError('Potential credential-bearing or unsupported path.')
 return u

def validate_addresses(addresses):
 if not addresses:raise CheckError('DNS returned no addresses.')
 safe=[]
 for value in addresses:
  try:a=ipaddress.ip_address(value)
  except ValueError:raise CheckError('Invalid DNS response.') from None
  if not a.is_global or a.is_multicast or a.is_reserved or a.is_loopback or a.is_link_local or (a.version==6 and (a.ipv4_mapped or a.sixtofour or a.teredo or a in ipaddress.ip_network('64:ff9b::/96') or a in ipaddress.ip_network('64:ff9b:1::/48'))):raise CheckError('DNS contains a non-public or translated address.')
  safe.append(str(a))
 return sorted(set(safe))

def resolve(host):
 return [row[4][0] for row in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)]

def decode_body(data,encoding,limit=BODY_LIMIT):
 if encoding in ('','identity'):
  if len(data)>limit:raise CheckError('Decoded response exceeds size limit.')
  return data
 if encoding not in ('gzip','deflate'):raise CheckError('Unsupported content encoding.')
 try:
  dec=zlib.decompressobj(31 if encoding=='gzip' else zlib.MAX_WBITS)
  out=dec.decompress(data,limit+1)
  if len(out)>limit or dec.unconsumed_tail:raise CheckError('Decoded response exceeds size limit.')
  if not dec.eof or dec.unused_data:raise CheckError('Malformed or concatenated compressed response.')
  return out
 except zlib.error:raise CheckError('Malformed compressed response.') from None

def robots_allowed(text,path):
 if '<html' in text.lower() or '<!doctype' in text.lower() or '\x00' in text:raise CheckError('Invalid robots response.')
 def canonical(value):
  # Decode only unreserved bytes; encoded '*' and '$' remain literal.
  def convert(match):
   char=chr(int(match.group(1),16))
   return char if char.isascii() and (char.isalnum() or char in '-._~') else match.group(0).upper()
  value=''.join(quote(char,safe='') if ord(char)>127 else char for char in value)
  return re.sub(r'%([0-9a-fA-F]{2})',convert,value)
 groups=[];agents=[];rules=[];begun=False
 for raw in text.splitlines():
  line=raw.split('#',1)[0].strip()
  if not line or ':' not in line:continue
  key,value=line.split(':',1);key=key.lower().strip();value=value.strip()
  if key=='user-agent':
   if begun:groups.append((agents,rules));agents=[];rules=[];begun=False
   agents.append(value.lower())
  elif agents:
   begun=True
   if key in ('allow','disallow','crawl-delay','request-rate'):rules.append((key,value))
 if agents:groups.append((agents,rules))
 specific=[r for a,r in groups if any(x!='*' and x and x in AGENT.lower() for x in a)]
 selected=specific or [r for a,r in groups if '*' in a]
 matches=[];path=canonical(path)
 for group in selected:
  for key,value in group:
   if key in ('crawl-delay','request-rate') and value not in ('','0'):raise CheckError('Robots pacing policy needs a scheduled crawler; this one-shot checker stops.')
   if not value or key not in ('allow','disallow'):continue
   if len(value)>1000:raise CheckError('Robots rule too long.')
   rule=canonical(value);end=rule.endswith('$');rule=rule[:-1] if end else rule
   pattern='^'+re.escape(rule).replace(r'\*','.*')+('$' if end else '')
   if re.search(pattern,path):matches.append((len(rule.replace('*','')),key=='allow'))
 return max(matches,default=(0,True))[1]

@dataclass
class Response:
 status:int
 headers:dict
 body:bytes

class PinnedHTTPS(http.client.HTTPSConnection):
 def __init__(self,host,ip,timeout,context=None):
  super().__init__(host,443,timeout=timeout,context=context or ssl.create_default_context());self.ip=ip
 def connect(self):
  raw=socket.create_connection((self.ip,443),self.timeout)
  try:self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
  except BaseException:raw.close();raise

def request(url,ip,deadline):
 u=validate_url(url);remaining=deadline-time.monotonic()
 if remaining<=0:raise CheckError('Fetch deadline exceeded.')
 c=PinnedHTTPS(u.hostname,ip,min(5,remaining))
 try:
  c.request('GET',u.path or '/',headers={'Host':u.hostname,'User-Agent':AGENT+'/0.1','Accept':'text/html,text/plain;q=0.8','Accept-Encoding':'gzip, deflate','Connection':'close'})
  r=c.getresponse();headers={k.lower():v for k,v in r.getheaders()}
  length=None
  if 'content-length' in headers and 'transfer-encoding' in headers:raise CheckError('Ambiguous response framing.')
  if 'content-length' in headers:
   try:length=int(headers['content-length'])
   except ValueError:raise CheckError('Invalid Content-Length.') from None
   if length<0 or length>WIRE_LIMIT:raise CheckError('Compressed response exceeds size limit.')
  chunks=[];size=0
  while True:
   if time.monotonic()>=deadline:raise CheckError('Fetch deadline exceeded.')
   chunk=r.read(min(16384,WIRE_LIMIT+1-size));size+=len(chunk)
   if size>WIRE_LIMIT:raise CheckError('Compressed response exceeds size limit.')
   if not chunk:break
   chunks.append(chunk)
  if length is not None and size!=length:raise CheckError('Incomplete response body.')
  return Response(r.status,headers,decode_body(b''.join(chunks),headers.get('content-encoding','').lower()))
 finally:c.close()

class Fetcher:
 def __init__(self,resolver=resolve,transport=request):
  self.resolver=resolver;self.transport=transport;self.deadline=time.monotonic()+18;self.redirects=0;self.observations=[]
 def get(self,url):
  u=validate_url(url)
  if time.monotonic()>=self.deadline:raise CheckError('Fetch deadline exceeded.')
  addresses=validate_addresses(self.resolver(u.hostname))
  # The connection uses this numeric address; no second hostname resolution occurs.
  return self.transport(url,addresses[0],self.deadline)
 def redirect(self,url,r):
  self.redirects+=1
  if self.redirects>3:raise CheckError('Redirect limit exceeded.')
  if not r.headers.get('location'):raise CheckError('Redirect missing Location.')
  dest=urljoin(url,r.headers['location']);validate_url(dest);return dest
 def check_robots(self,page):
  u=validate_url(page);origin='https://'+u.hostname;url=origin+'/robots.txt'
  while True:
   r=self.get(url)
   if r.status in (301,302,303,307,308):
    dest=self.redirect(url,r)
    if urlsplit(dest).hostname!=u.hostname:raise CheckError('Cross-origin robots redirect is unsupported; stopped.')
    url=dest;continue
   break
  if r.status in (404,410):allowed=True;policy='absent'
  elif r.status==200:
   if r.headers.get('content-type','').split(';')[0].strip() not in ('text/plain',''):raise CheckError('Robots response is not plain text.')
   try:txt=r.body.decode('utf-8-sig')
   except UnicodeDecodeError:raise CheckError('Robots text decoding failed.') from None
   allowed=robots_allowed(txt,u.path or '/');policy='parsed'
  else:raise CheckError('Robots fetch failed; page was not fetched.')
  self.observations.append({'url':url,'status':r.status,'policy':policy,'allowed_for_checker':allowed,'user_agent':AGENT})
  if not allowed:raise CheckError('Robots disallows this checker; page was not fetched.')
 def fetch(self,url):
  validate_url(url)
  while True:
   self.check_robots(url);r=self.get(url)
   if r.status in (301,302,303,307,308):url=self.redirect(url,r);continue
   if r.status!=200:raise CheckError('Page did not return HTTP 200.')
   if r.headers.get('content-type','').split(';')[0].strip().lower()!='text/html':raise CheckError('Only text/html is supported.')
   # Exact UTF-8 only; other encodings require an explicit future decoder.
   try:r.body.decode('utf-8-sig')
   except UnicodeDecodeError:raise CheckError('Only UTF-8 HTML is supported.') from None
   return {'url':url,'status':r.status,'content_type':r.headers.get('content-type'),'robots':self.observations,'redirects':self.redirects,'body':r.body}
