import pytest
from html import escape
from html.parser import HTMLParser
import bleach
from bleach.sanitizer import Cleaner
from bleach.css_sanitizer import CSSSanitizer
BASE='https://help.example.com/docs/'
ORIGINS={'https://static.example.com','https://xn--exmple-cua.com','http://intranet.example.com:8080'}
class Attributes(HTMLParser):
 def __init__(self,text):
  super().__init__(convert_charrefs=True);self.items=[];self.feed(text)
 def handle_starttag(self,tag,attrs):self.items.append((tag,dict(attrs)))
 def handle_startendtag(self,tag,attrs):self.handle_starttag(tag,attrs)
def cleaner(**kwargs):
 return Cleaner(tags={'a','img','form','blockquote','video','table','svg','use','p'},attributes={'*':['href','src','action','cite','poster','background','style']},base_url=BASE,allowed_origins=ORIGINS,css_sanitizer=CSSSanitizer(),**kwargs)
def attr(uri,tag='a',name='href',cl=None):
 text='<'+tag+' '+name+'="'+escape(uri,quote=True)+'">ok</'+tag+'>'
 out=(cl or cleaner()).clean(text)
 return Attributes(out).items[0][1].get(name),out
@pytest.mark.parametrize('uri,expected',[
 ('guide','https://help.example.com/docs/guide'),('../start?q=1&v=2#p','https://help.example.com/start?q=1&v=2#p'),('/start','https://help.example.com/start'),('?q=x','https://help.example.com/docs/?q=x'),('#part','#part'),('#','#'),('',BASE),
 ('HTTPS://HELP.EXAMPLE.COM:443/a','HTTPS://HELP.EXAMPLE.COM:443/a'),('https://static.example.com/a','https://static.example.com/a'),('http://intranet.example.com:8080/a','http://intranet.example.com:8080/a'),('https://exämple.com/a','https://exämple.com/a'),('https://XN--EXMPLE-CUA.COM:443/a','https://XN--EXMPLE-CUA.COM:443/a')])
def test_normal_and_equivalent_origins(uri,expected):assert attr(uri)[0]==expected
@pytest.mark.parametrize('uri',[
 'https://outside.invalid/x','//help.example.com/a','//outside.invalid/a','https://user@help.example.com/a','https://user:pw@help.example.com/a','https://sub.help.example.com/a','https://help.example.com.evil.invalid/a','https://help-example.com/a','http://help.example.com/a','https://help.example.com:8443/a','http://intranet.example.com/a','https://help.example.com:bad/a','https://help.example.com:65536/a','https://help.example.com:0/a','https://[::1/a','https://help.example.com%2eoutside.invalid/a','javascript:alert(1)','data:text/html,x','/path\\evil','https:\\help.example.com/a','https://help.example.com/\tfoo','https://help.example.com/\nfoo','https://help.example.com/\rfoo','https://help.example.com/\x1ffoo','https://help.example.com/\x7ffoo'])
def test_disallowed_values_removed(uri):assert attr(uri)[0] is None
@pytest.mark.parametrize('tag,name',[('img','src'),('form','action'),('blockquote','cite'),('video','poster'),('table','background')])
def test_all_uri_attributes_share_origin_gate(tag,name):
 assert attr('https://outside.invalid/a',tag,name)[0] is None
 assert attr('/asset',tag,name)[0]=='https://help.example.com/asset'
@pytest.mark.parametrize('html',[
 '<a href="java&#x73;cript:alert(1)">x</a>','<a href="&#106;avascript:alert(1)">x</a>','<img src="https://help.example.com/&#9;bad">','<a href="&#47;&#47;help.example.com/a">x</a>','<a href="https://u&#64;help.example.com/a">x</a>'])
def test_entities_decided_as_real_attribute_values(html):
 assert all(not attrs for _,attrs in Attributes(cleaner().clean(html)).items)
def test_entity_colon_and_query_keep_real_meaning():
 out=cleaner().clean('<a href="https&#58;//help.example.com/a?x=1&amp;y=2">x</a>')
 assert Attributes(out).items[0][1]['href']=='https://help.example.com/a?x=1&y=2'
def test_svg_local_href_stays_more_restrictive():
 c=cleaner()
 for href in ['/asset','https://help.example.com/asset']:
  out=c.clean('<svg><use xlink:href="'+href+'"></use></svg>')
  assert all('href' not in attrs and 'xlink:href' not in attrs for _,attrs in Attributes(out).items)
 out=c.clean('<svg><use xlink:href="#shape"></use></svg>')
 assert any(attrs.get('href',attrs.get('xlink:href'))=='#shape' for _,attrs in Attributes(out).items)
def test_legacy_protocol_filter_unchanged_when_disabled():
 assert Attributes(bleach.clean('<a href="mailto:a@example.com">x</a>')).items[0][1]['href']=='mailto:a@example.com'
 assert Attributes(bleach.clean('<a href="//outside.invalid/x">x</a>')).items[0][1]['href']=='//outside.invalid/x'
 assert not Attributes(bleach.clean('<a href="javascript:alert(1)">x</a>')).items[0][1]
def test_reusable_and_top_level_match_and_idempotent():
 c=cleaner();text='<a href="../start">x</a><img src="https://outside.invalid/p">'
 expected=c.clean(text)
 assert expected==c.clean(text)==c.clean(expected)
 assert bleach.clean(text,tags=c.tags,attributes=c.attributes,css_sanitizer=c.css_sanitizer,base_url=BASE,allowed_origins=ORIGINS)==expected
def test_css_security_retained_without_origin_extension():
 out=cleaner().clean('<p style="color: red; position: fixed; background: url(javascript:alert(1))">x</p>')
 style=Attributes(out).items[0][1]['style']
 assert 'color' in style and 'position' not in style and 'javascript' not in style
@pytest.mark.parametrize('tag,name',[('a','href'),('img','src')])
@pytest.mark.parametrize('char',['\u0085','\u009f'])
def test_literal_c1_control_character_removed(tag,name,char):
 uri='https://help.example.com/'+char+'asset'
 value,out=attr(uri,tag,name)
 print('control',hex(ord(char)),'parsed_value',repr(value))
 assert value is None,'Literal Unicode Cc control character must remove URI attribute'
