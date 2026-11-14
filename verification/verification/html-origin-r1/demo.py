import sys
from test_html_origin_review import attr
print("Help-center resource attributes")
for label,uri in [("Relative document","/docs/start"),("Outside origin","https://outside.invalid/pixel"),("Protocol-relative","//help.example.com/x"),("Page fragment","#part")]:
 value,_=attr(uri)
 print(label+": "+repr(value))
for c in (0x85,0x9f):
 value,_=attr("https://help.example.com/"+chr(c)+"asset")
 print("C1 U+%04X output: %r"%(c,value))
 print("Control character removed:",value is None)
print("Control-character boundary remains incomplete.")
sys.exit(1)
