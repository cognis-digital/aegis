# polyglot/python/injection_detector.py

import re
from typing import List, Dict, Any

class InjectionDetector:
    def __init__(self):
        self.patterns = {
            'sql': r'(?:;|--|&&|\|\||`|\'|\"|\$|\\|@|<|>|=|!=|<=|>=|<<|>>|~|!|&|\*|\+|-|/|%|`|\\|\.|,|:|;|<|>|\?|{|}|[|]|(|)|\{|\}|\[|\]|\^|\||_|~|`)',
            'xss': r'(<script>|<img.*src=|onerror=|onclick=|onload=|onsubmit=|onchange=|onfocus=|onblur=|onkeydown=|onkeyup=|onkeypress=|oninput=|onpaste=|oncopy=|oncut=|onmouseover=|onmouseout=|onmousedown=|onmouseup=|onmousemove=|onselect=|oncontextmenu=|onreadystatechange=|onbeforeunload=|onunload=|onresize=|onscroll=|onabort=|onerror=|onloadstart=|onprogress=|onloadend=|onwaiting=|onpause=|onplay=|onplaying=|onended=|ontimeupdate=|onvolumechange=|onratechange=|onfullscreenchange=|onfullscreenerror=|onwebkitfullscreenchange=|onwebkitfullscreenerror=)',
            'xpath': r'(//|/\*|\*|@|and|or|not|mod|div|rem|union|intersect|except|child::|attribute::|text::|comment::|processing-instruction::|namespace::|descendant-or-self::|descendant::|parent::|ancestor::|preceding-sibling::|following-sibling::|preceding::|following::|self::|descendant::|child::|attribute::|name::|namespace::|local-name::|normalize-space::|string-length::|substring::|substring-after::|substring-before::|starts-with::|ends-with::|contains::|number::|boolean::|text::|comment::|processing-instruction::|node()|text()|attribute()|child()|descendant()|parent()|ancestor()|preceding-sibling()|following-sibling()|preceding()|following()|self()|descendant-or-self()|namespace()|local-name()|normalize-space()|string-length()|substring()|substring-after()|substring-before()|starts-with()|ends-with()|contains()|number()|boolean()|text()|comment()|processing-instruction()|node())',
            'command': r'(?:;|&&|\|\||`|\'|\"|\\|$(?:\{.*?\}|.*?))'
        }

    def detect_injections(self, text: str) -> Dict[str, List[str]]:
        results = {key: [] for key in self.patterns}
        for pattern_key, pattern in self.patterns.items():
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            matches = compiled_pattern.findall(text)
            results[pattern_key].extend(matches)
        return results

    def analyze(self, text: str) -> Dict[str, List[str]]:
        return self.detect_injections(text)

def main():
    detector = InjectionDetector()
    sample_text = """
    SELECT * FROM users WHERE id = '1' OR '1'='1';
    <script>alert('XSS');</script>
    // xpath query
    // command injection attempt: ; rm -rf /
    """
    result = detector.analyze(sample_text)
    print("Injection Detection Results:")
    for key, values in result.items():
        if values:
            print(f"  {key.upper()}: {', '.join(values)}")
        else:
            print(f"  {key.upper()}: None detected")

if __name__ == "__main__":
    main()