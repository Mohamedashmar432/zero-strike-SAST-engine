// ZS-TS-052: javascript: URL built with tainted data assigned to href
const code = location.hash.slice(1);
link.href = "javascript:" + code;
