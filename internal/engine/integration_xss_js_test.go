//go:build cgo

package engine_test

import "testing"

// xssJSCase is one fire / no-fire probe for a ZS-JS-151..162 rule.
type xssJSCase struct {
	name string
	rule string
	src  string
}

func TestIntegration_XSSJSRulesFire(t *testing.T) {
	idx := loadJSRules(t)
	cases := []xssJSCase{
		{"N1 setHTMLUnsafe", "ZS-JS-151", "const h = location.hash.slice(1);\nhost.setHTMLUnsafe(h);\n"},
		{"N1 createContextualFragment", "ZS-JS-151", "const h = location.hash.slice(1);\nconst f = document.createRange().createContextualFragment(h);\n"},
		{"N2 jquery html", "ZS-JS-152", "const q = new URLSearchParams(location.search).get('q');\n$('#out').html(q);\n"},
		{"N3 on* handler value", "ZS-JS-153", "const c = location.hash.slice(1);\nbtn.setAttribute('onclick', c);\n"},
		{"N3 tainted attribute name", "ZS-JS-153", "const n = new URLSearchParams(location.search).get('n');\nbtn.setAttribute(n, 'x');\n"},
		{"N4 setAttribute href", "ZS-JS-154", "const u = new URLSearchParams(location.search).get('next');\na.setAttribute('href', u);\n"},
		{"N4 setAttributeNS xlink:href", "ZS-JS-154", "const u = new URLSearchParams(location.search).get('next');\nuse.setAttributeNS(XLINK, 'xlink:href', u);\n"},
		{"N5 href property", "ZS-JS-155", "const u = new URLSearchParams(location.search).get('next');\nanchor.href = u;\n"},
		{"N5 action property", "ZS-JS-155", "const u = new URLSearchParams(location.search).get('next');\nform.action = u;\n"},
		{"N6 message listener no origin", "ZS-JS-156", "window.addEventListener('message', (e) => { out.textContent = e.data; });\n"},
		{"N7 hostname endsWith bare domain", "ZS-JS-157", "if (new URL(u).hostname.endsWith('example.com')) { go(u); }\n"},
		{"N7 startsWith bare origin", "ZS-JS-157", "if (redirectUrl.startsWith('https://example.com')) { go(redirectUrl); }\n"},
		{"N7 includes bare domain", "ZS-JS-157", "if (returnUrl.includes('example.com')) { go(returnUrl); }\n"},
		{"N8 dangerouslySetInnerHTML prop", "ZS-JS-158", "const A = (props) => <div dangerouslySetInnerHTML={{ __html: props.bio }} />;\n"},
		{"N9 unsafeHTML imported", "ZS-JS-159", "import { unsafeHTML } from 'lit/directives/unsafe-html.js';\nconst t = html`${unsafeHTML(this.content)}`;\n"},
		{"N10 trustAsHtml", "ZS-JS-160", "$scope.bio = $sce.trustAsHtml(user.bio);\n"},
		{"N11 SafeString concat", "ZS-JS-161", "function h(url, text) { return new Handlebars.SafeString('<a href=\"' + url + '\">' + text + '</a>'); }\n"},
		{"N12 JSON.stringify in script", "ZS-JS-162", "res.send(`<script>window.__S=${JSON.stringify(state)}</script>`);\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !hasRule(matchJSSource(t, idx, c.src), c.rule) {
				t.Errorf("expected %s to fire", c.rule)
			}
		})
	}
}

func TestIntegration_XSSJSRulesStaySilent(t *testing.T) {
	idx := loadJSRules(t)
	cases := []xssJSCase{
		{"N1 constant markup", "ZS-JS-151", "host.setHTMLUnsafe('<b>static</b>');\n"},
		{"N1 sanitizing setHTML", "ZS-JS-151", "const h = location.hash.slice(1);\nhost.setHTML(h);\n"},
		{"N2 constant markup and getter", "ZS-JS-152", "$('#out').html('<i>loading</i>');\nconst v = $('#out').html();\n"},
		{"N2 untainted parameter", "ZS-JS-152", "function show(m) { $('#out').html(m); }\n"},
		{"N3 constant handler", "ZS-JS-153", "btn.setAttribute('onclick', 'toggle()');\n"},
		{"N3 tainted value in title", "ZS-JS-153", "const c = location.hash.slice(1);\nbtn.setAttribute('title', c);\n"},
		{"N4 constant href", "ZS-JS-154", "a.setAttribute('href', '/home');\n"},
		{"N4 plain parameter", "ZS-JS-154", "function link(el, u) { el.setAttribute('href', u); }\n"},
		{"N4 tainted non-url attribute", "ZS-JS-154", "const u = new URLSearchParams(location.search).get('t');\na.setAttribute('title', u);\n"},
		{"N5 constant href", "ZS-JS-155", "anchor.href = '/home';\n"},
		{"N5 location.href owned by ZS-JS-046", "ZS-JS-155", "const u = new URLSearchParams(location.search).get('next');\nlocation.href = u;\n"},
		{"N6 origin checked", "ZS-JS-156", "window.addEventListener('message', (e) => { if (e.origin !== 'https://a.example.com') return; out.textContent = e.data; });\n"},
		{"N6 websocket target", "ZS-JS-156", "ws.addEventListener('message', (ev) => { out.textContent = ev.data; });\n"},
		{"N6 named handler", "ZS-JS-156", "window.addEventListener('message', onMessage);\n"},
		{"N7 leading dot", "ZS-JS-157", "if (new URL(u).hostname.endsWith('.example.com')) { go(u); }\n"},
		{"N7 trailing slash", "ZS-JS-157", "if (redirectUrl.startsWith('https://example.com/')) { go(redirectUrl); }\n"},
		{"N7 non-url receiver", "ZS-JS-157", "if (name.includes('example.com')) { go(name); }\n"},
		{"N8 sanitized", "ZS-JS-158", "const A = (props) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.bio) }} />;\n"},
		{"N8 constant", "ZS-JS-158", "const A = () => <div dangerouslySetInnerHTML={{ __html: '<br/>' }} />;\n"},
		{"N9 constant argument", "ZS-JS-159", "import { unsafeHTML } from 'lit/directives/unsafe-html.js';\nconst t = html`${unsafeHTML('<b>x</b>')}`;\n"},
		{"N9 local helper not imported", "ZS-JS-159", "function unsafeHTML(s) { return s; }\nconst t = unsafeHTML(this.content);\n"},
		{"N10 constant", "ZS-JS-160", "$scope.banner = $sce.trustAsHtml('<b>Welcome</b>');\n"},
		{"N11 escaped", "ZS-JS-161", "function h(t) { return new Handlebars.SafeString('<b>' + Handlebars.Utils.escapeExpression(t) + '</b>'); }\n"},
		{"N11 constant", "ZS-JS-161", "const s = new Handlebars.SafeString('<b>static</b>');\n"},
		{"N12 escaped with replace", "ZS-JS-162", "res.send(`<script>window.__S=${JSON.stringify(state).replace(/</g, '\\\\u003c')}</script>`);\n"},
		{"N12 serialize-javascript", "ZS-JS-162", "res.send(`<script>window.__S=${serialize(state)}</script>`);\n"},
		{"N12 no script block", "ZS-JS-162", "res.send(`<p>${JSON.stringify(state)}</p>`);\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hasRule(matchJSSource(t, idx, c.src), c.rule) {
				t.Errorf("expected %s to stay silent", c.rule)
			}
		})
	}
}
