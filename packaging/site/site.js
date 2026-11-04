/* PrivacySafe Security Patches documentation site. CC0 1.0 Universal.
   Everything here is optional: the site reads fine without it. No network requests. */
(function () {
  var root = document.documentElement.getAttribute('data-root') || '';

  // Narrow screens start with the menu closed.
  var box = document.querySelector('.side-box');
  if (box && window.matchMedia('(max-width: 50rem)').matches) box.removeAttribute('open');
  var cur = document.querySelector('.docs-side [aria-current=page]');
  var side = document.querySelector('.docs-side');
  if (cur && side && box && box.open && side.scrollHeight > side.clientHeight) side.scrollTop = Math.max(0, cur.offsetTop - side.clientHeight / 2);

  // Copy buttons on code blocks.
  document.querySelectorAll('.doc pre').forEach(function (pre) {
    if (pre.classList.contains('manual') || pre.classList.contains('license')) return;
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'copy'; b.textContent = 'Copy';
    b.addEventListener('click', function () {
      var t = pre.querySelector('code') ? pre.querySelector('code').innerText : pre.innerText;
      var done = function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1500); };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(done);
      else { var r = document.createRange(); r.selectNodeContents(pre.querySelector('code') || pre); var s = getSelection(); s.removeAllRanges(); s.addRange(r); try { document.execCommand('copy'); done(); } catch (e) {} s.removeAllRanges(); }
    });
    pre.appendChild(b);
  });

  // Filter on the tools table, the CVE list and the manual page list.
  var f = document.getElementById('tool-filter'), only = document.getElementById('only-protect');
  function filterRows() {
    var q = f ? f.value.toLowerCase().trim() : '', p = only && only.checked, active = !!q || p;
    var rows = document.querySelectorAll('.tools-table tbody tr'), shown = 0;
    rows.forEach(function (tr) {
      tr.hidden = (q && tr.textContent.toLowerCase().indexOf(q) < 0) || (p && tr.getAttribute('data-protects') !== '1');
      if (!tr.hidden) shown++;
    });
    document.querySelectorAll('.tool-group').forEach(function (g) {
      var vis = g.querySelectorAll('tbody tr:not([hidden])').length, s = g.querySelector('small[data-total]');
      g.hidden = active && !vis;
      if (s) s.textContent = active ? vis + ' of ' + s.getAttribute('data-total') + ' entries' : s.getAttribute('data-total') + ' entries';
    });
    var st = document.getElementById('filter-status');
    if (st) st.textContent = active ? (shown ? shown + ' of ' + rows.length + ' entries shown' : 'No entry matches. Try a product name or a CVE number.') : '';
  }
  if (f) f.addEventListener('input', filterRows);
  if (only) only.addEventListener('change', filterRows);

  // Search. The index is a script so it works from a local file too.
  var input = document.getElementById('site-search'), out = document.getElementById('search-results');
  if (!input || !out) return;
  var loading = false, waiting = [];
  function ready(cb) {
    if (window.PSF_INDEX) return cb();
    waiting.push(cb);
    if (loading) return; loading = true;
    var s = document.createElement('script'); s.src = root + 'assets/search-index.js';
    s.onload = function () { var q = waiting; waiting = []; q.forEach(function (f) { f(); }); };
    document.head.appendChild(s);
  }
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function run() {
    var q = input.value.toLowerCase().trim();
    if (!q) { out.hidden = true; out.innerHTML = ''; return; }
    var words = q.split(/\s+/), res = [], N = window.PSF_INDEX.length;
    window.PSF_DF = window.PSF_DF || {};
    function idf(w) {   // a word on most pages tells little; a rare word tells a lot
      if (!(w in window.PSF_DF)) window.PSF_DF[w] = window.PSF_INDEX.filter(function (p) { return p.text.toLowerCase().indexOf(w) >= 0; }).length;
      return Math.max(0.2, Math.log(N / (window.PSF_DF[w] || 1)));
    }
    window.PSF_INDEX.forEach(function (p) {
      var t = p.title.toLowerCase(), h = p.heads.join(' ').toLowerCase(), x = p.text.toLowerCase(), score = 0, ok = true;
      words.forEach(function (w) {
        var s = 0;
        if (t.indexOf(w) >= 0) s += 10;
        if (h.indexOf(w) >= 0) s += 4;
        if ((p.alias || '').toLowerCase().indexOf(w) >= 0) s += 8;
        if (x.indexOf(w) >= 0) s += idf(w);
        if (!s) ok = false; score += s;
      });
      if (ok) {
        score += p.w || 0;
        // a bare command word is best answered by the guide that explains the commands
        if (p.url === 'how-it-works.html' && /^(check|hunt|mitigate|rollback|dry[- ]run|exit codes?|commands?)$/.test(q)) score += 20;
        res.push({ p: p, score: score });
      }
    });
    res.sort(function (a, b) { return b.score - a.score; });
    res = res.slice(0, 8);
    if (!res.length) { out.innerHTML = '<a href="#" tabindex="-1"><strong>No match</strong><small>Try a product name or a CVE number</small></a>'; out.hidden = false; return; }
    out.innerHTML = res.map(function (r) {
      var x = r.p.text, i = x.toLowerCase().indexOf(words[0]), st = i >= 0 ? Math.max(0, i - 40) : 0; if (st > 0) { var sp = x.indexOf(' ', st); if (sp > 0 && sp < i) st = sp + 1; } var snip = x.substr(st, 110);
      return '<a href="' + root + r.p.url + '" role="option"><strong><span class="kind-tag">' + esc(r.p.kind || '') + '</span>' + esc(r.p.title) + '</strong><small>' + esc(snip) + '</small></a>';
    }).join('');
    out.hidden = false;
  }
  document.addEventListener('keydown', function (e) {
    var t = (e.target.tagName || '').toLowerCase();
    if (e.key === '/' && t !== 'input' && t !== 'textarea' && !e.ctrlKey && !e.metaKey) { e.preventDefault(); input.focus(); }
  });
  input.addEventListener('focus', function () { ready(function () {}); });
  input.addEventListener('input', function () { ready(run); });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { out.hidden = true; input.blur(); }
    if (e.key === 'Enter') { var a = out.querySelector('a[role=option]'); if (a) { location.href = a.href; } }
    if (e.key === 'ArrowDown') { var a2 = out.querySelector('a[role=option]'); if (a2) { a2.focus(); e.preventDefault(); } }
  });
  out.addEventListener('keydown', function (e) {
    var cur = document.activeElement;
    if (e.key === 'ArrowDown' && cur.nextElementSibling) { cur.nextElementSibling.focus(); e.preventDefault(); }
    if (e.key === 'ArrowUp') { (cur.previousElementSibling || input).focus(); e.preventDefault(); }
    if (e.key === 'Escape') { out.hidden = true; input.focus(); }
  });
  document.addEventListener('click', function (e) { if (!out.contains(e.target) && e.target !== input) out.hidden = true; });
})();

// Assisted-by: Claude Sonnet 5.5
