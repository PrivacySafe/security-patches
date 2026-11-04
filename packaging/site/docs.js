/*!
 * PrivacySafe documentation script
 * Copyright (C) 2026 Ivy Cyber LLC.
 *
 * @license magnet:?xt=urn:btih:0b31508aeb0634b347b8270c7bee4d411b5d4109&dn=agpl-3.0.txt AGPL-v3-or-Later
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Everything here is optional: the pages read fine without it. It makes no
 * network requests of its own; the search index is a script file on the same site.
 */
(function () {
  'use strict';
  document.documentElement.classList.add('js');

  // Narrow screens start with the section menu closed.
  var box = document.querySelector('.side-box');
  if (box && window.matchMedia('(max-width: 860px)').matches) box.removeAttribute('open');
  var cur = document.querySelector('.docs-side [aria-current=page]'), side = document.querySelector('.docs-side');
  if (cur && side && box && box.open && side.scrollHeight > side.clientHeight) side.scrollTop = Math.max(0, cur.offsetTop - side.clientHeight / 2);

  // Close the small-screen menu when a link in it is used or Escape is pressed.
  var mnav = document.querySelector('.mnav');
  if (mnav) document.addEventListener('keydown', function (e) { if (e.key === 'Escape') mnav.removeAttribute('open'); });

  // Copy buttons on code blocks.
  document.querySelectorAll('.doc pre').forEach(function (pre) {
    if (pre.classList.contains('manual') || pre.classList.contains('license')) return;
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'copy'; b.textContent = 'Copy';
    b.addEventListener('click', function () {
      var code = pre.querySelector('code'), t = code ? code.innerText : pre.innerText;
      var done = function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1500); };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(done);
      else { var r = document.createRange(); r.selectNodeContents(code || pre); var s = getSelection(); s.removeAllRanges(); s.addRange(r); try { document.execCommand('copy'); done(); } catch (e) {} s.removeAllRanges(); }
    });
    pre.appendChild(b);
  });

  // Filters on the tools table, the CVE list and the manual page list.
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

  // Search. The index is a script file, so it also works from a local copy.
  var input = document.getElementById('site-search'), out = document.getElementById('search-results');
  if (!input || !out) return;
  var indexUrl = input.getAttribute('data-index'), base = input.getAttribute('data-base') || '';
  var loading = false, waiting = [];
  function ready(cb) {
    if (window.PSF_INDEX) return cb();
    waiting.push(cb);
    if (loading) return; loading = true;
    var s = document.createElement('script'); s.src = indexUrl;
    s.onload = function () { var q = waiting; waiting = []; q.forEach(function (fn) { fn(); }); };
    document.head.appendChild(s);
  }
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function run() {
    var q = input.value.toLowerCase().trim();
    if (!q) { out.hidden = true; out.innerHTML = ''; return; }
    var words = q.split(/\s+/), res = [], N = window.PSF_INDEX.length;
    window.PSF_DF = window.PSF_DF || {};
    function idf(w) {
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
        if (p.url === 'how-it-works.html' && /^(check|hunt|mitigate|rollback|dry[- ]run|exit codes?|commands?)$/.test(q)) score += 20;
        res.push({ p: p, score: score });
      }
    });
    res.sort(function (a, b) { return b.score - a.score; });
    res = res.slice(0, 8);
    if (!res.length) { out.innerHTML = '<a href="#" tabindex="-1"><strong>No match</strong><small>Try a product name or a CVE number</small></a>'; out.hidden = false; return; }
    out.innerHTML = res.map(function (r) {
      var x = r.p.text, i = x.toLowerCase().indexOf(words[0]), st = i >= 0 ? Math.max(0, i - 40) : 0;
      if (st > 0) { var sp = x.indexOf(' ', st); if (sp > 0 && sp < i) st = sp + 1; }
      return '<a href="' + base + r.p.url + '" role="option"><strong><span class="kind-tag">' + esc(r.p.kind || '') + '</span>' + esc(r.p.title) + '</strong><small>' + esc(x.substr(st, 110)) + '</small></a>';
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
    if (e.key === 'Enter') { var a = out.querySelector('a[role=option]'); if (a) location.href = a.href; }
    if (e.key === 'ArrowDown') { var a2 = out.querySelector('a[role=option]'); if (a2) { a2.focus(); e.preventDefault(); } }
  });
  out.addEventListener('keydown', function (e) {
    var c = document.activeElement;
    if (e.key === 'ArrowDown' && c.nextElementSibling) { c.nextElementSibling.focus(); e.preventDefault(); }
    if (e.key === 'ArrowUp') { (c.previousElementSibling || input).focus(); e.preventDefault(); }
    if (e.key === 'Escape') { out.hidden = true; input.focus(); }
  });
  document.addEventListener('click', function (e) { if (!out.contains(e.target) && e.target !== input) out.hidden = true; });
})();

// Assisted-by: Claude Sonnet 5.5
