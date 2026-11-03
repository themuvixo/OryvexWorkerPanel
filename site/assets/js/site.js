// OryvexWorkerPanel docs: theme toggle (light / system / dark), mobile menu, search, copy buttons, active section, back-to-top.
(function(){
  var d=document.documentElement,KEY='oryvex.site.theme',mq=matchMedia('(prefers-color-scheme: light)');
  function pref(){try{return localStorage.getItem(KEY)||'system';}catch(e){return 'system';}}
  function apply(p,anim){
    if(anim){d.classList.add('theme-anim');setTimeout(function(){d.classList.remove('theme-anim');},400);}
    d.setAttribute('data-theme-pref',p);
    d.setAttribute('data-theme',p==='system'?(mq.matches?'light':'dark'):p);
    document.querySelectorAll('.t-pick').forEach(function(b){b.setAttribute('aria-checked',b.dataset.th===p?'true':'false');});
  }
  apply(pref(),false);
  document.querySelectorAll('.t-pick').forEach(function(b){b.addEventListener('click',function(){try{localStorage.setItem(KEY,b.dataset.th);}catch(e){}apply(b.dataset.th,true);});});
  (mq.addEventListener?mq.addEventListener.bind(mq,'change'):mq.addListener.bind(mq))(function(){if(pref()==='system')apply('system',true);});
  window.addEventListener('storage',function(e){if(e.key===KEY)apply(pref(),true);});

  var mb=document.querySelector('.menu-btn'),nav=document.getElementById('top-nav');
  if(mb&&nav){mb.addEventListener('click',function(e){e.stopPropagation();var o=nav.classList.toggle('open');mb.setAttribute('aria-expanded',o?'true':'false');});
    document.addEventListener('click',function(e){if(!nav.contains(e.target)){nav.classList.remove('open');mb.setAttribute('aria-expanded','false');}});}

  document.querySelectorAll('pre').forEach(function(pre){
    var b=document.createElement('button');b.className='copy';b.type='button';b.textContent='Copy';
    b.onclick=function(){var t=pre.querySelector('code').innerText;(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent='Copied';b.classList.add('done');setTimeout(function(){b.textContent='Copy';b.classList.remove('done');},1400);}).catch(function(){b.textContent='Select & copy';});};
    pre.appendChild(b);
  });

  var links=[].slice.call(document.querySelectorAll('.side a'));
  if(links.length&&'IntersectionObserver'in window){
    var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){links.forEach(function(a){var on=a.getAttribute('href')==='#'+e.target.id;a.classList.toggle('on',on);if(on&&a.scrollIntoView&&innerWidth<900)a.parentNode.scrollTo({left:a.offsetLeft-12,behavior:'smooth'});});}});},{rootMargin:'-25% 0px -65% 0px'});
    links.forEach(function(a){var s=document.querySelector(a.getAttribute('href'));if(s)io.observe(s);});
  }

  var du=document.querySelector('.demo-user');if(du)setTimeout(function(){du.classList.add('in');},300);

  var top=document.querySelector('.to-top');
  if(top){addEventListener('scroll',function(){top.hidden=scrollY<700;},{passive:true});top.onclick=function(){scrollTo({top:0,behavior:'smooth'});};}

  var modal=document.getElementById('search-modal'),inp=document.getElementById('search-input'),list=document.getElementById('search-results'),idx=null,sel=0,root=(window.ORYVEX_SITE||{}).root||'';
  if(list)list.setAttribute('data-empty','Type to search every page');
  function load(){if(idx)return Promise.resolve(idx);return fetch(root+'assets/search-index.json').then(function(r){return r.json();}).then(function(j){idx=j;return j;}).catch(function(){idx=[];return idx;});}
  function escH(s){return s.replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function hl(s,q){var i=s.toLowerCase().indexOf(q);if(i<0)return escH(s.slice(0,110));var a=Math.max(0,i-40);return(a?'…':'')+escH(s.slice(a,i))+'<mark>'+escH(s.substr(i,q.length))+'</mark>'+escH(s.slice(i+q.length,i+q.length+70));}
  function run(){var q=inp.value.trim().toLowerCase();if(!q){list.innerHTML='';list.setAttribute('data-empty','Type to search every page');return;}
    var words=q.split(/\s+/);var res=(idx||[]).map(function(e){var t=(e.title+' '+e.text).toLowerCase(),s=0;for(var i=0;i<words.length;i++){if(t.indexOf(words[i])<0)return null;s+=e.title.toLowerCase().indexOf(words[i])>=0?3:1;}return{e:e,s:s};}).filter(Boolean).sort(function(a,b){return b.s-a.s;}).slice(0,12);
    sel=0;list.setAttribute('data-empty','Nothing found for "'+inp.value.trim()+'"');
    list.innerHTML=res.map(function(r,i){return'<li role="option" aria-selected="'+(i===0)+'"><a href="'+root+r.e.url+'"><span class="pg">'+escH(r.e.page)+'</span><b>'+escH(r.e.title)+'</b><small>'+hl(r.e.text,words[0])+'</small></a></li>';}).join('');}
  function open(){if(!modal)return;modal.hidden=false;load().then(run);setTimeout(function(){inp.focus();inp.select();},20);}
  function close(){if(modal)modal.hidden=true;}
  document.querySelectorAll('[data-search-open]').forEach(function(b){b.addEventListener('click',open);});
  if(modal){modal.addEventListener('click',function(e){if(e.target===modal)close();});inp.addEventListener('input',run);
    inp.addEventListener('keydown',function(e){var items=list.querySelectorAll('li');if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();if(!items.length)return;items[sel].setAttribute('aria-selected','false');sel=(sel+(e.key==='ArrowDown'?1:-1)+items.length)%items.length;items[sel].setAttribute('aria-selected','true');items[sel].scrollIntoView({block:'nearest'});}else if(e.key==='Enter'&&items[sel]){location.href=items[sel].querySelector('a').href;close();}});
    list.addEventListener('click',function(e){if(e.target.closest('a'))close();});}
  document.addEventListener('keydown',function(e){var t=e.target.tagName;if(e.key==='Escape'){close();if(nav)nav.classList.remove('open');}else if((e.key==='/'||(e.key==='k'&&(e.metaKey||e.ctrlKey)))&&t!=='INPUT'&&t!=='TEXTAREA'){e.preventDefault();open();}});
})();
