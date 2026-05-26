// 粘贴到浏览器验证码页面的控制台
(function(){
var sc={};
try{var sh=document.styleSheets;
for(var si=0;si<sh.length;si++){var rs=sh[si].cssRules||sh[si].rules||[];
for(var ri=0;ri<rs.length;ri++){var r=rs[ri];
if(!r.selectorText||!r.selectorText.startsWith('.'))continue;
var cls=r.selectorText.substring(1);
var dp=r.style.getPropertyValue('display');
var pr=r.style.getPropertyPriority('display');
if(dp&&pr==='important')sc[cls]=dp;}}}
catch(e){}
var g={'rvndhl':1,'evmgwewcv':1,'pmnhxjya':1,'dyocusr':1,'xpvfjtu':1,'bogxikqc':1,'xwxvm':1,'pcvptmiw':1,'qyaem':1};
var imgs=document.querySelectorAll('img.captcha-img');
var vis={};
for(var img of imgs){
var p=img.parentElement;while(p&&p.tagName!=='DIV')p=p.parentElement;
if(!p||!p.id||!g[p.id])continue;
if(window.getComputedStyle(p).display==='none')continue;
vis[p.id]=img.src;}
var lbls=document.querySelectorAll('[class*="box-label"]');
var labelZ=[];
for(var lbl of lbls){
if(window.getComputedStyle(lbl).display==='none')continue;
var m=lbl.textContent.match(/number (\d+)/);
if(m)labelZ.push({d:m[1],z:0});}
labelZ.sort(function(a,b){return b.z-a.z;});
var target=labelZ[0]?labelZ[0].d:'';
var x=new XMLHttpRequest();
x.open('POST','http://127.0.0.1:8765',false);
x.setRequestHeader('Content-Type','application/json');
x.send(JSON.stringify({target:target,images:vis}));
var res=JSON.parse(x.responseText);
var sel=[];
for(var id in res)if(res[id].match)sel.push(id);
if(sel.length===0){alert('no match:'+target);return;}
var pwds=document.querySelectorAll('input[type=password]');
var vp=null;
for(var pwd of pwds){
if(window.getComputedStyle(pwd.parentElement).display!=='none'){vp=pwd;break;}}
if(!vp){alert('no vis pwd');return;}
vp.value='386929';
var form=document.querySelector('form');
var pnames=[];for(var p2 of pwds)pnames.push(p2.name);
var rd={};for(var n of pnames)rd[n]=(n===vp.name)?'386929':'';
form.querySelector('input[name=ResponseData]').value=JSON.stringify(rd);
form.querySelector('input[name=SelectedImages]').value=sel.join(',');
form.submit();
})();
