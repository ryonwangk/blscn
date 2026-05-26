# -*- coding: utf-8 -*-
"""
最终版验证码解决方案 - blscn 登录
核心逻辑:
  1. 可见9图 = 每个格子位置(left,top)上 z-index 最高的 div
  2. Target = box-label 中 color=rgb(33,37,41) 的那一条
  3. 密码框 = display!==none 的 input[type=password]
  4. 识别出包含 target 数字的图片后, 浏览器自动选点提交
"""
import json, time
import requests

# ==================== 配置 ====================
BLS_URL = "https://spain.blscn.cn/CHN/account/login"
EMAIL = "turquoise5548@wshu.net"
PWD = "386929"
CAPTCHA_DATA_JSON = None  # 如果已从浏览器获取了JSON数据, 直接填在这里
# ============================================

def get_visible_grid_from_page():
    """
    从浏览器页面提取可见9图的 base64 + target + pwdField + pnames
    返回 dict
    """
    import subprocess
    # 使用 PowerShell 通过 Chrome DevTools Protocol 获取数据
    # 但更简单的是直接用浏览器 evaluate script
    raise NotImplementedError("请通过 MCP 工具在浏览器中执行 JS 提取数据")


def solve_by_browser_js(captcha_data_json):
    """
    captcha_data_json: 浏览器 evaluate 得到的 JSON 字符串
    返回 {"target": "511", "pwdField": "dfixowc", "pnames": [...], "imgs": {"id": {"src":"data:...", "l":"0px","t":"0px"}}}
    """
    data = json.loads(captcha_data_json)
    target = data["target"]
    pwd_field = data["pwdField"]
    pnames = data["pnames"]
    imgs = data["imgs"]

    # 按位置排序 (3x3 grid)
    def pos_key(item):
        l = int(item[1]['l'].rstrip('px'))
        t = int(item[1]['t'].rstrip('px'))
        return (t, l)

    sorted_imgs = sorted(imgs.items(), key=pos_key)

    # OCR 识别 (本地服务挂了则跳过, 人工介入)
    OCR_URL = "http://127.0.0.1:8765/ocr"
    selected = []

    for bid, info in imgs.items():
        src = info["src"]
        if not src.startswith("data:image"):
            continue
        b64 = src.split(",", 1)[1]
        img_data = base64.b64decode(b64) if 'base64' in globals() else None
        if not img_data:
            import base64 as b64mod
            img_data = b64mod.b64decode(b64)

        try:
            resp = requests.post(OCR_URL, files={"image": ("img.gif", img_data, "image/gif")}, timeout=20)
            ocr_text = resp.json().get("text", "").strip()
            print(f"  {bid}: '{ocr_text}'")
            if target in ocr_text:
                selected.append(bid)
                print(f"    *** MATCH ***")
        except Exception as e:
            print(f"  {bid}: OCR failed - {e}")

    return {
        "target": target,
        "pwdField": pwd_field,
        "pnames": pnames,
        "selected": selected,
        "sortedGrid": [(bid, info) for bid, info in sorted_imgs]
    }


def build_browser_submit_script(solved_data):
    """
    生成在浏览器控制台执行的 JS 脚本, 选点 + 填表 + 提交
    """
    target = solved_data["target"]
    pwd_field = solved_data["pwdField"]
    pnames = solved_data["pnames"]
    selected = solved_data["selected"]

    script = f"""
(function(){{
var target='{target}';
var pwdField='{pwd_field}';
var selected={json.dumps(selected)};
var pnames={json.dumps(pnames)};

// 找密码框
var pwds=document.querySelectorAll('input[type=password]');
var vp=null;
for(var p of pwds){{
if(window.getComputedStyle(p.parentElement).display!=='none'){{vp=p;break;}}
}}
if(!vp){{console.log('no pwd field');return;}}
vp.value='{PWD}';

// 填 ResponseData
var form=document.querySelector('form');
var rd={{}};
for(var n of pnames)rd[n]=(n===pwdField)?'{PWD}':'';
form.querySelector('input[name=ResponseData]').value=JSON.stringify(rd);

// 选图
if(selected.length===0){{
console.log('WARNING: No images selected! Please select manually.');
return;
}}

// 点击每个选中格子的 div
for(var sid of selected){{
var div=document.getElementById(sid);
if(div){{
var cs=window.getComputedStyle(div);
if(cs.display!=='none'){{
div.click();
console.log('Clicked: '+sid);
}}
}}
}}

// 填 SelectedImages
form.querySelector('input[name=SelectedImages]').value=selected.join(',');

// 延迟提交
setTimeout(function(){{
form.submit();
console.log('Submitted!');
}}, 500);
}})();
"""
    return script


def main():
    if CAPTCHA_DATA_JSON:
        solved = solve_by_browser_js(CAPTCHA_DATA_JSON)
    else:
        print("请先在浏览器中执行以下 JS, 将结果保存到 captcha_data.json:")
        print()
        js_template = """
(function(){
var divs=document.querySelectorAll('div');
var byPos={};
for(var d of divs){
  if(!d.id)continue;
  var cs=window.getComputedStyle(d);
  if(cs.display==='none'||cs.position!=='absolute')continue;
  var img=d.querySelector('img.captcha-img');
  if(!img)continue;
  var key=cs.left+','+cs.top;
  var z=parseInt(cs.zIndex)||0;
  if(!byPos[key]||z>byPos[key].z){byPos[key]={id:d.id,z:z,left:cs.left,top:cs.top,src:img.src};}
}
var imgs={};
for(var k in byPos){imgs[byPos[k].id]={src:byPos[k].src,l:byPos[k].left,t:byPos[k].top};}

var lbls=document.querySelectorAll('[class*="box-label"]');
var target='';
for(var lbl of lbls){
  if(window.getComputedStyle(lbl).display==='none')continue;
  var cs2=window.getComputedStyle(lbl);
  if(cs2.color==='rgb(33, 37, 41)'){var m=lbl.textContent.match(/number (\\d+)/);if(m){target=m[1];break;}}
}

var pwds=document.querySelectorAll('input[type=password]');
var vp=null;for(var p of pwds){if(window.getComputedStyle(p.parentElement).display!=='none'){vp=p.name;break;}}
var pnames=[];for(var p2 of pwds)pnames.push(p2.name);

return JSON.stringify({target:target,pwdField:vp,pnames:pnames,imgs:imgs});
})()
"""
        print(js_template)
        return

    print(f"Target: {solved['target']}")
    print(f"Selected: {solved['selected']}")

    if not solved["selected"]:
        print("\nOCR失败, 请手动选图后执行提交脚本")
        return

    script = build_browser_submit_script(solved)
    print("\n=== 浏览器提交脚本 ===")
    print(script)


if __name__ == "__main__":
    main()
