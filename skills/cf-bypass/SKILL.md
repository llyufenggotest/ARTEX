---
name: cf-bypass
description: 破 Cloudflare / Turnstile / managed challenge 盾。遇到被盾拦截的目标（403 + cf-mitigated、Just a moment、Turnstile widget、challenge loop）时必须先用本技能的方法过盾，再做后续测试。附带图形验证码 OCR 识别。
allowed-tools: Bash(bash:*) Bash(python3:*) Bash(sh:*)
---

# CF 盾破解（DrissionPage + CDP pierce 实战验证）

## 判断盾类型

```bash
# 一发探测：看响应头
curl -sI https://target.example/ | grep -iE "cf-mitigated|server|cf-ray"
# cf-mitigated: challenge = managed challenge（要交互点击）
# 403 + 无 cf-mitigated = WAF 拦截（换 UA / TLS 指纹，不需要浏览器）
# Turnstile widget = 页面里有 0x4AAAA... sitekey 的 iframe
```

## 核心铁律（实测血泪）

1. **headless 必死**：CF 检测 CDP/headless 指纹，`headless=True` 永远过不了 managed challenge。必须 `headless(False)` + Xvfb 虚拟显示（容器内 `DISPLAY=:99` 已由 start.sh 常驻）。
2. **CDP pierce 点击**：Turnstile 复选框在 shadow DOM 里，普通选择器（`@type=checkbox`）匹配不到，点了等于没点。必须用 `DOM.getDocument(depth=-1, pierce=True)` 拿 backendNodeId → `DOM.getBoxModel` 算坐标 → `Input.dispatchMouseEvent` 点击。
3. **出口 IP 质量**：数据中心 IP（AWS/GCP）经常被静默拒（过了盾也不放行）。优先住宅/家宽出口；同一个出口连续打 ~20 请求可能被拉黑，盾破了赶紧把 cookie 存下来复用。
4. **cookie 复用**：过盾后 `cf_clearance` + 会话 cookie 全存盘，后续请求全部带上，别每次重新过盾。注意 cf_clearance 绑定 IP+UA，换出口要重新过。

## 破盾脚本（模板）

```python
import os, time, json
os.environ['DISPLAY'] = ':99'  # 容器内已常驻 Xvfb
from DrissionPage import ChromiumPage, ChromiumOptions

co = ChromiumOptions()
co.set_browser_path('/usr/bin/chromium')  # playwright 装的也行，find 一下
co.set_local_port(9550)                    # 每任务独立端口=独立 profile
co.headless(False)                         # 铁律 1
co.set_proxy('http://宿主:17890')          # 出口代理，见铁律 3
co.set_argument('--no-sandbox')
co.set_argument('--disable-dev-shm-usage')
p = ChromiumPage(co)

p.get('https://target.example/', timeout=60)
time.sleep(4)

if 'moment' in p.title.lower() or 'challenge' in p.title.lower():
    # CDP pierce 找 iframe 复选框（铁律 2）
    doc = p.run_cdp('DOM.getDocument', depth=-1, pierce=True)
    boxes = []
    def walk(n):
        if n.get('nodeName') == 'IFRAME':
            boxes.append(n['backendNodeId'])
        for c in (n.get('children') or []): walk(c)
        for c in (n.get('shadowRoots') or []): walk(c)
        if n.get('contentDocument'): walk(n['contentDocument'])
    walk(doc['root'])
    for bid in boxes:
        try:
            q = p.run_cdp('DOM.getBoxModel', backendNodeId=bid)['model']['content']
        except Exception:
            continue
        x, y = min(q[0::2]), min(q[1::2])
        w, h = max(q[0::2]) - x, max(q[1::2]) - y
        if w < 50: continue  # 太小的是隐藏帧
        for t in ('mouseMoved', 'mousePressed', 'mouseReleased'):
            p.run_cdp('Input.dispatchMouseEvent', type=t,
                      x=int(x + 30), y=int(y + h / 2),
                      button='left', clickCount=1)
            time.sleep(0.15)
        break
    # 等 title 变化（一般 2-8 秒）
    t0 = time.time()
    while time.time() - t0 < 40:
        if 'moment' not in p.title.lower(): break
        time.sleep(1.5)

print('title:', p.title)  # 不是 Just a moment = 过了

# 过盾后立刻存 cookie + 复用
cookies = p.cookies()  # list of dict
json.dump(cookies, open('/app/data/cf_cookies.json', 'w'))
```

## 图形验证码（ddddocr）

```python
# 在已过盾的浏览器上下文里 fetch 验证码图（保持同源 cookie）
b64 = p.run_js("return fetch('/captcha.jpg', {credentials:'include'})"
               ".then(r=>r.arrayBuffer()).then(b=>{var u=new Uint8Array(b),s='';"
               "for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s)})")
import base64
open('/tmp/cap.png','wb').write(base64.b64decode(b64))
import subprocess
r = subprocess.run(['python3','-c',
    'import ddddocr; o=ddddocr.DdddOcr(); print(o.classification("/tmp/cap.png"))'],
    capture_output=True, text=True)
code = r.stdout.strip().split('\n')[-1]
```

注意：类名是 `DdddOcr`（大写 O 小写 c r），写错 import 报错。

## 登录表单坑

- **不要用 DOM click 提交**：很多站点的 submit 按钮带 JS 校验/字段禁用，click 后字段值传不到。**用浏览器上下文 fetch 直接 POST**（保 cookie 保 token）：

```python
r = p.run_js("""
return fetch('/login.php', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body: 'token=' + tk + '&username=USER&password=PASS&code=' + capcode
}).then(r => 'STATUS=' + r.status)
""")
```

- CSRF token 从 DOM 拿：`document.querySelector('input[name=token]').value`
- 失败重试 5 次：每次重取验证码重识别，token 可能刷新

## 无交互盾（403 但无 challenge 页）

TLS 指纹被拦，不需要浏览器，用 curl_cffi：

```python
from curl_cffi import requests
r = requests.get('https://target.example/',
                 impersonate='chrome131')  # JA3 指纹伪装
```

## 何时换路

- 同一出口 3 次点击全不过 → 换出口 IP（找 operator 或换代理）
- managed challenge 过了但目标站对住宅 IP 才放行 → 报 operator，别死磕
- cf_clearance 拿到了但请求还是 403 → 检查 UA 是否和过盾时一致、IP 是否变了
