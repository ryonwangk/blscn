# CAPTCHA_ALGORITHM.md
# 创建日期: 2026-05-22 14:00:00（北京时间 UTC+8）
# 更新日期: 2026-05-22 14:00:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 验证码图片可见性算法分析，记录 9 宫格图片选择器的纯算法获取方案

# BLS 验证码图片可见性 - 纯算法获取方案

## 1. 问题背景

验证码页面 (`/CHN/CaptchaPublic/GenerateCaptcha`) 是一个 **9 宫格图片选择题**。

- 页面显示 9 张图片（3×3 网格）和 1 个问题文字（如 "Please select all boxes with number 817"）
- 用户需要在 9 张图中**点击所有包含数字 817 的图片**，然后提交
- 服务器返回 `{"success": true, "captcha": "..."}` 表示成功

**核心问题**：9 张可见图片是如何从 HTML 中确定的？它们不是直接列出来的。

---

## 2. HTML 结构分析

### 2.1 图片层（Layered Images）

页面 HTML 中实际包含 **54 张图片**，分为 9 组，每组 6 层，堆叠在 9 个网格位置上：

```
网格位置 (left, top):
  (0, 0)     (110, 0)    (220, 0)
  (0, 110)   (110, 110)  (220, 110)
  (0, 220)   (110, 220)  (220, 220)
```

每组 6 层叠加在同一位置，形成"层叠"效果。

### 2.2 HTML 中图片的存储格式

图片以 **base64 内嵌**形式存储在 HTML 中：

```html
<div id="xyz123" class="col-4 random-class-a random-class-b ..." style="padding:5px;">
    <img style="width:100px;height:100px;" class="captcha-img"
         src="data:image/gif;base64,/9j/4AAQSkZJRgABAQAAAQ..." />
</div>
```

关键点：
- 每个 `<img>` 的父 `<div>` 有唯一的随机 `id`
- `class` 里有多个随机生成的 CSS class 名
- `src` 是 base64 编码的 JPEG 图片

### 2.3 Box-Label（问题标签）

显示在顶部的重叠层，用于显示问题文字：

```html
<div class='col-12 box-label random-a random-b' id='abc456'>
    Please select all boxes with number 817
</div>
```

---

## 3. CSS 的作用

### 3.1 随机 CSS 类

CSS 中为每个随机 class 定义了 `position`、`left`、`top`、`z-index`：

```css
.abc123 { z-index: 3848; position: absolute; left: 0px; top: 0px; }
.def456 { z-index: 8270; position: absolute; left: 0px; top: 0px; display: none; }
.ghi789 { z-index: 1429; position: absolute; left: 0px; top: 0px; }
```

关键规则：
- **`position: absolute`** + **`left/top`** → 决定 div 在哪个网格位置
- **`z-index`** → 决定层的上下顺序
- **`display: none`** → 如果 class 有这条规则，整个 div 被隐藏

### 3.2 可见性判断

判断一个 div 是否可见的规则：

```
遍历该 div 的所有 class：
  如果任何一个 class 在 CSS 中定义了 display:none → 该 div 不可见
  否则 → 该 div 可见
```

**不需要执行 JavaScript！** 可见性完全由 CSS 的 `display` 规则决定。

---

## 4. 最终可见图片的选取算法

对于每个网格位置 `(left, top)`：

```
Step 1: 找出该位置上所有 div
Step 2: 过滤掉 display:none 的 div
Step 3: 在剩余的可见 div 中，取 z-index 最高的那个
```

这就是该位置最终显示的图片。

**验证结果**：
- MCP 浏览器实测：9 个位置 × 平均 4-5 层可见 = 约 27 个可见 div
- Python 算法结果：完全一致
- 最终每位置取最高 z-index 的 9 张图片 = 9 张可见图

---

## 5. 完整算法流程

### Step 1: 获取验证码页面 HTML

```
GET /CHN/CaptchaPublic/GenerateCaptcha?data=<SecurityCode>
```

### Step 2: 解析 CSS

```python
# 提取每个 class 的 display / z-index / left / top
for class_name, properties in css_rules:
    if 'display' in properties:
        display_map[class_name] = extract_display(properties)
    if 'z-index' in properties:
        z_index_map[class_name] = extract_z_index(properties)
    if 'left' in properties:
        left_map[class_name] = extract_left(properties)
    if 'top' in properties:
        top_map[class_name] = extract_top(properties)
```

### Step 3: 解析图片 div

```python
# 匹配 <div id="xxx" class="..."><img class="captcha-img" src="data:image/gif;base64,..."/>
for div_id, src, div_class_list in img_div_elements:
    # 计算该 div 的 position 和 z-index
    left = max(left_map.get(c) for c in div_class_list if c in left_map)
    top  = max(top_map.get(c) for c in div_class_list if c in top_map)
    z    = max(z_index_map.get(c) for c in div_class_list if c in z_index_map)

    # 判断是否可见 (CSS display 规则)
    is_hidden = any(
        display_map.get(c) == 'none'
        for c in div_class_list
        if c in display_map
    )

    if not is_hidden:
        visible_divs.append({
            'id': div_id,
            'src': src,
            'left': left,
            'top': top,
            'z': z
        })
```

### Step 4: 按位置选取最佳图片

```python
# 对每个 (left, top) 位置，取 z-index 最高的可见 div
GRID_POSITIONS = [(0,0), (0,110), (0,220),
                  (110,0), (110,110), (110,220),
                  (220,0), (220,110), (220,220)]

visible_images = {}
for div in visible_divs:
    key = (div['left'], div['top'])
    if key not in visible_images or div['z'] > visible_images[key]['z']:
        visible_images[key] = div

# 结果: 9 张可见图片的 id 和 base64 src
```

### Step 5: 提取目标数字

```python
# 从 box-label 中提取数字
for label_element in label_elements:
    digit = extract_number_from_text(label_element.text)
    # box-label 也通过 CSS z-index 堆叠
    # 取 z-index 最高的可见 label，就是最终显示的问题
    all_labels.append((label_z_index, digit))

target_digit = max(all_labels)[1]  # 如 "817"
```

### Step 6: OCR + 匹配

```python
import ddddocr
ocr = ddddocr.DdddOcr(show_ad=False, beta=True)

selected_ids = []
for position, image in visible_images.items():
    img_data = base64_decode(image['src'])
    ocr_result = ocr.classification(img_data)  # 如 "817" 或 "819"
    if target_digit in ocr_result:
        selected_ids.append(image['id'])
```

### Step 7: 提交

```
POST /CHN/CaptchaPublic/SubmitCaptcha
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Referer: https://spain.blscn.cn/CHN/CaptchaPublic/GenerateCaptcha?data=...

SelectedImages=id1,id2,id3,id4&Id=<Id>&Captcha=<Captcha>&__RequestVerificationToken=<token>
```

成功响应：`{"success": true, "captcha": "..."}`

---

## 6. 关键结论

| 问题 | 答案 |
|------|------|
| 9 张可见图如何确定？ | 每个网格位置的 div 通过 CSS 的 `display:none` 隐藏部分层，再取剩余中 z-index 最高的 |
| 需要执行 JS 吗？ | **不需要**。可见性完全由 CSS 规则决定，纯静态解析即可 |
| CSS 类名是固定的吗？ | 不是，每次刷新都随机生成，完全由服务器决定 |
| 如何知道哪些 class 控制 display？ | 解析 CSS 中的 `.classname{display:none;}` 规则 |
| 为什么只选 1 张而不是多张？ | 需要选择**所有**匹配目标数字的图片（多选），通过 OCR 对比数字来决定 |

---

## 7. 常见错误排查

| 症状 | 原因 |
|------|------|
| 正则匹配不到 img div | HTML 混用单/双引号，需要同时支持 `id='xxx'` 和 `id="xxx"` |
| base64 解码失败 | HTML 中的 `+` 被编码为 `&#x2B;`，需要先实体解码再 base64 |
| HTTP 返回的不是 HTML | 服务器可能返回 gzip 压缩，需要判断 `Content-Encoding` 响应头 |
| 提交的 ID 在 HTML 中找不到 | Session 过期，SecurityCode 已失效 |
