# BLS 中国站自动化项目

# 创建日期: 2026-05-26 09:09:00（北京时间 UTC+8）
# 更新日期: 2026-05-26 09:09:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 中国站自动化注册/登录逆向工程项目，实现签证申请网站的自动化操作

---

## 项目概述

本项目实现 BLS 中国站（西班牙签证申请网站）的自动化注册和登录功能，包括：

- 临时邮箱注册
- 滑块验证码识别（9 宫格图片选择）
- 代理支持
- 登录状态保持

## 目录结构

```
blscn/
├── *.py                        # 最终可用的脚本（入口脚本放根目录）
├── memory/                     # Agent 规则记忆存储
│   ├── CAPTCHA_ALGORITHM.md    # 验证码算法分析
│   ├── 逆向分析报告.md          # 逆向分析笔记
│   └── 流程.md                  # BLS 申请流程
├── res/                        # 分析资源目录
│   ├── js/                     # 提取的 JS 源码
│   ├── html/                   # 抓包的 HTML 页面
│   ├── har/                    # 流量抓包文件 (.har)
│   ├── captcha_debug/          # 验证码调试图片
│   ├── captcha_images/          # 验证码图片样本
│   ├── captcha_images_har/      # HAR 中提取的验证码图片
│   ├── ocr_model/              # 自训练 OCR 模型
│   └── *.json/*.png/*.html     # 中间分析产物
└── tmp/                        # 临时调试脚本（可清理）
    ├── debug_*.py              # 调试脚本
    ├── test_*.py               # 测试脚本
    └── captcha_img_*.png       # 临时验证码图片
```

## 核心脚本

| 脚本 | 说明 |
|------|------|
| `bls_auto_register.py` | 自动注册主脚本 |
| `blscn_register_mailtm_auto.py` | 临时邮箱自动注册 |
| `bls_login_change_password.py` | 登录和修改密码 |
| `bls_solve_captcha_auto.py` | 验证码自动求解 |
| `captcha_solver_final.py` | 验证码识别模块 |
| `blscn_send_code.py` | 发送验证码请求封装 |
| `blscn_register.py` | 注册主入口（模板） |

## 验证码机制

BLS 使用 9 宫格图片选择验证码：

```
┌─────────────────────────────────────────────────────────────┐
│                   请选择所有包含数字 817 的图片              │
├─────────┬─────────┬─────────┐
│ 图片 1  │ 图片 2  │ 图片 3  │  ← 每格约 4-5 张图叠加
├─────────┼─────────┼─────────┤        z-index 最高者显示
│ 图片 4  │ 图片 5  │ 图片 6  │
├─────────┼─────────┼─────────┤
│ 图片 7  │ 图片 8  │ 图片 9  │
└─────────┴─────────┴─────────┘
```

**核心原理**：
- 54 张图片分为 9 组，每组 6 层叠加
- CSS `display:none` 控制隐藏层
- 最终可见图片 = 每位置剩余中 z-index 最高的

详见 `memory/CAPTCHA_ALGORITHM.md`

## 模块架构

```
blscn_register.py (主入口)
├── 获取临时邮箱
│   └── blscn_register_mailtm_auto.py
├── 验证码识别
│   └── captcha_solver_final.py
└── 发送验证码请求
    └── blscn_send_code.py

bls_login_change_password.py (登录模块)
├── 登录请求
├── 忘记密码
└── 修改密码
```

## 环境依赖

```bash
pip install requests pillow ddddocr curl_cffi easyocr
```

## 使用说明

### 1. 注册新账号

```bash
python blscn_register_mailtm_auto.py
```

### 2. 登录并修改密码

```bash
python bls_login_change_password.py --username <邮箱> --password <密码>
```

### 3. 单独测试验证码识别

```bash
python -c "from captcha_solver_final import solve; print(solve())"
```

## 注意事项

- 网站可能封禁非西班牙 IP，建议使用西班牙代理
- 验证码 ID 有有效期，需在同一次会话中使用
- OCR 识别可能有误差，可多重试几次

## 更新日志

| 日期 | 版本 | 说明 |
|------|------|------|
| 2026-05-26 | v1.0 | 初始项目结构，应用文档规范 |
