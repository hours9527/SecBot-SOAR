import telebot
import imaplib
import email
from email import policy
import requests
import re
from urllib.parse import urlparse
import time
import threading
import hashlib  # <--- 新增这行，用于计算附件的 SHA-256 特征码

# ==========================================
# 📖 威胁情报百科字典 (CTI 翻译官)
# ==========================================
THREAT_DICT = {
    "trojan": "🐎 **木马/远控** (潜伏在后台，窃取密码或被黑客远程控制)",
    "ransom": "🔒 **勒索软件** (极其致命！会加密破坏文件，勒索加密货币)",
    "phishing": "🎣 **钓鱼/欺诈** (伪装正规网站，骗取账号密码或财务信息)",
    "stealer": "🕵️ **窃密客** (专门偷取浏览器中保存的密码、Cookie)",
    "miner": "⛏️ **挖矿木马** (偷偷占用CPU/显卡疯狂挖矿，导致严重卡顿)",
    "worm": "🐛 **蠕虫病毒** (具横向移动能力，会自动传染局域网其他电脑)",
    "adware": "📢 **广告流氓** (疯狂弹窗，强制篡改浏览器主页，通常不致命)",
    "backdoor": "🚪 **后门程序** (给黑客偷偷开系统后门，随时能潜入电脑)"
}
# ==========================================
# 📖 本地静态规则特征库 (YARA-Lite)
# ==========================================
STATIC_RULES = {
    # 业界标准的 EICAR 恶意软件测试字符串
    "EICAR_AV_TEST": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    # 业界标准的 GTUBE 垃圾邮件测试字符串
    "GTUBE_SPAM_TEST": "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
}

# ==========================================
# ⚙️ 终极配置中心 (已脱敏)
# ==========================================
TG_BOT_TOKEN = "your_telegram_bot_token_here".strip()
TG_CHAT_ID = "your_telegram_chat_id_here".strip()
VT_API_KEY = "your_virustotal_api_key_here".strip()

IMAP_SERVER = "imap.qq.com"
EMAIL_ACCOUNT = "your_email_address_here".strip()
EMAIL_PASSWORD = "your_email_password_here".strip()

bot = telebot.TeleBot(TG_BOT_TOKEN)

# ==========================================
# 模块 1: 威胁情报核心引擎 (骨灰级溯源版)
# ==========================================
def scan_vt(domain):
    """请求 VT 获取域名深度情报与具体查杀引擎详情"""
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            attr = resp.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            reputation = attr.get('reputation', 0)
            categories = attr.get('categories', {})
            tags = list(set(categories.values()))[:3] if categories else ["未知资产类型"]
            
            analysis_results = attr.get('last_analysis_results', {})
            malware_details = []
            behaviors_found = set()
            
            for engine, result_data in analysis_results.items():
                if result_data['category'] in ['malicious', 'suspicious']:
                    virus_name = result_data.get('result', '恶意载荷') 
                    malware_details.append(f"    ┠ 🛡️ {engine}: `{virus_name}`")
                    
                    name_lower = virus_name.lower()
                    for keyword, explanation in THREAT_DICT.items():
                        if keyword in name_lower:
                            behaviors_found.add(explanation)
            
            details_str = "\n".join(malware_details[:5])
            if len(malware_details) > 5:
                details_str += f"\n    ┗ ...等共 {len(malware_details)} 家安全引擎拦截"
            elif not malware_details:
                details_str = "    ┗ (暂无具体特征命中记录)"

            behavior_str = "\n".join([f"  ┠ {b}" for b in behaviors_found]) if behaviors_found else "  ┗ 暂无明确的攻击行为画像"
                
            return {
                "mal": stats['malicious'], "sus": stats['suspicious'], 
                "har": stats['harmless'], "rep": reputation,
                "tags": ", ".join(tags), "details": details_str,
                "behavior": behavior_str
            }
    except Exception as e:
        print(f"VT 域名请求异常: {e}")
    return {"mal": 0, "sus": 0, "har": 0, "rep": 0, "tags": "解析失败", "details": "", "behavior": ""}

def scan_vt_ip(ip):
    """请求 VT 获取 IP 物理归属与黑产信誉"""
    if ip == "未知": return {"mal": 0, "sus": 0, "country": "未知", "asn": "未知", "rep": 0}
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            attr = resp.json()['data']['attributes']
            return {
                "mal": attr['last_analysis_stats']['malicious'], 
                "sus": attr['last_analysis_stats']['suspicious'], 
                "country": attr.get('country', '未知地区'),
                "asn": attr.get('as_owner', '未知运营商'),
                "rep": attr.get('reputation', 0)
            }
    except Exception as e:
        print(f"VT IP 请求异常: {e}")
    return {"mal": 0, "sus": 0, "country": "未知", "asn": "未知", "rep": 0}
def scan_vt_file(file_hash):
    """请求 VT 获取附件 SHA-256 的查杀结果"""
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            attr = resp.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            
            # 同样提取具体的查杀引擎结果
            analysis_results = attr.get('last_analysis_results', {})
            malware_details = []
            for engine, result_data in analysis_results.items():
                if result_data['category'] in ['malicious', 'suspicious']:
                    virus_name = result_data.get('result', '恶意附件')
                    malware_details.append(f"    ┠ 🛡️ {engine}: `{virus_name}`")
            
            details_str = "\n".join(malware_details[:5])
            if not malware_details: details_str = "    ┗ (暂无具体特征命中记录)"
            
            return {"mal": stats['malicious'], "sus": stats['suspicious'], "details": details_str}
        elif resp.status_code == 404:
            return {"mal": 0, "sus": 0, "details": "    ┗ ⚠️ 云端沙箱未收录此文件，极度可疑的未知 0day 载荷！"}
    except Exception as e:
        print(f"VT 文件请求异常: {e}")
    return {"mal": 0, "sus": 0, "details": ""}

def extract_sender_ip(msg):
    """剥离伪造头，提取发件人真实物理 IP"""
    origin_ip = str(msg.get('X-Originating-IP', ''))
    if origin_ip:
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', origin_ip)
        if ip_match: return ip_match.group(0)

    received_headers = msg.get_all('Received')
    if received_headers:
        for header in reversed(received_headers):
            for ip in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(header)):
                if not ip.startswith(('10.', '192.168.', '172.', '127.')): return ip
    return "未知"

# ==========================================
# 模块 2: 后台邮件暗哨 (生产环境稳定版)
# ==========================================
def mail_monitor_daemon():
    WHITELIST = ['qq.com', '163.com', 'baidu.com', 'github.com', 'microsoft.com', 
                 'apple.com', 'zhaopin.com', '51job.com', 'bosszhipin.com', 'liepin.com']
    POLL_INTERVAL = 180 
    
    while True:
        mail = None
        try:
            print("[后台暗哨] 正在连接邮箱...")
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
            mail.select('inbox')
            
            status, messages = mail.search(None, 'UNSEEN')
            email_ids = messages[0].split()
            
            if email_ids:
                latest_email_id = email_ids[-1]
                _, msg_data = mail.fetch(latest_email_id, '(RFC822)')
                
                # 🚨 致命 Bug 修复：强制将邮件标记为已读，防止无限死循环读取！
                mail.store(latest_email_id, '+FLAGS', '\\Seen')
                
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1], policy=policy.default)
                        subject = msg['Subject']
                        print(f"\n[后台暗哨] 🚨 发现新邮件: {subject}")
                        
                        # --- 阶段 1: IP 溯源 ---
                        print(f"  ┠ 正在穿透伪造头，追踪真实发件 IP...")
                        real_ip = extract_sender_ip(msg)
                        ip_data = scan_vt_ip(real_ip)
                        print(f"  ┠ 锁定源 IP: {real_ip} [{ip_data['country']} | {ip_data['asn']}]")
                        
                        if ip_data['mal'] > 0 or ip_data['sus'] > 0:
                            alert_msg = (
                                f"🚨 **[SOC 异常来源溯源告警]** 🚨\n━━━━━━━━━━━━━━━━━━━━━━\n"
                                f"📧 **邮件主题:** `{subject}`\n👤 **表面发件人:** `{msg.get('From')}`\n\n"
                                f"🌍 **物理溯源结果:**\n  ┠ 真实 IP: `{real_ip}`\n"
                                f"  ┠ 物理定位: **{ip_data['country']}**\n  ┗ 运营商: `{ip_data['asn']}`\n\n"
                                f"📈 **威胁情报库判定:** 此服务器已被 `{ip_data['mal']}` 家安全厂商标记为僵尸网络！\n"
                                f"━━━━━━━━━━━━━━━━━━━━━━"
                            )
                            requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", 
                                          json={"chat_id": TG_CHAT_ID, "text": alert_msg, "parse_mode": "Markdown"})
                            print(f"  ┠ [!] IP 溯源告警已推送！")
                            
                            # 🛡️ 保护 API 额度：查完恶意 IP 后强制冷却，再查域名
                            print("  ┠ (API 冷却缓冲 15 秒...)")
                            time.sleep(15)
                            
                        # =======================================
                        # --- 阶段 2: 静态特征与附件不落地查杀 ---
                        # =======================================
                        print(f"  ┠ 正在进行深度内容解析 (附件提取 & 静态规则匹配)...")
                        body = ""
                        
                        # 遍历邮件的所有组件（正文、HTML、附件）
                        for part in msg.walk():
                            # 1. 提取正文内容 (用于后面的静态规则和链接提取)
                            if part.get_content_type() in ['text/plain', 'text/html']:
                                try:
                                    chunk = part.get_content()
                                    if chunk: body += chunk
                                except: pass
                                
                            # 2. 🛡️ 核心大招：提取附件并计算文件不落地 Hash
                            filename = part.get_filename()
                            if filename:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    # 在内存中直接计算 SHA-256，绝不将病毒保存到本地硬盘！
                                    file_hash = hashlib.sha256(payload).hexdigest()
                                    print(f"  ┠ 📎 捕获附件: `{filename}`")
                                    print(f"  ┠ 正在呼叫云端沙箱进行 Hash 查杀: {file_hash} ...")
                                    
                                    vt_file = scan_vt_file(file_hash)
                                    if vt_file.get("mal", 0) > 0 or vt_file.get("sus", 0) > 0:
                                        alert_msg = (
                                            f"🚨 **[SOC 恶意附件告警]** 🚨\n━━━━━━━━━━━━━━━━━━━━━━\n"
                                            f"📧 **邮件主题:** `{subject}`\n"
                                            f"📎 **高危附件:** `{filename}`\n"
                                            f"🧬 **SHA-256:** `{file_hash}`\n\n"
                                            f"🦠 **云端查杀分布 ({vt_file['mal']}家报毒):**\n"
                                            f"{vt_file['details']}\n━━━━━━━━━━━━━━━━━━━━━━"
                                        )
                                        requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", json={"chat_id": TG_CHAT_ID, "text": alert_msg, "parse_mode": "Markdown"})
                                        print(f"  ┠ [!] 恶意附件告警已推送！")
                                        time.sleep(15) # 防风控冷却

                        # 3. ⚡ 极速防御：本地静态规则 (YARA-Lite) 匹配
                        static_rule_hit = False
                        for rule_name, rule_string in STATIC_RULES.items():
                            if rule_string in body:
                                static_rule_hit = True
                                alert_msg = (
                                    f"🚨 **[SOC 静态规则命中告警]** 🚨\n━━━━━━━━━━━━━━━━━━━━━━\n"
                                    f"📧 **邮件主题:** `{subject}`\n"
                                    f"⚡ **触发高危特征:** `{rule_name}`\n"
                                    f"🛡️ **防御机制:** 本地规则秒杀，零延迟拦截！\n━━━━━━━━━━━━━━━━━━━━━━"
                                )
                                requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", json={"chat_id": TG_CHAT_ID, "text": alert_msg, "parse_mode": "Markdown"})
                                print(f"  ┠ [!] 触发本地静态规则: {rule_name}，告警已推送！")
                                break # 命中一个足以定罪，直接跳出循环

                        # =======================================
                        # --- 阶段 3: 传统域名查杀 ---
                        # =======================================
                        if not static_rule_hit: # 如果已经被本地规则秒杀了，就没必要浪费 API 去查域名了
                            print(f"  ┠ 正在提取邮件正文链接...")
                            urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*', body)
                            domains = list(set([urlparse(u).netloc for u in urls if urlparse(u).netloc]))
                            
                            suspicious_domains = [d for d in domains if not any(d.endswith(w) for w in WHITELIST)]
                            print(f"  ┠ 提取总域名: {len(domains)} 个 | 过滤后剩余可疑目标: {len(suspicious_domains)} 个")
                            
                            targets_to_scan = suspicious_domains[:3] 
                            
                            if targets_to_scan:
                                for index, target_domain in enumerate(targets_to_scan):
                                    print(f"  ┠ 呼叫云端沙箱检测域名: {target_domain} ...")
                                    vt_data = scan_vt(target_domain)
                                    
                                    if vt_data["mal"] > 0 or vt_data["sus"] > 0:
                                        alert_msg = (
                                            f"🚨 **[SOC 自动化防御拦截告警]** 🚨\n━━━━━━━━━━━━━━━━━━━━━━\n"
                                            f"📧 **邮件主题:** `{subject}`\n🎯 **恶意载荷:** `{target_domain}`\n\n"
                                            f"💡 **AI 威胁行为画像:**\n{vt_data['behavior']}\n\n"
                                            f"📊 **资产画像:** 信誉 `{vt_data['rep']}` | 标签 `{vt_data['tags']}`\n"
                                            f"🦠 **查杀引擎分布 ({vt_data['mal']}家报毒):**\n{vt_data['details']}\n"
                                            f"━━━━━━━━━━━━━━━━━━━━━━"
                                        )
                                        requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", json={"chat_id": TG_CHAT_ID, "text": alert_msg, "parse_mode": "Markdown"})
                                        print(f"  ┠ [!] 域名告警已推送！")
                                    else:
                                        print(f"  ┠ [放行] 资产信誉良好。")
                                    
                                    if index < len(targets_to_scan) - 1:
                                        print("  ┠ (系统冷却 15 秒...)")
                                        time.sleep(15)
                            else:
                                print("  ┗ [系统放行] 邮件内无高危链接，且未触发静态规则。")
                        else:
                            print("  ┗ [系统拦截] 邮件已被本地规则拦截，跳过域名检测。")
                            
        except Exception as e:
            print(f"[后台暗哨] 监听异常: {e}")
        finally:
            # 🛡️ 资源保护：无论是否报错，强制安全断开邮箱连接，防止被拉黑
            if mail:
                try: mail.logout()
                except: pass
            
        print(f"\n[后台暗哨] 潜伏中，{POLL_INTERVAL} 秒后再次扫描...")
        time.sleep(POLL_INTERVAL)

# ==========================================
# 模块 3: 机器人客服 (主线程)
# ==========================================
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "🛡️ SOAR 双核引擎已启动。您可以手动发 IP/域名给我，后台邮件监听也已开启。")

@bot.message_handler(func=lambda message: True)
def handle_manual_query(message):
    bot.reply_to(message, "✅ 收到人工研判指令，但目前主打邮件全自动监听哦~")

if __name__ == "__main__":
    print("[*] 🚀 正在启动 SOAR 企业级双核防御系统...")
    monitor_thread = threading.Thread(target=mail_monitor_daemon, daemon=True)
    monitor_thread.start()
    print("[*] 🤖 Telegram 交互终端已上线。")
    bot.infinity_polling()