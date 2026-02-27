import telebot
import requests
import re
from urllib.parse import urlparse
import datetime
# ==========================================
# ⚙️ 配置中心 (把你的 Token 和 Key 填在这里)
# ==========================================
TG_BOT_TOKEN = "your_telegram_bot_token_here".strip()
VT_API_KEY = "your_virustotal_api_key_here".strip()
if not TG_BOT_TOKEN or not VT_API_KEY:
    raise ValueError("🚨 致命错误：未检测到环境变量！请在云端配置 TG_BOT_TOKEN 和 VT_API_KEY。")

# 初始化机器人
bot = telebot.TeleBot(TG_BOT_TOKEN)
# 初始化机器人
bot = telebot.TeleBot(TG_BOT_TOKEN)

def extract_target(text):
    """智能识别用户发来的是 IP 还是 URL/域名"""
    # 正则匹配 IPv4
    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    if re.match(ip_pattern, text):
        return text, "ip"
    
    # 如果不是 IP，尝试提取主域名
    if not text.startswith(('http://', 'https://')):
        text = 'http://' + text  # 补全协议方便 urlparse 解析
    
    domain = urlparse(text).netloc
    return domain, "domain"

def query_threat_intel(target, target_type):
    """调用云端沙箱进行穿透查询"""
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    if target_type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"

    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return "404"
        elif response.status_code == 429:
            return "429"
        else:
            return None
    except Exception as e:
        print(f"API 请求错误: {e}")
        return None

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """机器人欢迎语"""
    welcome_text = (
        "🛡️ **企业级 SOAR 威胁情报助手已上线**\n\n"
        "我是你的专属安全分析师。请直接发给我任何可疑的：\n"
        "👉 `IP 地址` (如: 8.8.8.8)\n"
        "👉 `钓鱼链接` (如: taobao-login-safe.com/admin)\n\n"
        "我将为你进行毫秒级溯源研判。"
    )
    bot.reply_to(message, welcome_text, parse_mode="Markdown")

@bot.message_handler(func=lambda message: True)
def handle_target(message):
    """核心研判逻辑：接收消息 -> 提取特征 -> 查询云端 -> 回传战报"""
    raw_text = message.text.strip()
    
    # 告诉用户机器人正在干活（增强交互体验）
    msg = bot.reply_to(message, "⏳ 正在连接全球威胁情报网络进行深度研判，请稍候...")

    # 1. 智能提取
    target, target_type = extract_target(raw_text)
    if not target:
        bot.edit_message_text("❌ 无法识别目标格式，请发送合法的 IP 或域名。", chat_id=message.chat.id, message_id=msg.message_id)
        return

    # 2. 查询情报
    data = query_threat_intel(target, target_type)

    # 3. 组装华丽战报
    if data == "404":
        report = f"❓ **目标:** {target}\n\n[-] 情报库中暂无该资产记录，极其罕见，建议人工介入甄别。"
    elif data == "429":
        report = "🛑 **API 触发风控**\n请求过于频繁，请等待 15 秒后重试。"
    elif data:
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']
        
        # ==========================================
        # 🕵️ 深度情报挖掘模块启动
        # ==========================================
        
        # 1. 提取资产类别 (如: Phishing, Malware, CDN)
        categories = attributes.get('categories', {})
        category_str = ", ".join(set(categories.values())) if categories else "未知/未分类"

        # 2. 提取归属地与 ASN (主要针对 IP)
        asn = attributes.get('asn', 'N/A')
        country = attributes.get('country', '未知')
        network_str = f"AS{asn} ({country})" if asn != 'N/A' else "N/A (非IP或无记录)"

        # 3. 提取域名注册信息 (主要针对 Domain)
        registrar = attributes.get('registrar', 'N/A')
        creation_date = attributes.get('creation_date', 0)
        if creation_date:
            create_time_str = datetime.datetime.fromtimestamp(creation_date).strftime('%Y-%m-%d')
        else:
            create_time_str = "N/A"

        # 4. 提取具体是哪家引擎报的毒？报的什么毒？
        analysis_results = attributes.get('last_analysis_results', {})
        malicious_details = []
        for engine, result in analysis_results.items():
            if result['category'] in ['malicious', 'suspicious']:
                malware_name = result.get('result', '恶意载荷')
                malicious_details.append(f"    ┠ 🛡️ {engine}: `{malware_name}`")
        
        # 为了防止手机屏幕被刷爆，只展示前 5 个最致命的报警
        details_str = "\n".join(malicious_details[:5])
        if len(malicious_details) > 5:
            details_str += f"\n    ┗ ...等共 {len(malicious_details)} 家安全引擎拦截"
        elif not malicious_details:
            details_str = "    ┗ (暂无具体特征库命中记录)"

        # ==========================================
        # 🎨 重新组装骨灰级专业战报
        # ==========================================
        if malicious > 0:
            status_icon = "🚨 🚨 🚨 **[极度危险]**"
        elif suspicious > 0:
            status_icon = "⚠️ **[可疑资产]**"
        else:
            status_icon = "✅ **[信誉良好]**"

        report = (
            f"📊 **ChatOps 深度威胁研判战报**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🎯 **检测目标:** `{target}`\n"
            f"🛡️ **安全评级:** {status_icon}\n"
            f"🏷️ **资产标签:** `{category_str}`\n\n"
            f"🌍 **网络特征:**\n"
            f"    ┠ 归属地/ASN: `{network_str}`\n"
            f"    ┠ 注册商: `{registrar}`\n"
            f"    ┗ 注册时间: `{create_time_str}`\n\n"
            f"📈 **多引擎共识引擎 ({malicious + suspicious + harmless}家参与):**\n"
            f"    🔴 恶意: {malicious} | 🟠 可疑: {suspicious} | 🟢 安全: {harmless}\n\n"
            f"🦠 **致命特征提取 (IOC):**\n"
            f"{details_str}\n\n"
            f"🤖 *Powered by Python SOAR Engine*"
        )

    else:
        report = "❌ **网络错误**，无法连接至威胁情报中心。"

    # 将原有等待消息“修改”为最终战报，实现极客级的 UI 刷新效果
    bot.edit_message_text(report, chat_id=message.chat.id, message_id=msg.message_id, parse_mode="Markdown")

if __name__ == "__main__":
    print("[*] 🚀 SecBot 威胁情报引擎已启动！")
    print("[*] 正在监听 Telegram 消息...")
    # 启动长轮询，保持在线
    bot.infinity_polling()