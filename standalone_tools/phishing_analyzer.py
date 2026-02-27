import email
from email import policy
import re
import os
import requests
import base64
import time
from urllib.parse import urlparse

class PhishingAnalyzer:
    def __init__(self, eml_file_path):
        self.eml_file_path = eml_file_path
        self.msg = None
        self.origin_ip = None

    def load_email(self):
        """加载并解析 .eml 邮件文件"""
        if not os.path.exists(self.eml_file_path):
            print(f"[-] 找不到文件: {self.eml_file_path}")
            return False
            
        with open(self.eml_file_path, 'rb') as f:
            # policy.default 会自动帮我们处理复杂的邮件编码问题
            self.msg = email.message_from_binary_file(f, policy=policy.default)
        return True
    def scan_url_with_vt(self, api_key, urls_to_scan):
        """调用 VirusTotal API 批量扫描提取出的【主域名】"""
        print("\n[*] 4. 威胁情报自动化研判 (VirusTotal 域名信誉库)")
        print("    [!] 优化逻辑启动：已自动剥离冗余路径，仅对核心域名进行信誉穿透检测。")
        
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # 去重并提取前 3 个链接
        for index, url in enumerate(list(urls_to_scan)[:3]):
            # 💡 核心提纯代码：把又长又臭的 URL 拆解，只提取网络位置（netloc）
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            if not domain:
                print(f"\n    [-] 第 {index + 1} 个链接无法提取有效域名，已跳过。")
                continue

            print(f"\n    🔍 正在查询资产信誉: {domain} (来源: {url[:35]}...)")
            
            # 💡 注意：这里换成了 VT 的 domain（域名）查询接口，不仅命中率极高，而且不需要 base64 转换！
            vt_endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"

            try:
                response = requests.get(vt_endpoint, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats['malicious']
                    suspicious = stats['suspicious']
                    harmless = stats['harmless']
                    
                    if malicious > 0 or suspicious > 0:
                        print(f"      🚨 [拦截报警] {malicious} 款引擎报毒！{suspicious} 款标记可疑！危险！！")
                    else:
                        print(f"      ✅ [安全放行] 该域名信誉良好，{harmless} 款主流引擎未见异常。")
                        
                elif response.status_code == 404:
                    print("      ❓ [情报库缺失] 极其罕见的域名，VT 暂无记录，需人工甄别。")
                elif response.status_code == 429:
                    print("      🛑 [触发风控] API 请求过快，已被 VT 服务器限流。")
                else:
                    print(f"      [-] 检测失败，服务器返回状态码: {response.status_code}")
                    
            except Exception as e:
                print(f"      [-] 情报网连接异常: {e}")

            # 强制休眠 15 秒防止被封 API
            if index < 2 and index < (len(urls_to_scan) - 1):
                print("      ⏳ (系统冷却中 15 秒，规避免费 API 防火墙...)")
                time.sleep(15)
    
    def extract_basic_info(self):
        """提取基础信息 (警告: 发件人可能被伪造)"""
        print("\n==================================================")
        print("  📧 钓鱼邮件自动化分析报告")
        print("==================================================")
        print("[*] 1. 基础信息 (警惕：From 字段极易伪造！)")
        print(f"    - 宣称的发件人 (From): {self.msg['From']}")
        print(f"    - 实际回复地址 (Reply-To): {self.msg.get('Reply-To', '未设置')}")
        print(f"    - 收件人 (To): {self.msg['To']}")
        print(f"    - 邮件主题 (Subject): {self.msg['Subject']}")
        print(f"    - 发送时间 (Date): {self.msg['Date']}")

    def trace_origin_ip(self):
        """核心原理：通过倒序追踪 Received 头，寻找真实发件 IP"""
        print("\n[*] 2. 网络溯源 (分析 Received 路由跳数)")
        
        # 获取所有的 Received 头记录 (列表形式)
        received_headers = self.msg.get_all('Received')
        
        if not received_headers:
            print("    [-] 未找到路由信息。")
            return

        print(f"    - 邮件共经过了 {len(received_headers)} 个路由节点。")
        
        # 邮件服务器是一层一层往上加 Received 的，所以最底层记录（列表最后一个元素）通常是最靠近攻击源的
        origin_hop = received_headers[-1]
        print(f"    - 🎯 追溯到的最早路由节点 (真实来源端倪):\n      {origin_hop.strip()}")
        
        # 使用正则表达式，从这段又长又乱的字符串里把 IPv4 地址“揪”出来
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ipv4_pattern, origin_hop)
        
        # 排除掉常见的内网保留 IP (如 127.0.0.1, 10.x.x.x)
        public_ips = [ip for ip in ips if not ip.startswith(('127.', '10.', '192.168.', '172.'))]
        
        if public_ips:
            self.origin_ip = public_ips[0]
            print(f"\n    🚨 [关键发现] 提取到嫌疑攻击源公网 IP: {self.origin_ip}")
        else:
            print("    [-] 未能在最早节点提取到有效的公网 IPv4。攻击者可能使用了代理或 IPv6。")

    def extract_iocs(self):
        """提取失陷指标 (IOCs): 包含链接和附件"""
        print("\n[*] 3. 恶意载荷分析 (提取正文链接与附件)")
        
        # 提取邮件正文
        body = ""
        # 遍历邮件的所有部分 (应对 multipart 多段结构的邮件)
        for part in self.msg.walk():
            # 1. 如果有附件，把文件名抓出来
            filename = part.get_filename()
            if filename:
                print(f"    📎 发现可疑附件: {filename}")
            
            # 2. 如果是文本正文，提取出来准备找 URL
            content_type = part.get_content_type()
            if content_type in ['text/plain', 'text/html']:
                try:
                    body += part.get_content()
                except:
                    pass
        
        # 从正文中提取所有 URL
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*'
        urls = set(re.findall(url_pattern, body))
        
        if urls:
            print(f"    🔗 发现 {len(urls)} 个内嵌链接:")
            for i, url in enumerate(list(urls)[:5]): # 打印前 5 个
                print(f"      {i+1}. {url}")
        else:
            print("    [-] 正文中未发现明显的 URL 链接。")
        print("==================================================\n")
        return urls

    def run(self, vt_api_key=""):
        if self.load_email():
            self.extract_basic_info()
            self.trace_origin_ip()
            
            # 提取链接（为了方便传给下一个函数，你需要让 extract_iocs 返回 urls 集合）
            urls = self.extract_iocs() 
            
            # 如果配置了 API 密钥，且提取到了链接，就启动核武器
            if vt_api_key and urls:
                self.scan_url_with_vt(vt_api_key, urls)

if __name__ == "__main__":
    test_file = "test_phishing.eml"
    analyzer = PhishingAnalyzer(test_file)
    
    # 把你的真实 Key 填在这里（千万不要带引号以外的多余空格）
    MY_VT_KEY = "your_virustotal_api_key_here".strip() 
    
    analyzer.run(vt_api_key=MY_VT_KEY)