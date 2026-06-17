import sys
import urllib.parse
import os
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# --- تصميم الواجهة الاحترافية ---
class Theme:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def banner():
        print(f"{Theme.MAGENTA}{Theme.BOLD}")
        print("  ██████╗ █████╗ ██████╗ ███╗   ██╗██████╗ ")
        print(" ██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔══██╗")
        print(" ██║     ███████║██████╔╝██╔██╗ ██║██████╔╝")
        print(" ██║     ██╔══██║██╔══██╗██║╚██╗██║██╔══██╗")
        print(" ╚██████╗██║  ██║██║  ██║██║ ╚████║██║  ██║")
        print("  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝")
        print(f"       {Theme.CYAN}Advanced Param Scoring & Filtering Engine v2.0{Theme.END}\n")

# --- قاعدة بيانات التصنيف (Scoring Engine) ---
# البرامترات التي لها احتمالية عالية جداً للحقن (Critical)
CRITICAL_PARAMS = ['id', 'query', 'search', 'sql', 'file', 'doc', 'page', 'cat', 'category', 'user', 'uid', 'pid']
# البرامترات التي لها احتمالية متوسطة (Medium)
MEDIUM_PARAMS = ['sort', 'order', 'filter', 'view', 'lang', 'mode', 'type', 'action']
# الامتدادات التي تزيد من احتمالية وجود ثغرة (High Potential Extensions)
SENSITIVE_EXT = ('.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.cfm')
# الامتدادات التي يتم تجاهلها تماماً (Noise)
STATIC_EXT = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.pdf', '.zip', '.png', '.ico')

def score_url(url):
    """نظام تقييم الروابط بناءً على المعايير الأمنية"""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    
    # 1. تجاهل الملفات الساكنة
    if path.endswith(STATIC_EXT):
        return None
        
    # 2. التحقق من وجود برامترات
    if not parsed.query:
        return None
        
    score = 0
    params = urllib.parse.parse_qs(parsed.query)
    found_params = []

    # تقييم البرامترات
    for p in params.keys():
        found_params.append(p)
        if p.lower() in CRITICAL_PARAMS:
            score += 10  # خطورة عالية
        elif p.lower() in MEDIUM_PARAMS:
            score += 5   # خطورة متوسطة
        else:
            score += 1   # برامتر عادي

    # تقييم الامتداد
    if path.endswith(SENSITIVE_EXT):
        score += 5

    return {
        'url': url,
        'score': score,
        'params': found_params,
        'priority': 'CRITICAL' if score >= 15 else ('MEDIUM' if score >= 5 else 'LOW')
    }

def process_urls(input_file):
    if not os.path.exists(input_file):
        print(f"{Theme.RED}[!] Input file not found!{Theme.END}")
        return

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"{Theme.GREEN}[+] Total URLs to analyze: {len(urls)}{Theme.END}")
    
    # استخدام ThreadPoolExecutor لسرعة فائقة في المعالجة
    with ThreadPoolExecutor() as executor:
        results = list(filter(None, executor.map(score_url, urls)))

    # ترتيب النتائج حسب السكور (الأعلى أولاً)
    results.sort(key=lambda x: x['score'], reverse=True)
    
    # تنظيم المخرجات في مجموعات
    categorized = defaultdict(list)
    for res in results:
        categorized[res['priority']].append(res['url'])

    # عرض النتائج بشكل مميز
    print(f"\n{Theme.BOLD}{Theme.CYAN}--- Analysis Report ---{Theme.END}")
    
    for priority in ['CRITICAL', 'MEDIUM', 'LOW']:
        color = Theme.RED if priority == 'CRITICAL' else (Theme.YELLOW if priority == 'MEDIUM' else Theme.GREEN)
        print(f"\n{color}{Theme.BOLD}[{priority}] targets found: {len(categorized[priority])}{Theme.END}")
        
        # حفظ النتائج في ملفات منفصلة
        filename = f"{priority.lower()}_targets.txt"
        with open(filename, 'w') as f:
            f.write("\n".join(categorized[priority]))
        
        # عرض عينة من الروابط
        for url in categorized[priority][:5]:
            print(f"  {Theme.CYAN}->{Theme.END} {url}")

    print(f"\n{Theme.GREEN}[+] All results saved to: critical_targets.txt, medium_targets.txt, low_targets.txt{Theme.END}")

def main():
    Theme.banner()
    if len(sys.argv) < 2:
        print(f"{Theme.RED}Usage: python3 paramhunter.py <urls_list.txt>{Theme.END}")
        sys.exit(1)

    process_urls(sys.argv[1])

if __name__ == "__main__":
    main()
