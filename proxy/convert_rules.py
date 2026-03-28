import yaml
import urllib.request
import re
import os

with open('mrs.yaml', 'r', encoding='utf-8') as f:
    original_text = f.read()

# Parse yaml
config = yaml.safe_load(original_text)

rule_providers = config.get('rule-providers', {})
rules = config.get('rules', [])

new_rules_lines = []

for rule in rules:
    if not rule.startswith('RULE-SET,'):
        new_rules_lines.append(f"  - {rule}")
        continue
    
    parts = rule.split(',')
    name = parts[1]
    target = parts[2]
    extra = parts[3:]
    
    if name not in rule_providers:
        print(f"Warning: {name} not found in rule-providers")
        new_rules_lines.append(f"  - {rule}")
        continue
    
    provider = rule_providers[name]
    url = provider['url']
    if url.endswith('.mrs'):
        url = url[:-4] + '.list'
    
    behavior = provider.get('behavior', 'domain')
    
    print(f"Downloading {url} for {name} ({behavior})...")
    
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        response = urllib.request.urlopen(req, timeout=30)
        content = response.read().decode('utf-8')
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        continue
    
    new_rules_lines.append(f"  # {name}")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if behavior == 'domain':
            if line.startswith('+.'):
                rule_str = f"DOMAIN-SUFFIX,{line[2:]},{target}"
            else:
                rule_str = f"DOMAIN,{line},{target}"
        elif behavior == 'ipcidr':
            if ':' in line:
                rule_str = f"IP-CIDR6,{line},{target}"
            else:
                rule_str = f"IP-CIDR,{line},{target}"
            if extra:
                rule_str += f",{','.join(extra)}"
        elif behavior == 'classical':
            rule_str = f"{line},{target}"
        else:
            rule_str = f"{line},{target}"
            
        new_rules_lines.append(f"  - {rule_str}")

# Now for fakeip-filter
fakeip_url = "https://raw.githubusercontent.com/wwqgtxx/clash-rules/release/fakeip-filter.list"
print(f"Downloading fakeip-filter from {fakeip_url}...")
try:
    req = urllib.request.Request(fakeip_url, headers={'User-Agent': 'Mozilla/5.0'})
    response = urllib.request.urlopen(req, timeout=30)
    fakeip_content = response.read().decode('utf-8')
    fakeip_lines = []
    for line in fakeip_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and line != '*':
            fakeip_lines.append(f'    - "{line}"')
except Exception as e:
    print(f"Failed to download fakeip-filter: {e}")
    fakeip_lines = []

# Now we need to construct the new yaml text
# We will replace the rules section
# and rule-anchor / rule-providers sections

# Find rules: section
rules_start = original_text.find('\nrules:\n')
if rules_start != -1:
    rules_end = original_text.find('\n# 规则集\n', rules_start)
    if rules_end == -1:
        rules_end = len(original_text)
    
    new_text = original_text[:rules_start] + '\nrules:\n' + '\n'.join(new_rules_lines) + '\n'
else:
    new_text = original_text

# Find and replace fake-ip-filter
if fakeip_lines:
    fakeip_start = new_text.find('\n  fake-ip-filter:\n    - "rule-set:fakeipfilter_domain"')
    if fakeip_start != -1:
        fakeip_replace = '\n  fake-ip-filter:\n' + '\n'.join(fakeip_lines)
        new_text = new_text.replace('\n  fake-ip-filter:\n    - "rule-set:fakeipfilter_domain"', fakeip_replace)

with open('mrs_new.yaml', 'w', encoding='utf-8') as f:
    f.write(new_text)

print("Done. Saved to mrs_new.yaml")
