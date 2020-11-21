# generate-rule

将 AdBlock 规则转换成 Quantumult 的分流规则和正则规则片段，也能同时生成 Surfboard 的规则。

## Features

- 支持 HOSTS / Adblock Plus / GFWlist 规则转 Quantumult / QuantumultX 规则片段。
- 支持从生成的规则片段组合成 Surfboard 的完整规则（或许 Surge 之类的也可以用）。
- （针对完整规则生成）片段化的组合模式，可以自行拼接想要的规则列表。

## 使用方法

### 生成规则列表

配置好 [配置文件](https://github.com/MisakaMikoto-35c5/generate-rule/blob/master/config.json) 以后直接运行 `generate_list.py`。

默认的配置文件已经配置好生成 EasyPrivacy、EasyList、GFWlist 等规则，参考配置文件可以做出自己需要的规则。

这个项目附加了一份规则列表，涵盖了一部分公共规则列表中没有涵盖的部分，[点击这里可以看到列表详情](https://github.com/MisakaMikoto-35c5/generate-rule/blob/master/adblock/custom-block-domains.txt)。如果这部分规则列表导致上网异常，请 [新建一个 issue](https://github.com/MisakaMikoto-35c5/generate-rule/issues)。

## 输出文件命名方式
```
name-hostnames.conf: 只包含域名分流规则或阻止规则的文件
name-rejection.conf: 只包含正则阻止规则的文件
name-unbound_dns.conf: 只包含 Unbound 域名规则的文件
```

其中，默认配置文件还配置了 `surfboard-rules.conf` 的输出，包含 EasyPrivacy、EasyList、EasyList CHN、GFWlist 和 AdGuard DNS Filter。

[生成的输出样例可以在这里找到](https://lab.wsl.moe/quantumult_rules_test/)。