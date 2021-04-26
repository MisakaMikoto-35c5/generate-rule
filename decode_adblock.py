import base64
import json

class IllegalRuleException(RuntimeError):
    pass

class AdblockRuleDecoder:
    __uniq_cache = {}
    
    def __clear_uniq_cache(self):
        self.__uniq_cache = {}

    def __uniq(self, find_str):
        try:
            index_obj = self.__uniq_cache[find_str[0]]
        except KeyError:
            self.__uniq_cache[find_str[0]] = []
            index_obj = self.__uniq_cache[find_str[0]]
        for i in index_obj:
            if i == find_str:
                return False
        index_obj.append(find_str)
        return True

    def decode_hosts_rule(self, rules_list, action_type = 'HOST-SUFFIX', default_action = 'REJECT', unsupport_convert = 'REGEX', unsupport_action = 'REJECT', exclude_action = 'DIRECT'):
        now_rule_string = ''
        rules = []
        ignore_this_line = False
        space = False
        ip_path = False
        for rule_char in rules_list:
            if rule_char == '\n':
                if now_rule_string != '':
                    rules.append({'domain': now_rule_string, 'regex': None, 'prefer': action_type, 'action': default_action})
                    now_rule_string = ''
                ignore_this_line = False
                space = False
                ip_path = False
                now_rule_string = ''
                continue
            if ignore_this_line or rule_char == '\r':
                continue
            if rule_char == '#':
                ignore_this_line = True
                continue
            if ip_path == False and now_rule_string == '':
                if rule_char != ' ' and rule_char != '\t':
                    ip_path = True
                continue
            if ip_path == True and rule_char == ' ' or rule_char == '\t':
                if space == False:
                    space = True
                elif now_rule_string != '':
                    ignore_this_line = True
                continue
            if space:
                now_rule_string += rule_char
        if now_rule_string != '':
            rules.append({'domain': now_rule_string, 'regex': None, 'prefer': action_type, 'action': default_action})
            now_rule_string = ''
        return rules

    def decode_gfwlist_rule(self, rules_list, default_action = 'REJECT', unsupport_convert = 'REGEX', unsupport_action = 'REJECT', exclude_action = 'DIRECT'):
        return self.decode_adblock_rule(
            base64.b64decode(rules_list).decode('utf-8'),
            default_action=default_action,
            unsupport_action=unsupport_action,
            unsupport_convert=unsupport_convert,
            exclude_action=exclude_action
        )

    def convert_rule_to_unbound(self, ruleset, unbound_target_dns = '8.8.8.8'):
        rejection_ruleset = ''
        forward_ruleset = ''
        for i in ruleset:
            if i['domain'] == '':
                continue
            if i['prefer'] == 'HOST-SUFFIX' or i['prefer'] == 'HOST' and self.__uniq(i['domain']):
                if i['action'] == 'REJECT':
                    rejection_ruleset += 'local-zone: "' + i['domain'] + '" refuse\n'
                else:
                    forward_ruleset += 'forward-zone:\n\tname: "' + i['domain'] + '."\n' + unbound_target_dns + '\n'
        self.__clear_uniq_cache()
        return {
            'rejection': rejection_ruleset,
            'forward': forward_ruleset
        }

    def convert_rule_to_quantumult(self, ruleset):
        hosts_ruleset = ''
        regex_rejection_ruleset = ''
        for i in ruleset:
            if i['prefer'] == 'HOST-SUFFIX' or i['prefer'] == 'HOST-KEYWORD' or i['prefer'] == 'HOST':
                if i['domain'] == '':
                    continue
                if self.__uniq(i['domain']):
                    hosts_ruleset += i['prefer'] + ',' + i['domain'] + ',' + i['action'] + '\n'
            elif i['prefer'] == 'REGEX':
                if i['action'] != 'REJECT':
                    continue
                if i['regex'] == '':
                    continue
                regex_rejection_ruleset += i['regex'] + '\n'
        self.__clear_uniq_cache()
        return {
            'hosts': hosts_ruleset,
            'regex_rejection': regex_rejection_ruleset
        }

    def convert_rule_to_clash(self, ruleset):
        file_header = 'payload:\n'
        clash_action_rules = {}
        for i in ruleset:
            if i['prefer'] == 'HOST-SUFFIX' or i['prefer'] == 'HOST-KEYWORD' or i['prefer'] == 'HOST':
                if i['domain'] == '':
                    continue
                if self.__uniq(i['domain']):
                    try:
                        clash_action_rules[i['action'].lower()] += '  - ' + self.convert_action_name(i['prefer'], 'clash') + ',' + i['domain'] + '\n'
                    except KeyError:
                        clash_action_rules[i['action'].lower()] = file_header + '  - ' + self.convert_action_name(i['prefer'], 'clash') + ',' + i['domain'] + '\n'
        self.__clear_uniq_cache()
        return clash_action_rules

    def make_full_rule(self, parts, target_software = 'surfboard'):
        match_type_prefix = ''
        if target_software == 'clash':
            match_type_prefix = '  - '
        config_file = ''
        for i in parts:
            if i['type'] == 'base':
                for rules_text in i['rules_text']:
                    config_file += rules_text + '\n\n'
            elif i['type'] == 'surge-like-rules':
                action_replace = None
                try:
                    action_replace = i['action_replace']
                except KeyError:
                    pass
                self.__clear_uniq_cache()
                minify = False
                try:
                    minify = i['minify']
                except KeyError:
                    pass
                for rule_file in i['rules_text']:
                    for rule in rule_file.split('\n'):
                        if rule.startswith('#'):
                            continue
                        if rule.isspace():
                            continue
                        if len(rule) == 0:
                            continue
                        rule = rule.split(',')
                        if rule[0] in ['FINAL', 'MATCH']:
                            match_type = self.convert_action_name(rule[0], target_software)
                            action = rule[1]
                            if action_replace != None:
                                try:
                                    action = action_replace[action]
                                except KeyError:
                                    pass
                            config_file +=  f'{match_type_prefix}{match_type},{action}\n'
                            self.__clear_uniq_cache()
                            return config_file
                        elif not minify or self.__uniq(rule[1]):
                            match_type = self.convert_action_name(rule[0], target_software)
                            action = rule[2]
                            if action_replace != None:
                                try:
                                    action = action_replace[action]
                                except KeyError:
                                    pass
                            config_file +=  f'{match_type_prefix}{match_type},{rule[1]},{action}\n'
        self.__clear_uniq_cache()
        return config_file
                

    def decode_adblock_rule(self, rules_list, default_action = 'REJECT', unsupport_convert = 'REGEX', unsupport_action = 'REJECT', exclude_action = 'DIRECT'):
        rules = []
        rules_raw = rules_list.split('\n')
        # scheme: ^(https?://)?
        # 域名及子域名: ([0-9a-zA-Z_\-\.]*\.)?
        # 标记分隔符 ^: (?![0-9a-zA-Z_\-\.\%]).
        if len(rules_raw) == 0:
            return rules
        for rule in rules_raw:
            if len(rule) < 2:
                continue
            if rule[-1] == '\r':
                rule = rule[0:-1]
            first_str = rule[0]
            if first_str == '[' and rule[-1] == ']': # 去掉 [Adblock Plus 1.1] 这一行
                continue
            if first_str == '!': # 去掉注释行
                continue
            prev_str = ''
            generated_domain = ''
            generated_regex = ''

            char_path = -1 # 当前处理字符的位置，0 开始计
            domain_end = False # 标记停止记录域名
            prefix_match = False # 标记规则需要匹配前缀
            suffix_match = False # 标记规则需要匹配后缀
            path_length = 0 # 标记除域名后面的目录的长度
            subdomain = False # 标记规则需要匹配子域名
            regex_only = False # 标记规则只能用正则
            skip_char = 0 # 标记跳过多少字
            unsupport_rule = False # 标记不支持的规则
            is_exclude_rule = False
            for now_char in rule:
                char_path += 1
                if skip_char > 0:
                    skip_char -= 1
                    continue
                if char_path == 0:
                    if now_char == '@' and rule[1] == '@':
                        if exclude_action == 'IGNORE':
                            break
                        skip_char = 1
                        char_path = -2
                        is_exclude_rule = True
                        continue
                    if now_char == '|': # 检查开头是否匹配
                        prefix_match = True
                        generated_regex = '^'
                        prev_str = now_char
                        domain_end = False
                        continue
                    elif now_char == '/': # 正则规则，直接跳过
                        if rule[-1] == '/':
                            regex_only = True
                            generated_regex = rule[1:-1]
                            break
                        else:
                            regex_suffix = rule.find('/$')
                            rule_length = len(rule) - 2
                            if regex_suffix != -1 and regex_suffix != rule_length:
                                regex_only = True
                                generated_regex = rule[1:regex_suffix]
                                break
                elif regex_only == False and char_path == 1 and now_char == '|' and prev_str == '|': # 检查是否匹配子域名
                    subdomain = True
                    generated_regex += '(https?://)?([0-9a-zA-Z_\\-\\.]*\\.)?'
                    prev_str = now_char
                    continue
                if now_char == '$':
                    rule_options = rule[rule.find('$'):] # 检查是否有高度可能导致访问网站出问题的附加选项
                    if 'domain=' in rule_options or 'csp=' in rule_options or 'popup' in rule_options or 'popunder' in rule_options:
                        unsupport_rule = True
                    break
                if now_char == '#': # 不支持元素过滤，直接忽略
                    unsupport_rule = True
                    break
                elif (now_char == ':' and (generated_domain == 'http' or generated_domain == 'https' or generated_domain == 'http*')) and rule[char_path + 1:char_path + 3] == '//':
                    # 如果出现冒号检查是否是 scheme，如果是重新提取域名
                    generated_domain = ''
                    skip_char = 2
                    prev_str = '/'
                    generated_regex += '://'
                    continue
                elif domain_end == False and now_char == '/': # 如果出现路径则停止记录域名
                    domain_end = True
                elif now_char == '*': # 如果出现 * 则转换成正则的形式
                    generated_regex += '.'
                elif now_char == '^': # 如果出现分隔符则用正则替代，并且停止记录域名
                    generated_regex += '(?![0-9a-zA-Z_\-\.\%]).'
                    domain_end = True
                    generated_regex += now_char
                    prev_str = now_char # 记录最后一个字是什么
                    continue
                elif now_char in '.?-+[]{},\\': # 如果出现正则的特殊字符则在签名加一个转义符
                    generated_regex += '\\'
                if domain_end:
                    path_length += 1 # 记录域名后面的路径有多长，方便后面判断是否必须用正则
                else:
                    if now_char == '.' and generated_domain == '':
                        generated_regex += now_char
                        prev_str = now_char # 记录最后一个字是什么
                        continue
                    generated_domain += now_char # 记录域名
                generated_regex += now_char
                prev_str = now_char # 记录最后一个字是什么
            if unsupport_rule == False:
                if generated_domain == 'localhost' or generated_domain == 'ip6_localhost':
                    continue
                if prev_str == '^': # 如果最后是分隔符，根据 AdBlock 的规则，在最后的分隔符可以没有
                    generated_regex += '?'
                elif prev_str == '|':
                    if rule[char_path-1] == '^': # 如果最后要求匹配结尾并且上一个是分隔符，就在正则后面加这些
                        generated_regex = generated_regex[0:len(generated_regex)-1] + '?$'
                    else: # 如果上一个字不是分隔符就不加问号
                        generated_regex = generated_regex[0:len(generated_regex)-1] + '$'
                maybe_domain_only = True
                if first_str != '|' and not is_exclude_rule:
                    maybe_domain_only = False
                rule_end_path = char_path
                if is_exclude_rule:
                    rule_end_path += 2
                last_str = rule[rule_end_path]
                if last_str == '$':
                    char_path -= 1
                    rule_end_path -= 1
                    last_str = rule[rule_end_path]
                if (maybe_domain_only and (path_length == 0 or path_length == 1)):
                    # 判断是否只包含域名的字符串，然后判断一下 path 的长度
                    # 先决条件满足以后检查一下最后面是不是 / 或分隔符，如果是的话就分域名或者子域名
                    # 如果不是的话就改用域名关键字
                    if last_str == '/' or last_str == '^':
                        if subdomain:
                            prefer = 'HOST-SUFFIX'
                        else:
                            prefer = 'HOST'
                    else:
                        if unsupport_convert != 'REGEX':
                            prefer = unsupport_convert
                        else:
                            prefer = 'HOST-KEYWORD'
                else:
                    # 如果明显不是域名就改用正则
                    prefer = unsupport_convert
                action = ''
                if prefer == 'HOST' or prefer == 'HOST-SUFFIX' or prefer == 'HOST-KEYWORD': # 如果是域名就用默认操作
                    if self.check_str_is_domain(generated_domain) == False: # 如果规则不支持用域名的方式但是用户要求用域名的时候把规则偏好改回正则避免出问题
                        prefer = 'REGEX'
                        action = unsupport_action
                    else: # 如果域名没问题就用域名的规则
                        action = default_action
                else:
                    action = unsupport_action # 如果不是就用正则的
                if is_exclude_rule and prefer != 'REGEX': # 判断是否为排除规则
                    action = exclude_action
                rules.append({'domain': generated_domain, 'regex': generated_regex, 'prefer': prefer, 'action': action})
        return rules

    def convert_action_name(self, action, target_software = 'surfboard'):
        actions = {
            'HOST': 'HOST',
            'HOST-SUFFIX': 'HOST-SUFFIX',
            'HOST-KEYWORD': 'HOST-KEYWORD'
        }
        if target_software == 'surfboard' or target_software == 'clash':
            actions = {
                'HOST': 'DOMAIN',
                'HOST-SUFFIX': 'DOMAIN-SUFFIX',
                'HOST-KEYWORD': 'DOMAIN-KEYWORD'
            }
        if target_software == 'clash':
            actions['FINAL'] = 'MATCH'
        try:
            return actions[action]
        except KeyError:
            return action


    def _test_adblock_rule(self):
        while True:
            user_input = input('AdBlock Plus 1.1 rule: ')
            if user_input == 'exit':
                break
            print(self.decode_adblock_rule(user_input))
            print('')
    
    def check_str_is_domain(self, domain):
        have_dot = False
        for i in domain:
            if i == '.':
                have_dot = True
            if i not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.':
                return False
        return have_dot

