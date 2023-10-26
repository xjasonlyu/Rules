# -*- coding: utf-8 -*-

import argparse
import re
import sys
from io import StringIO
from typing import (Iterable,
                    Optional)
from urllib.parse import urlparse

import requests
from ordered_set import OrderedSet
from ruamel.yaml import YAML

ClashRuleTypes = (
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD',
    # 'GEOIP'  # not supported
    'IP-CIDR', 'IP-CIDR6',
    'SRC-IP-CIDR', 'DST-PORT', 'SRC-PORT',
    'PROCESS-NAME',
    # 'MATCH'  # should be ignored
)

SurgeRuleTypes = (
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD',
    # 'DOMAIN-SET',  # not supported
    'IP-CIDR', 'IP-CIDR6',
    # 'GEOIP'  # not supported
    'USER-AGENT', 'URL-REGEX',
    'PROCESS-NAME',
    # 'AND', 'OR', 'NOT',  # not supported
    'DEST-PORT', 'SRC-IP', 'IN-PORT', 'PROTOCOL',
    # 'RULE-SET',  # should be processed
    # 'FINAL'  # should be ignored
)


class RuleError(Exception):
    pass


class RuleSet(OrderedSet):

    def __init__(self,
                 is_clash: bool = False,
                 # params
                 force_no_resolve: bool = False):
        super().__init__()

        self.is_clash = is_clash
        self.force_no_resolve = force_no_resolve

        self.types = ClashRuleTypes \
            if is_clash else SurgeRuleTypes

    @staticmethod
    def fetch_lines(*urls):
        for url in urls:
            if url.startswith('file://'):
                with open(urlparse(url).path, encoding='utf-8') as f:
                    for line in f.readlines():
                        yield line
            else:  # as a HTTP request
                with requests.get(url, stream=True, allow_redirects=True) as r:
                    r.raise_for_status()
                    for line in r.iter_lines(decode_unicode=True):
                        yield line

    def _process(self, text: str) -> tuple:
        # remove whitespaces
        text = text.strip()
        if not text:
            return ()

        # include comment
        if text.startswith('#'):
            return () if self.is_clash else (text,)

        offset = text.find('#')
        if offset > 0:
            # remove inline comment
            text = text[:offset]

        rule = [i.strip() for i in text.split(',')]
        if len(rule) > 4:
            raise RuleError(f'invalid rule: {text}')
        elif len(rule) == 4:
            if rule[-1] != 'no-resolve':
                raise RuleError(f'invalid option: {text}')
            rule.pop(2)
        elif len(rule) == 3 and rule[-1] != 'no-resolve':
            rule.pop(-1)
        elif rule[0] == 'RULE-SET':
            pass  # ignore ruleset
        elif re.match('^(http|https|file)://', rule[0]):
            rule.insert(0, 'RULE-SET')
        elif rule[0] not in self.types:
            # print(f'unsupported type: {text}', file=sys.stderr)  # just warning
            return ()

        if self.force_no_resolve \
                and rule[0] in ('IP-CIDR', 'IP-CIDR6')\
                and rule[-1] != 'no-resolve':
            rule.append('no-resolve')

        return tuple(rule)

    def _operate(self, text: str, fn: str):
        rule = self._process(text)
        if not rule:
            return
        elif rule[0] == 'RULE-SET':  # process ruleset
            for text in self.fetch_lines(rule[1]):
                getattr(self, fn)(text)
        else:
            getattr(super(), fn)(','.join(rule))

    def add(self, text: str):
        self._operate(text, self.add.__name__)

    def discard(self, text: str):
        self._operate(text, self.discard.__name__)


def generate(sources: Iterable[str],
             exclusions: Optional[Iterable[str]] = (),
             is_clash: Optional[bool] = False,
             force_no_resolve: Optional[bool] = False) -> str:
    rules = RuleSet(is_clash,
                    force_no_resolve)

    for i in sources:
        rules.add(i)
    for i in exclusions:
        rules.discard(i)

    if is_clash:
        with StringIO() as ss:
            yaml = YAML(typ='safe', pure=True)
            yaml.default_flow_style = False
            yaml.indent(mapping=2, sequence=4, offset=2)
            yaml.dump({'payload': list(rules)}, ss)
            result = ss.getvalue()
    else:
        result = '\n'.join(rules)

    return result


def main():
    parser = argparse.ArgumentParser(description='Ruleset Generator')
    parser.add_argument('-s', '--source', action="append",
                        help='set sources', required=True)
    parser.add_argument('-e', '--exclude', action="append",
                        help='set exclusions', default=[])
    parser.add_argument('-c', '--is-clash',
                        action='store_true', help='set to clash format')
    parser.add_argument('--force-no-resolve',
                        action='store_true', help='force set no resolve')
    args = parser.parse_args()

    sys.stdout.write(generate(args.source,
                              args.exclude,
                              args.is_clash,
                              args.force_no_resolve))
    sys.stdout.flush()


if __name__ == '__main__':
    main()
