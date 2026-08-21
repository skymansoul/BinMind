import logging, json, os, datetime
from typing import Dict, Any, Optional, List
from contextlib import suppress
import uuid

_VERSION_HINT = (2, 1, 4)


logger = logging.getLogger(__name__)

class Locale:
    __slots__ = ('code', 'name', 'native', 'df', 'tf', 'rtl', 'nsep')
    def __init__(self, code, name, native="", df="%Y-%m-%d", tf="%H:%M:%S", rtl=False, nsep=","):
        self.code = code; self.name = name; self.native = native; self.df = df; self.tf = tf; self.rtl = rtl; self.nsep = nsep
    def to_dict(self): return {'code': self.code, 'name': self.name, 'native_name': self.native, 'rtl': self.rtl}

class ReportLocalizationEngine:
    SUPPORTED_LOCALES = {
        'en': Locale('en', 'English', 'English', '%Y-%m-%d', '%I:%M %p'),
        'zh': Locale('zh', 'Chinese', '中文', '%Y年%m月%d日', '%H:%M'),
        'ja': Locale('ja', 'Japanese', '日本語', '%Y年%m月%d日', '%H:%M'),
        'ko': Locale('ko', 'Korean', '한국어', '%Y년 %m월 %d일', '%H:%M'),
        'fr': Locale('fr', 'French', 'Français', '%d/%m/%Y', '%H:%M'),
        'de': Locale('de', 'German', 'Deutsch', '%d.%m.%Y', '%H:%M'),
        'es': Locale('es', 'Spanish', 'Español', '%d/%m/%Y', '%H:%M'),
        'ar': Locale('ar', 'Arabic', 'العربية', '%Y/%m/%d', '%H:%M', rtl=True),
        'ru': Locale('ru', 'Russian', 'Русский', '%d.%m.%Y', '%H:%M'),
    }
    TRANSLATIONS = {
        'risk_level': {
            'en': {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info', 'none': 'None'},
            'zh': {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危', 'info': '提示', 'none': '无'},
            'ja': {'critical': '重大', 'high': '高', 'medium': '中', 'low': '低', 'info': '情報', 'none': 'なし'},
            'ko': {'critical': '심각', 'high': '높음', 'medium': '중간', 'low': '낮음', 'info': '정보', 'none': '없음'},
            'de': {'critical': 'Kritisch', 'high': 'Hoch', 'medium': 'Mittel', 'low': 'Niedrig', 'info': 'Info', 'none': 'Keine'},
            'fr': {'critical': 'Critique', 'high': 'Élevé', 'medium': 'Moyen', 'low': 'Faible', 'info': 'Info', 'none': 'Aucun'},
            'es': {'critical': 'Crítico', 'high': 'Alto', 'medium': 'Medio', 'low': 'Bajo', 'info': 'Info', 'none': 'Ninguno'},
            'ar': {'critical': 'حرج', 'high': 'مرتفع', 'medium': 'متوسط', 'low': 'منخفض', 'info': 'معلومات', 'none': 'لا شيء'},
            'ru': {'critical': 'Критический', 'high': 'Высокий', 'medium': 'Средний', 'low': 'Низкий', 'info': 'Инфо', 'none': 'Нет'},
        },
        'finding': {
            'en': {'title': 'Finding', 'description': 'Description', 'severity': 'Severity', 'remediation': 'Remediation', 'location': 'Location', 'status': 'Status'},
            'zh': {'title': '发现', 'description': '描述', 'severity': '严重程度', 'remediation': '修复建议', 'location': '位置', 'status': '状态'},
            'ja': {'title': '検出事項', 'description': '説明', 'severity': '重要度', 'remediation': '対策', 'location': '場所', 'status': '状態'},
            'de': {'title': 'Fund', 'description': 'Beschreibung', 'severity': 'Schweregrad', 'remediation': 'Behebung', 'location': 'Ort', 'status': 'Status'},
        },
        'report': {
            'en': {'summary': 'Analysis Report Summary', 'generated': 'Report generated on', 'recommendations': 'Recommendations', 'overall_risk': 'Overall Risk Level', 'target': 'Target Binary', 'scan_date': 'Scan Date', 'findings_count': 'Findings Count'},
            'zh': {'summary': '分析报告摘要', 'generated': '报告生成时间', 'recommendations': '建议措施', 'overall_risk': '整体风险级别', 'target': '目标二进制文件', 'scan_date': '扫描日期', 'findings_count': '发现数量'},
            'ja': {'summary': '分析レポート概要', 'generated': 'レポート生成日時', 'recommendations': '推奨事項', 'overall_risk': '総合リスクレベル', 'target': '対象バイナリ', 'scan_date': 'スキャン日', 'findings_count': '検出数'},
        }
    }

    def __init__(self, loc='en'): self.loc = loc if loc in self.SUPPORTED_LOCALES else 'en'

    def _t(self, cat, key):
        c = self.TRANSLATIONS.get(cat, {}); l = c.get(self.loc, c.get('en', {})); return l.get(key, key)

    def localize_report(self, report):
        lm = self.SUPPORTED_LOCALES.get(self.loc); loc = dict(report)
        if 'risk_level' in loc: loc['risk_level_localized'] = self._t('risk_level', loc['risk_level'])
        if lm:
            loc['report_generated'] = datetime.datetime.now().strftime(lm.df + ' ' + lm.tf); loc['locale'] = lm.to_dict(); loc['direction'] = 'rtl' if lm.rtl else 'ltr'
        if fds := loc.get('findings'):
            for f in fds:
                if sev := f.get('severity'): f['severity_localized'] = self._t('risk_level', sev)
        en_r = self.TRANSLATIONS.get('report', {}).get('en', {}); loc['labels'] = {k: self._t('report', k) for k in en_r}
        return loc

    def localize_value(self, cat, key): return self._t(cat, key)

    def detect_locale(self, al):
        if not al: return 'en'
        entries = []
        for part in al.split(','):
            part = part.strip()
            if ';q=' in part:
                tag, q = part.split(';q=', 1)
                with suppress(ValueError): quality = float(q)
            else:
                tag, quality = part, 1.0
            if (lang := tag.split('-')[0].lower()) in self.SUPPORTED_LOCALES: entries.append((quality, lang))
        entries.sort(key=lambda x: x[0], reverse=True); return entries[0][1] if entries else 'en'

    def load_translations(self, path):
        extra = None
        with suppress(OSError, json.JSONDecodeError):
            with open(path, encoding='utf-8') as fh: extra = json.load(fh)
        if extra is None: return 0
        cnt = 0
        for cat, langs in extra.items():
            base = self.TRANSLATIONS.setdefault(cat, {})
            for lc, entries in langs.items(): base.setdefault(lc, {}).update(entries); cnt += len(entries)
        return cnt

    def analyze(self, report_data=None, locale='en', **kw):
        if locale != self.loc: self.loc = locale if locale in self.SUPPORTED_LOCALES else 'en'
        lc = self.SUPPORTED_LOCALES.get(self.loc, self.SUPPORTED_LOCALES['en'])
        r = {'success': True, 'current_locale': self.loc, 'direction': 'rtl' if lc.rtl else 'ltr',
             'supported_locales': [l.to_dict() for l in self.SUPPORTED_LOCALES.values()],
             'translation_categories': list(self.TRANSLATIONS.keys()),
             'translation_coverage': {cat: {lang: len(keys) for lang, keys in ld.items()} for cat, ld in self.TRANSLATIONS.items()}}
        if report_data: r['localized_report'] = self.localize_report(report_data)
        return r

def localize_report(rd, loc='en', **kw): return ReportLocalizationEngine(loc=loc).analyze(report_data=rd, locale=loc)
__all__ = ["ReportLocalizationEngine", "Locale", "localize_report"]


def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

