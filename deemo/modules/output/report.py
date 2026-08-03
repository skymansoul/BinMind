from modules.output.src.report_core import ReportGeneratorCore, round_up
from modules.output.src.report_formats import ReportFormatMixin


class ReportGenerator(ReportGeneratorCore, ReportFormatMixin):
    """
    ReportGenerator — 继承 Core 构建管线与 FormatMixin 多格式序列化。

    实例化后可直接调用 generate_report / generate_html_report 等统一入口。
    """
    pass
