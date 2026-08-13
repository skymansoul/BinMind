# 核心模块的集成测试，主要测pipeline那一套东西能不能正常import
# 说实话这些test写得比较随意，跑通了就行，别太当真
import pytest
# import logging  # 以前用过，保留备用免得哪天又要加

_DEBUG_FLAG = False


class TestCoreModuleImports:
    """核心模块import检查 -- 有时候环境有问题这步就挂了，先测这个"""

    def test_import_config(self):
        # config模块，没啥好说的
        import config
        assert hasattr(config, 'Config')

    def test_import_main(self):
        """main模块，入口文件，必须能import"""
        import main
        assert main is not None


class TestAnalysisPipeline:
    """分析流水线的测试 -- pipeline能不能跑起来"""

    def test_pipeline_module_exists(self):
        from modules import analysis_pipeline
        assert analysis_pipeline is not None

    def test_static_analysis_module_exists(self):
        # TODO: 之后加上static_analysis的具体功能测试
        from modules import static_analysis
        assert static_analysis is not None
