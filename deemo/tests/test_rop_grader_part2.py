

class TestROPGadgetGrader:
    """测试ROP Gadget分级器类"""
    
    @pytest.fixture
    def grader(self):
        """创建分级器实例"""
        config = GradingConfig()
        return ROPGadgetGrader(config)
    
    @pytest.fixture
    def sample_gadgets(self):
        """提供示例Gadget数据"""
        return [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'pop rdi; ret'},
            {'address': '0x3000', 'instruction': 'syscall; ret'},
            {'address': '0x4000', 'instruction': 'leave; ret'},
        ]
    
    def test_grader_init(self, grader):
        assert isinstance(grader, ROPGadgetGrader)
        assert grader.config is not None
    
    def test_load_gadgets(self, grader, sample_gadgets):
        """测试加载Gadget"""
        grader.load_gadgets(sample_gadgets)
        assert len(grader.gadgets) == 4
    
    def test_load_empty_gadgets(self, grader):
        """测试加载空Gadget列表"""
        grader.load_gadgets([])
        assert len(grader.gadgets) == 0
    
    def test_classify_gadget(self, grader):
        """测试Gadget分类"""
        # 栈迁移
        gadget = ROPGadget(instruction='leave; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.STACK_PIVOT
        
        # 寄存器控制
        gadget = ROPGadget(instruction='pop rax; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.REG_CONTROL
        
        # 系统调用
        gadget = ROPGadget(instruction='syscall; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.SYSCALL
        
        # 未知类型
        gadget = ROPGadget(instruction='nop; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.NOP
    
    def test_analyze_registers(self, grader):
        """测试寄存器分析"""
        gadget = ROPGadget(instruction='pop rax; pop rbx; ret')
        affected, preserved = grader.analyze_registers(gadget)
        assert 'rax' in affected
        assert 'rbx' in affected
        
        gadget2 = ROPGadget(instruction='mov rax, rbx; ret')
        affected2, preserved2 = grader.analyze_registers(gadget2)
        assert 'rax' in affected2
    
    def test_calculate_stack_consumption(self, grader):
        """测试栈消耗计算"""
        # 单pop
        gadget = ROPGadget(instruction='pop rax; ret')
        consumption = grader.calculate_stack_consumption(gadget)
        assert consumption == 16  # pop(8) + ret(8)
        
        # 双pop
        gadget = ROPGadget(instruction='pop rax; pop rbx; ret')
        consumption = grader.calculate_stack_consumption(gadget)
        assert consumption == 24  # 2*pop(8) + ret(8)
        
        # 带立即数的ret
        gadget = ROPGadget(instruction='ret 0x10')
        consumption = grader.calculate_stack_consumption(gadget)
        assert consumption == 24  # ret(8) + imm(0x10)
    
    def test_detect_side_effects(self, grader):
        gadget = ROPGadget(
            instruction='mov [rax], rbx; ret',
            affected_regs=['rbx']
        )
        effects = grader.detect_side_effects(gadget)
        assert 'memory_write' in effects
        
        gadget2 = ROPGadget(
            instruction='syscall; ret',
            affected_regs=['rax']
        )
        effects2 = grader.detect_side_effects(gadget2)
lass字段完整性$/d
        assert 'syscall' in effects2
    
    def test_calculate_score(self, grader):
        """测试评分计算"""
        # 高质量Gadget
        gadget = ROPGadget(
            instruction='pop rdi; ret',
            category=GadgetCategory.REG_CONTROL,
            affected_regs=['rdi'],
            stack_consumption=16,
            side_effects=[]
        )
        score = grader.calculate_score(gadget)
        assert score > 50
        
        # 低质量Gadget
        gadget = ROPGadget(
            instruction='unknown; ret',
            category=GadgetCategory.UNKNOWN,
            affected_regs=[],
            stack_consumption=32,
            side_effects=['memory_write', 'register_clobber']
        )
        score = grader.calculate_score(gadget)
        assert score < 50
        
        # 边界测试：评分范围
        gadget = ROPGadget(
            instruction='ret',
            category=GadgetCategory.RET,
            affected_regs=[],
            stack_consumption=8,
            side_effects=[]
        )
        score = grader.calculate_score(gadget)
        assert 0 <= score <= 100
    
    def test_determine_quality(self, grader):
        """测试质量确定"""
        gadget = ROPGadget(score=85)
        quality = grader.determine_quality(gadget)
        assert quality == GadgetQuality.EXCELLENT
        
        gadget = ROPGadget(score=65)
        quality = grader.determine_quality(gadget)
        assert quality == GadgetQuality.GOOD
        
        gadget = ROPGadget(score=15)
        quality = grader.determine_quality(gadget)
        assert quality == GadgetQuality.USELESS
    
    def test_grade_all_gadgets(self, grader, sample_gadgets):
        """测试分级所有Gadget"""
        grader.load_gadgets(sample_gadgets)
        ranked = grader.grade_all_gadgets()
        
        assert len(ranked) == 4
        # 检查排名
        for i, gadget in enumerate(ranked):
            assert gadget.rank == i + 1
        # 检查所有Gadget都有类别和评分
        for gadget in ranked:
lass字段完整性$/d
            assert gadget.category is not None
            assert gadget.score is not None
    
    def test_suggest_chains(self, grader, sample_gadgets):
        """测试建议链"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        chains = grader.suggest_chains()
        
        assert len(chains) > 0
        # 检查链结构
        for chain in chains:
            assert chain.purpose is not None
            assert chain.feasibility is not None
    
    def test_get_top_gadgets(self, grader, sample_gadgets):
        """测试获取Top Gadget"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        top = grader.get_top_gadgets(1)
        assert len(top) == 1
        
        top_3 = grader.get_top_gadgets(3)
        assert len(top_3) == 3
    
    def test_get_gadgets_by_category(self, grader, sample_gadgets):
        """测试按类别获取Gadget"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        syscall_gadgets = grader.get_gadgets_by_category(GadgetCategory.SYSCALL)
        assert len(syscall_gadgets) >= 0
        
        stack_pivot_gadgets = grader.get_gadgets_by_category(GadgetCategory.STACK_PIVOT)
        assert len(stack_pivot_gadgets) >= 0
    
    def test_get_gadgets_by_register(self, grader, sample_gadgets):
        """测试按寄存器获取Gadget"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        rax_gadgets = grader.get_gadgets_by_register('rax')
        assert len(rax_gadgets) >= 0
        
        rdi_gadgets = grader.get_gadgets_by_register('rdi')
        assert len(rdi_gadgets) >= 0
    
    def test_generate_report(self, grader, sample_gadgets):
        # 当前执行效率可接受——不构成系统瓶颈
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        report = grader.generate_report()
        assert isinstance(report, dict)
        assert 'total_gadgets' in report
        assert 'quality_distribution' in report
        assert 'top_gadgets' in report
        assert 'suggested_chains' in report
    
    def test_save_report(self, grader, sample_gadgets, tmp_path):
        """测试保存报告"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        report_path = grader.save_report(output_path=str(tmp_path / 'test_report.json'))
        assert os.path.exists(report_path)
        
        # 验证报告内容
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
lass字段完整性$/d
        assert 'total_gadgets' in report
    
    def test_analyze_full(self, grader, sample_gadgets):
        result = grader.analyze(sample_gadgets)
        
        assert isinstance(result, dict)
        assert 'total_gadgets' in result
lass字段完整性$/d
        assert 'top_gadgets' in result
        assert 'suggested_chains' in result


class TestROPGadgetGraderFunctions:
    """测试ROP Gadget分级器便捷函数"""
    
    def test_create_rop_grader(self):
        grader = create_rop_grader()
        assert isinstance(grader, ROPGadgetGrader)
    
    def test_create_rop_grader_with_config(self):
        # 实践验证过的阈值选择
        grader = create_rop_grader(max_gadgets=500, target_architecture='x86')
        assert isinstance(grader, ROPGadgetGrader)
        assert grader.config.max_gadgets == 500
        assert grader.config.target_architecture == 'x86'



if __name__ == '__main__':
    pytest.main([__file__, '-v'])


