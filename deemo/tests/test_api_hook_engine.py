"""Tests for the API hook engine."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.dynamic_analysis.api_hook_engine import (
    HookEngine, HookRegistry, HookDescriptor, HookContext,
    HookAction, HookEvent, log_args_callback, return_override_callback,
    arg_mutator_callback, conditional_skip
)


class TestHookRegistry:
    def test_register_and_lookup(self):
        reg = HookRegistry()
        reg.register('h1', r'CreateFile.*', pre=[lambda ctx: None])
        hooks = reg.get_hooks_for_api('CreateFileW')
        assert len(hooks) == 1
        assert hooks[0].hook_id == 'h1'

    def test_pattern_matching(self):
        reg = HookRegistry()
        reg.register('file_ops', r'(?i)(Create|Read|Write|Delete)File',
                     pre=[lambda ctx: None])
        assert len(reg.get_hooks_for_api('CreateFileW')) == 1
        assert len(reg.get_hooks_for_api('ReadFile')) == 1
        assert len(reg.get_hooks_for_api('VirtualAlloc')) == 0

    def test_module_filter(self):
        reg = HookRegistry()
        reg.register('kernel_only', r'CreateFile',
                     pre=[lambda ctx: None],
                     module_filter={'kernel32.dll'})
        assert len(reg.get_hooks_for_api('CreateFileW', 'kernel32.dll')) == 1
        assert len(reg.get_hooks_for_api('CreateFileW', 'ntdll.dll')) == 0

    def test_unregister(self):
        reg = HookRegistry()
        reg.register('temp', r'.*', pre=[lambda ctx: None])
        assert len(reg.get_hooks_for_api('anything')) == 1
        reg.unregister('temp')
        assert len(reg.get_hooks_for_api('anything')) == 0

    def test_enable_disable(self):
        reg = HookRegistry()
        reg.register('toggle', r'.*', pre=[lambda ctx: None])
        assert len(reg.get_hooks_for_api('x')) == 1
        reg.disable('toggle')
        assert len(reg.get_hooks_for_api('x')) == 0
        reg.enable('toggle')
        assert len(reg.get_hooks_for_api('x')) == 1

    def test_list_hooks(self):
        reg = HookRegistry()
        reg.register('a', r'foo', pre=[lambda ctx: None])
        reg.register('b', r'bar', post=[lambda ctx: None])
        hooks = reg.list_hooks()
        assert len(hooks) == 2
        assert hooks[0]['hook_id'] == 'a'

    def test_priority_ordering(self):
        reg = HookRegistry()
        reg.register('low', r'Target', pre=[lambda c: None], priority=0)
        reg.register('high', r'Target', pre=[lambda c: None], priority=100)
        hooks = reg.get_hooks_for_api('TargetFunc')
        assert hooks[0].hook_id == 'high'
        assert hooks[1].hook_id == 'low'


class TestHookEngine:
    def test_dispatch_pre_basic(self):
        engine = HookEngine()
        calls = []
        engine.registry.register('log', r'CreateFile',
                                 pre=[lambda ctx: calls.append(ctx.api_name)])
        ctx = engine.dispatch_pre('CreateFileW', [b'C:\\test.txt', 0x40000000],
                                   module_name='kernel32.dll')
        assert len(calls) == 1
        assert calls[0] == 'CreateFileW'
        assert ctx.action == HookAction.CONTINUE

    def test_pre_callback_mutates_args(self):
        engine = HookEngine()
        def mutator(ctx):
            ctx.args[1] = 0  # change desired access to 0
            ctx.action = HookAction.MODIFY_ARGS
        engine.registry.register('mut', r'CreateFile', pre=[mutator])
        ctx = engine.dispatch_pre('CreateFileW', [b'file.txt', 0x40000000])
        assert ctx.args[1] == 0

    def test_skip_original(self):
        engine = HookEngine()
        def skipper(ctx):
            ctx.return_value = 1
            return HookAction.SKIP_ORIGINAL
        engine.registry.register('skip', r'IsDebuggerPresent', pre=[skipper])
        ctx = engine.dispatch_pre('IsDebuggerPresent', [])
        assert ctx.action == HookAction.SKIP_ORIGINAL
        assert ctx.return_value == 1

    def test_dispatch_post(self):
        engine = HookEngine()
        post_values = []
        engine.registry.register('post', r'VirtualAlloc',
                                 post=[lambda ctx: post_values.append(ctx.return_value)])
        ctx = engine.dispatch_pre('VirtualAlloc', [0, 4096, 0x3000, 0x40])
        engine.dispatch_post(ctx, return_value=0x7fff0000)
        assert len(post_values) == 1
        assert post_values[0] == 0x7fff0000

    def test_dispatch_error(self):
        engine = HookEngine()
        errors = []
        engine.registry.register('err', r'.*',
                                 error=[lambda ctx: errors.append(str(ctx.error))])
        ctx = engine.dispatch_pre('BadFunction', [])
        exc = RuntimeError("test error")
        ctx = engine.dispatch_error(ctx, exc)
        assert len(errors) == 1
        assert 'test error' in errors[0]

    def test_stats_accumulation(self):
        engine = HookEngine()
        engine.registry.register('s', r'.*', pre=[lambda c: None])
        for _ in range(5):
            engine.dispatch_pre('SomeFunc', [])
        stats = engine.get_stats()
        assert stats['total_calls'] == 5

    def test_context_manager(self):
        with HookEngine() as engine:
            engine.registry.register('x', r'.*', pre=[lambda c: None])
            engine.dispatch_pre('f', [])
        # registry should be cleared after exit
        assert len(engine.registry.list_hooks()) == 0


class TestConvenienceCallbacks:
    def test_return_override(self):
        cb = return_override_callback(42)
        ctx = HookContext(api_name='test')
        action = cb(ctx)
        assert action == HookAction.SKIP_ORIGINAL
        assert ctx.return_value == 42

    def test_arg_mutator(self):
        cb = arg_mutator_callback(0, 'replaced')
        ctx = HookContext(api_name='test', args=['original', 2, 3])
        cb(ctx)
        assert ctx.args[0] == 'replaced'

    def test_conditional_skip(self):
        cb = conditional_skip(lambda c: c.args[0] == 'bad', -1)
        ctx = HookContext(api_name='test', args=['bad'])
        action = cb(ctx)
        assert action == HookAction.SKIP_ORIGINAL
        assert ctx.return_value == -1


# integration-ish: chaining multiple hooks on same API
def test_hook_chaining():
    engine = HookEngine()
    order = []

    engine.registry.register('a', r'Target',
                             pre=[lambda c: order.append('a_pre')],
                             post=[lambda c: order.append('a_post')],
                             priority=10)
    engine.registry.register('b', r'Target',
                             pre=[lambda c: order.append('b_pre')],
                             post=[lambda c: order.append('b_post')],
                             priority=20)

    ctx = engine.dispatch_pre('Target', [])
    engine.dispatch_post(ctx, return_value=0)

    # b has higher priority, should run first
    assert order == ['b_pre', 'a_pre', 'b_post', 'a_post']
