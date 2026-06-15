#!/usr/bin/env python3
"""
并发漏洞与竞态条件检测模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.concurrency_analyzer import ConcurrencyAnalyzer, analyze_concurrency


class TestConcurrencyAnalyzer(unittest.TestCase):
    """
    并发分析器测试类
    """
    
    def setUp(self):
        """
        测试前准备
        """
        self.simple_pseudocode = """
#include <pthread.h>

int global_counter = 0;
pthread_mutex_t mutex;

void* thread_func1(void* arg) {
    pthread_mutex_lock(&mutex);
    global_counter++;
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void* thread_func2(void* arg) {
    pthread_mutex_lock(&mutex);
    global_counter++;
    pthread_mutex_unlock(&mutex);
    return NULL;
}

int main() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_func1, NULL);
    pthread_create(&t2, NULL, thread_func2, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
"""
        
        self.race_condition_pseudocode = """
#include <pthread.h>

int shared_data = 0;
pthread_mutex_t mutex1;
pthread_mutex_t mutex2;

void* writer_thread(void* arg) {
    shared_data = 42;
    return NULL;
}

void* reader_thread(void* arg) {
    int val = shared_data;
    return NULL;
}

void* bad_lock_order1(void* arg) {
    pthread_mutex_lock(&mutex1);
    pthread_mutex_lock(&mutex2);
    // ...
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
    return NULL;
}

void* bad_lock_order2(void* arg) {
    pthread_mutex_lock(&mutex2);
    pthread_mutex_lock(&mutex1);
    // ...
    pthread_mutex_unlock(&mutex1);
    pthread_mutex_unlock(&mutex2);
    return NULL;
}
"""
        
        self.toctou_pseudocode = """
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

void process_file(const char* path) {
    if (access(path, R_OK) == 0) {
        int fd = open(path, O_RDONLY);
        // TOCTOU race condition here
        read(fd, buffer, sizeof(buffer));
        close(fd);
    }
}

void signal_handler(int sig) {
    printf("Signal received\\n");
    free(some_buffer);
}
"""

    def test_init(self):
        """
        测试分析器初始化
        """
        analyzer = ConcurrencyAnalyzer(self.simple_pseudocode)
        self.assertIsInstance(analyzer, ConcurrencyAnalyzer)
        self.assertEqual(analyzer.pseudocode, self.simple_pseudocode)

    def test_thread_detection(self):
        """
        测试线程创建检测
        """
        analyzer = ConcurrencyAnalyzer(self.simple_pseudocode)
        self.assertEqual(len(analyzer.thread_create_points), 2)
        self.assertTrue(any(tcp.thread_func == 'thread_func1' for tcp in analyzer.thread_create_points))
        self.assertTrue(any(tcp.thread_func == 'thread_func2' for tcp in analyzer.thread_create_points))

    def test_sync_operations_detection(self):
        """
        测试同步操作检测
        """
        analyzer = ConcurrencyAnalyzer(self.simple_pseudocode)
        lock_ops = [op for op in analyzer.sync_operations if op.operation_type == 'mutex_lock']
        unlock_ops = [op for op in analyzer.sync_operations if op.operation_type == 'mutex_unlock']
        self.assertGreaterEqual(len(lock_ops), 2)
        self.assertGreaterEqual(len(unlock_ops), 2)
        self.assertIn('mutex', str([op.lock_name for op in lock_ops]))

    def test_global_variable_detection(self):
        """
        测试全局变量检测
        """
        analyzer = ConcurrencyAnalyzer(self.simple_pseudocode)
        self.assertIn('global_counter', analyzer.global_variables)
        self.assertIn('mutex', analyzer.global_variables)

    def test_data_race_analysis_with_protection(self):
        """
        测试有锁保护的数据访问不应被检测为数据竞争
        """
        analyzer = ConcurrencyAnalyzer(self.simple_pseudocode)
        issues = analyzer.analyze_data_race()
        self.assertEqual(len(issues), 0)

    def test_data_race_analysis_without_protection(self):
        """
        测试无锁保护的数据写入应被检测为数据竞争
        """
        analyzer = ConcurrencyAnalyzer(self.race_condition_pseudocode)
        issues = analyzer.analyze_data_race()
        self.assertGreaterEqual(len(issues), 1)
        data_race_issues = [i for i in issues if i.issue_type == 'data_race']
        self.assertGreaterEqual(len(data_race_issues), 1)

    def test_deadlock_detection(self):
        """
        测试死锁检测
        """
        deadlock_code = """
pthread_mutex_t mutex1;
pthread_mutex_t mutex2;

void func1() {
    pthread_mutex_lock(&mutex1);
    pthread_mutex_lock(&mutex2);
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
}

void func2() {
    pthread_mutex_lock(&mutex2);
    pthread_mutex_lock(&mutex1);
    pthread_mutex_unlock(&mutex1);
    pthread_mutex_unlock(&mutex2);
}
"""
        analyzer = ConcurrencyAnalyzer(deadlock_code)
        issues = analyzer.analyze_deadlock()
        self.assertGreaterEqual(len(issues), 1)
        deadlock_issues = [i for i in issues if i.issue_type == 'deadlock']
        self.assertGreaterEqual(len(deadlock_issues), 1)

    def test_toctou_detection(self):
        """
        测试TOCTOU竞态条件检测
        """
        analyzer = ConcurrencyAnalyzer(self.toctou_pseudocode)
        issues = analyzer.analyze_toctou()
        self.assertGreaterEqual(len(issues), 1)
        toctou_issues = [i for i in issues if i.issue_type == 'toctou']
        self.assertGreaterEqual(len(toctou_issues), 1)

    def test_signal_unsafe_function_detection(self):
        """
        测试信号处理中不安全函数检测
        """
        analyzer = ConcurrencyAnalyzer(self.toctou_pseudocode)
        issues = analyzer.analyze_toctou()
        signal_issues = [i for i in issues if 'signal_handler' in i.function_name]
        self.assertGreaterEqual(len(signal_issues), 1)

    def test_analyze_full(self):
        """
        测试完整分析流程
        """
        result = analyze_concurrency(self.race_condition_pseudocode)
        self.assertIn('thread_create_points', result)
        self.assertIn('sync_operations', result)
        self.assertIn('shared_variables', result)
        self.assertIn('issues', result)
        self.assertIn('summary', result)

    def test_empty_pseudocode(self):
        """
        测试空伪代码输入
        """
        result = analyze_concurrency('')
        self.assertIsInstance(result, dict)
        self.assertEqual(result['summary']['total_issues'], 0)

    def test_no_concurrency_code(self):
        """
        测试无并发代码的情况
        """
        simple_code = """
int main() {
    int x = 0;
    x++;
    return 0;
}
"""
        result = analyze_concurrency(simple_code)
        self.assertEqual(result['summary']['total_threads'], 0)
        self.assertEqual(result['summary']['total_sync_ops'], 0)
        self.assertEqual(result['summary']['total_issues'], 0)


if __name__ == '__main__':
    unittest.main()
