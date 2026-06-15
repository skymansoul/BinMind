import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入模块，避免触发 __init__.py 的导入
import importlib.util
spec = importlib.util.spec_from_file_location("syscall_classifier", 
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'syscall_classifier.py'))
syscall_classifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(syscall_classifier)

SyscallClassifier = syscall_classifier.SyscallClassifier
ClassificationResult = syscall_classifier.ClassificationResult
SyscallSequence = syscall_classifier.SyscallSequence
SyscallPattern = syscall_classifier.SyscallPattern
ThreatCategory = syscall_classifier.ThreatCategory


class TestSyscallClassifier(unittest.TestCase):

    def test_init(self):
        classifier = SyscallClassifier()
        self.assertIsNotNone(classifier)

    def test_init_with_model_path(self):
        classifier = SyscallClassifier(model_path='model.pkl')
        self.assertEqual(classifier.model_path, 'model.pkl')

    def test_classify_empty(self):
        classifier = SyscallClassifier()
        result = classifier.classify([])
        self.assertEqual(result.category, ThreatCategory.UNKNOWN)
        self.assertEqual(result.confidence, 0.0)

    def test_classify_ransomware_pattern(self):
        syscalls = ['CreateFile', 'WriteFile', 'EncryptFile', 'DeleteFile']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.RANSOMWARE)
        self.assertGreater(result.confidence, 0.3)

    def test_classify_miner_pattern(self):
        syscalls = ['CreateThread', 'Sleep', 'Connect', 'Recv']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.MINER)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_backdoor_pattern(self):
        syscalls = ['socket', 'bind', 'listen', 'accept', 'CreateProcess']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.BACKDOOR)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_spyware_pattern(self):
        syscalls = ['GetAsyncKeyState', 'BitBlt', 'GetDC']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.SPYWARE)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_downloader_pattern(self):
        syscalls = ['HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'WriteFile']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.DOWNLOADER)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_trojan_pattern(self):
        syscalls = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.TROJAN)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_benign_pattern(self):
        syscalls = ['CreateWindow', 'ShowWindow', 'UpdateWindow', 'DispatchMessage']
        classifier = SyscallClassifier()
        result = classifier.classify(syscalls)
        self.assertEqual(result.category, ThreatCategory.BENIGN)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_sequence(self):
        sequence = SyscallSequence(pid=1234, calls=['CreateFile', 'ReadFile'])
        classifier = SyscallClassifier()
        result = classifier.classify_sequence(sequence)
        self.assertIsNotNone(result)

    def test_batch_classify(self):
        sequences = [
            SyscallSequence(pid=1, calls=['CreateFile', 'EncryptFile']),
            SyscallSequence(pid=2, calls=['socket', 'bind'])
        ]
        classifier = SyscallClassifier()
        results = classifier.batch_classify(sequences)
        self.assertEqual(len(results), 2)

    def test_get_malicious_probability_malicious(self):
        syscalls = ['CreateRemoteThread', 'WriteProcessMemory']
        classifier = SyscallClassifier()
        prob = classifier.get_malicious_probability(syscalls)
        self.assertGreater(prob, 0.0)

    def test_get_malicious_probability_benign(self):
        syscalls = ['CreateWindow', 'ShowWindow']
        classifier = SyscallClassifier()
        prob = classifier.get_malicious_probability(syscalls)
        self.assertEqual(prob, 0.0)

    def test_get_analysis_summary(self):
        syscalls = ['CreateFile', 'EncryptFile']
        classifier = SyscallClassifier()
        summary = classifier.get_analysis_summary(syscalls)
        self.assertIsInstance(summary, dict)
        self.assertIn('category', summary)
        self.assertIn('confidence', summary)

    def test_threat_category_enum(self):
        self.assertEqual(ThreatCategory.RANSOMWARE.value, 'ransomware')
        self.assertEqual(ThreatCategory.TROJAN.value, 'trojan')
        self.assertEqual(ThreatCategory.BACKDOOR.value, 'backdoor')
        self.assertEqual(ThreatCategory.MINER.value, 'miner')
        self.assertEqual(ThreatCategory.SPYWARE.value, 'spyware')
        self.assertEqual(ThreatCategory.BENIGN.value, 'benign')

    def test_syscall_sequence_dataclass(self):
        sequence = SyscallSequence(
            pid=1234,
            calls=['CreateFile', 'ReadFile'],
            timestamps=[100, 200]
        )
        self.assertEqual(sequence.pid, 1234)
        self.assertEqual(len(sequence.calls), 2)

    def test_classification_result_dataclass(self):
        result = ClassificationResult(
            category=ThreatCategory.RANSOMWARE,
            confidence=0.85,
            score=2.5,
            features={'dangerous_call_ratio': 0.5},
            explanation='Test explanation'
        )
        self.assertEqual(result.category, ThreatCategory.RANSOMWARE)
        self.assertEqual(result.confidence, 0.85)

    def test_train(self):
        training_data = [
            (['CreateFile', 'EncryptFile'], ThreatCategory.RANSOMWARE),
            (['CreateWindow'], ThreatCategory.BENIGN)
        ]
        classifier = SyscallClassifier()
        classifier.train(training_data)

    def test_save_load_model(self):
        classifier = SyscallClassifier()
        model_path = 'test_model.pkl'
        try:
            classifier.save_model(model_path)
            self.assertTrue(os.path.exists(model_path))
            
            new_classifier = SyscallClassifier()
            new_classifier.load_model(model_path)
        finally:
            if os.path.exists(model_path):
                os.remove(model_path)

    def test_calculate_pattern_match(self):
        pattern = SyscallPattern(
            name='test',
            pattern=['CreateFile', 'WriteFile'],
            category=ThreatCategory.RANSOMWARE
        )
        classifier = SyscallClassifier()
        score = classifier._calculate_pattern_match(['CreateFile', 'ReadFile'], pattern)
        self.assertEqual(score, 0.5)

    def test_extract_features(self):
        syscalls = ['CreateFile', 'ReadFile', 'socket', 'bind']
        classifier = SyscallClassifier()
        features = classifier._extract_features(syscalls)
        self.assertIsInstance(features, dict)
        self.assertIn('file_call_ratio', features)
        self.assertIn('network_call_ratio', features)


if __name__ == '__main__':
    unittest.main()