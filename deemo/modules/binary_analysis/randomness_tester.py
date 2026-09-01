import logging
import math
from typing import Dict, Any, List, Optional
from collections import Counter

logger = logging.getLogger(__name__)



class RandomnessTest:

    @staticmethod
    def frequency_test(data: bytes) -> Dict[str, Any]:
        if not data:
            return {'pass': False, 'reason': 'empty'}
        ones = sum(bin(b).count('1') for b in data)
        total_bits = len(data) * 8
        zeros = total_bits - ones
        ratio = ones / max(1, total_bits)
        passed = 0.45 <= ratio <= 0.55
        return {
            'test': 'frequency_monobit',
            'passed': passed,
            'ones': ones, 'zeros': zeros, 'ratio': round(ratio, 4),
            'ideal': 0.5,
            'threshold': '±0.05'
        }

    @staticmethod
    def runs_test(data: bytes) -> Dict[str, Any]:
        if not data:
            return {'pass': False, 'reason': 'empty'}
        bits = ''.join(bin(b)[2:].zfill(8) for b in data)
        runs = 1
        for i in range(1, len(bits)):
            if bits[i] != bits[i - 1]:
                runs += 1
        n = len(bits)
        expected_runs = (2 * n) / 3
        passed = abs(runs - expected_runs) < (2.0 * math.sqrt(n))
        return {
            'test': 'runs',
            'passed': passed,
            'runs': runs,
            'expected_runs': round(expected_runs, 1),
            'total_bits': n
        }

    @staticmethod
    def chi_squared_test(data: bytes, num_bins: int = 256) -> Dict[str, Any]:
        if not data or len(data) < 100:
            return {'pass': False, 'reason': 'insufficient_data'}
        freq = Counter(data)
        expected = len(data) / num_bins
        chi2 = sum((freq.get(i, 0) - expected) ** 2 / expected
                  for i in range(num_bins))
        passed = chi2 < 293
        return {
            'test': 'chi_squared',
            'passed': passed,
            'chi2_statistic': round(chi2, 2),
            'degrees_of_freedom': num_bins - 1,
            'critical_value_95': 293.0
        }

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        n = len(data)
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def entropy_test(data: bytes) -> Dict[str, Any]:
        """熵检验"""
        ent = RandomnessTest.shannon_entropy(data)
        passed = ent >= 7.5
        return {
            'test': 'shannon_entropy',
            'passed': passed,
            'entropy': round(ent, 4),
            'max_entropy': 8.0,
            'threshold': 7.5,
            'quality': 'good' if ent >= 7.8 else
                      'adequate' if ent >= 7.0 else
                      'poor' if ent >= 5.0 else 'very_poor'
        }


class RandomnessTester:

    def __init__(self):
        self._results: List[Dict[str, Any]] = []

    def analyze(self, data: Optional[bytes] = None,
                **kwargs) -> Dict[str, Any]:
        results = []
        if data:
            results.append(RandomnessTest.frequency_test(data))
            results.append(RandomnessTest.runs_test(data))
            results.append(RandomnessTest.chi_squared_test(data))
            results.append(RandomnessTest.entropy_test(data))

        passed = sum(1 for r in results if r.get('passed', False))
        total = len(results)

        self._results = results
        return {
            'success': True,
            'data_size_bytes': len(data) if data else 0,
            'tests_run': total,
            'tests_passed': passed,
            'all_passed': passed == total,
            'results': results,
            'overall_quality': 'good' if passed == total else
                              'acceptable' if passed >= total * 0.75 else
                              'poor' if passed >= 1 else 'failed',
            'recommendations': [
                '使用 /dev/urandom  or  getrandom() 替代 rand()'
            ] if passed < total else []
        }


def test_randomness(data: bytes, **kwargs) -> Dict[str, Any]:
    tester = RandomnessTester()
    return tester.analyze(data=data)


__all__ = ["RandomnessTester", "RandomnessTest", "test_randomness"]
