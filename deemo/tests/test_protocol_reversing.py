import unittest
import os
import tempfile
import shutil

from modules.protocol_reversing import (
    ProtocolFieldType,
    ProtocolField,
    ProtocolMessage,
    ProtocolFormatInferrer,
    ProtocolFuzzGenerator,
    create_protocol_inferrer,
    create_fuzz_generator
)


class TestProtocolFieldType(unittest.TestCase):
    """协议字段类型枚举测试"""

    def test_field_types(self):
        self.assertEqual(ProtocolFieldType.UINT8.value, 'uint8')
        self.assertEqual(ProtocolFieldType.UINT16.value, 'uint16')
        self.assertEqual(ProtocolFieldType.UINT32.value, 'uint32')
        self.assertEqual(ProtocolFieldType.STRING.value, 'string')
        self.assertEqual(ProtocolFieldType.BYTES.value, 'bytes')


class TestProtocolField(unittest.TestCase):
    """协议字段类测试"""

    def test_field_init(self):
        field = ProtocolField(
            name='length',
            field_type=ProtocolFieldType.UINT16,
            offset=0,
            size=2,
            description='消息长度'
        )
        self.assertEqual(field.name, 'length')
        self.assertEqual(field.field_type, ProtocolFieldType.UINT16)
        self.assertEqual(field.offset, 0)
        self.assertEqual(field.size, 2)
        self.assertEqual(field.description, '消息长度')

    def test_field_to_dict(self):
        field = ProtocolField(
            name='magic',
            field_type=ProtocolFieldType.UINT16,
            offset=0,
            size=2,
            enum_values={1: 'REQUEST', 2: 'RESPONSE'}
        )
        field_dict = field.to_dict()
        self.assertEqual(field_dict['name'], 'magic')
        self.assertEqual(field_dict['type'], 'uint16')
        self.assertEqual(field_dict['enum_values'], {1: 'REQUEST', 2: 'RESPONSE'})


class TestProtocolMessage(unittest.TestCase):
    """协议消息类测试"""

    def test_message_init(self):
        msg = ProtocolMessage('TestMessage')
        self.assertEqual(msg.name, 'TestMessage')
        self.assertEqual(msg.fields, [])

    def test_add_field(self):
        msg = ProtocolMessage('TestMessage')
        field = ProtocolField('length', ProtocolFieldType.UINT16, 0, 2)
        msg.add_field(field)
        self.assertEqual(len(msg.fields), 1)
        self.assertEqual(msg.fields[0].name, 'length')

    def test_get_total_size(self):
        msg = ProtocolMessage('TestMessage')
        msg.add_field(ProtocolField('field1', ProtocolFieldType.UINT16, 0, 2))
        msg.add_field(ProtocolField('field2', ProtocolFieldType.UINT32, 2, 4))
        self.assertEqual(msg.get_total_size(), 6)

    def test_to_dict(self):
        msg = ProtocolMessage('TestMessage')
        msg.add_field(ProtocolField('length', ProtocolFieldType.UINT16, 0, 2))
        msg_dict = msg.to_dict()
        self.assertEqual(msg_dict['name'], 'TestMessage')
        self.assertEqual(len(msg_dict['fields']), 1)


class TestProtocolFormatInferrer(unittest.TestCase):
    """协议格式推断器测试"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validate_path(self):
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')
        
        inferrer = ProtocolFormatInferrer(test_file)
        self.assertEqual(inferrer.binary_path, os.path.abspath(test_file))

    def test_validate_path_empty(self):
        with self.assertRaises(ValueError):
            ProtocolFormatInferrer('')

    def test_validate_path_nonexistent(self):
        with self.assertRaises(ValueError):
            ProtocolFormatInferrer('/nonexistent/file.bin')

    def test_create_protocol_inferrer(self):
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        inferrer = create_protocol_inferrer(test_file)
        self.assertIsInstance(inferrer, ProtocolFormatInferrer)

    def test_add_raw_sample(self):
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        inferrer = ProtocolFormatInferrer(test_file)
        inferrer.add_raw_sample(b'\x00\x08hello')
        
        self.assertEqual(len(inferrer.raw_bytes), 1)

    def test_infer_protocol_basic(self):
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        inferrer = ProtocolFormatInferrer(test_file)
        messages = inferrer.infer_protocol()
        
        self.assertIsInstance(messages, list)
        self.assertGreater(len(messages), 0)

    def test_generate_protocol_spec(self):
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        inferrer = ProtocolFormatInferrer(test_file)
        inferrer.infer_protocol()
        
        spec = inferrer.generate_protocol_spec()
        self.assertIsInstance(spec, str)
        self.assertIn('协议格式规格说明', spec)


class TestProtocolFuzzGenerator(unittest.TestCase):
    """协议模糊测试生成器测试"""

    def setUp(self):
        self.messages = [
            ProtocolMessage('TestMessage')
        ]
        self.messages[0].add_field(ProtocolField(
            name='length',
            field_type=ProtocolFieldType.UINT16,
            offset=0,
            size=2
        ))
        self.messages[0].add_field(ProtocolField(
            name='payload',
            field_type=ProtocolFieldType.BYTES,
            offset=2,
            size=10
        ))

    def test_create_fuzz_generator(self):
        generator = create_fuzz_generator(self.messages)
        self.assertIsInstance(generator, ProtocolFuzzGenerator)

    def test_generate_seed_cases(self):
        generator = ProtocolFuzzGenerator(self.messages)
        seeds = generator.generate_seed_cases(count=5)
        
        self.assertIsInstance(seeds, list)
        self.assertEqual(len(seeds), 5)
        for seed in seeds:
            self.assertIsInstance(seed, bytes)

    def test_generate_mutation_cases(self):
        generator = ProtocolFuzzGenerator(self.messages)
        seed = b'\x00\x0c' + b'hello world'
        
        mutations = generator.generate_mutation_cases(seed, count=3)
        
        self.assertEqual(len(mutations), 3)
        for mutation in mutations:
            self.assertIsInstance(mutation, bytes)

    def test_bit_flip_mutation(self):
        generator = ProtocolFuzzGenerator([])
        seed = b'\x00\x01\x02\x03'
        
        mutated = generator._bit_flip_mutation(seed)
        
        self.assertEqual(len(mutated), 4)
        self.assertEqual(mutated[:3], b'\xff\xfe\xfd')

    def test_length_overflow(self):
        generator = ProtocolFuzzGenerator([])
        seed = b'\x00\x0chello'
        
        mutated = generator._length_overflow(seed)
        
        self.assertEqual(mutated[:2], b'\xff\xff')

    def test_truncation(self):
        generator = ProtocolFuzzGenerator([])
        seed = b'hello world'
        
        truncated = generator._truncation(seed)
        
        self.assertEqual(len(truncated), 5)

    def test_append_garbage(self):
        generator = ProtocolFuzzGenerator([])
        seed = b'hello'
        
        result = generator._append_garbage(seed)
        
        self.assertEqual(len(result), 105)
        self.assertTrue(result.endswith(b'\x41' * 100))

    def test_generate_harness(self):
        generator = ProtocolFuzzGenerator(self.messages)
        harness = generator.generate_fuzzing_harness()
        
        self.assertIsInstance(harness, str)
        self.assertIn('LLVMFuzzerTestOneInput', harness)
        self.assertIn('struct testmessage', harness.lower())

    def test_generate_afl_dict(self):
        msg_with_enum = ProtocolMessage('MessageWithEnum')
        msg_with_enum.add_field(ProtocolField(
            name='command',
            field_type=ProtocolFieldType.ENUM,
            offset=0,
            size=4,
            enum_values={1: 'CMD_REQUEST', 2: 'CMD_RESPONSE'}
        ))
        
        generator = ProtocolFuzzGenerator([msg_with_enum])
        dict_content = generator.generate_afl_dict()
        
        self.assertIsInstance(dict_content, str)
        self.assertIn('CMD_REQUEST', dict_content)

    def test_get_all_cases(self):
        generator = ProtocolFuzzGenerator(self.messages)
        generator.generate_seed_cases(count=3)
        
        cases = generator.get_all_cases()
        
        self.assertEqual(len(cases), 3)


class TestPCAPParsing(unittest.TestCase):
    """PCAP解析测试"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parse_pcap_manual_basic(self):
        pcap_file = os.path.join(self.temp_dir, 'test.pcap')
        
        with open(pcap_file, 'wb') as f:
            f.write(b'\xd4\xc3\xb2\xa1')
            f.write(b'\x00\x00\x02\x04')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x00')
            
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x1e')
            f.write(b'\x00\x00\x00\x1e')
            
            f.write(b'\x00\x00\x00\x00\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x08\x00')
            f.write(b'\x45')
            f.write(b'\x00')
            f.write(b'\x00\x14')
            f.write(b'\x00\x00\x00\x00\x40\x06')
            f.write(b'\x00\x00')
            f.write(b'\x7f\x00\x00\x01')
            f.write(b'\x7f\x00\x00\x01')
            f.write(b'\x00\x50')
            f.write(b'\x00\x50')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x00\x00\x00\x00')
            f.write(b'\x50\x02')
            f.write(b'\x00\x00')
            f.write(b'\x00\x00')
            f.write(b'hello')
        
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        inferrer = ProtocolFormatInferrer(test_file)
        success = inferrer.add_pcap_sample(pcap_file)
        
        self.assertTrue(success)


if __name__ == '__main__':
    unittest.main()
