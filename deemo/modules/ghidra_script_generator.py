import os
import json
from typing import Dict, Any, Optional


def generate_ghidra_script(binary_path: str, output_path: str) -> Dict[str, Any]:
    """
    生成 Ghidra 标注脚本
    
    Args:
        binary_path: 二进制文件路径
        output_path: 输出脚本路径
    
    Returns:
        生成结果字典，包含 success 和输出路径
    """
    try:
        binary_name = os.path.basename(binary_path)
        
        script_content = f'''# Ghidra 标注脚本 - 自动生成
# 二进制文件: {binary_name}
# 生成时间: 自动生成

import ghidra
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function

def run():
    currentProgram = getCurrentProgram()
    listing = currentProgram.getListing()
    symbolTable = currentProgram.getSymbolTable()
    
    print("=" * 60)
    print(f"Ghidra 标注脚本 - {binary_name}")
    print("=" * 60)
    
    # 标记已知的危险函数
    dangerous_functions = [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "memcpy", "memmove", "memset", "bcopy",
        "system", "execve", "fork", "popen",
        "strncpy", "strncat", "snprintf"
    ]
    
    print("\\n📋 危险函数标记:")
    for func_name in dangerous_functions:
        symbols = symbolTable.getSymbols(func_name)
        for symbol in symbols:
            addr = symbol.getAddress()
            func = listing.getFunctionAt(addr)
            if func:
                print(f"  标记危险函数: {func_name} @ 0x{addr.toString()}")
                # 添加注释
                comment = f"⚠ 危险函数: {func_name} - 可能存在安全风险"
                func.setComment(comment)
    
    # 添加自定义数据类型和结构体
    print("\\n📐 添加常用数据类型:")
    try:
        from ghidra.program.model.data import StructureDataType, PointerDataType, IntegerDataType
        
        # 定义常用结构体模板
        common_structs = [
            ("iovec", [("iov_base", PointerDataType(), 8), ("iov_len", IntegerDataType(8), 8)]),
            ("timeval", [("tv_sec", IntegerDataType(8), 8), ("tv_usec", IntegerDataType(8), 8)]),
            ("sockaddr_in", [("sin_family", IntegerDataType(2), 2), ("sin_port", IntegerDataType(2), 2), 
                            ("sin_addr", IntegerDataType(4), 4), ("sin_zero", IntegerDataType(8), 8)])
        ]
        
        dataManager = currentProgram.getDataTypeManager()
        for struct_name, fields in common_structs:
            struct = StructureDataType(struct_name, 0)
            for field_name, field_type, field_size in fields:
                struct.add(field_type, field_size, field_name, "")
            dataManager.addDataType(struct, None)
            print(f"  添加结构体: {struct_name}")
    except Exception as e:
        print(f"  ⚠ 添加数据类型时出错: {e}")
    
    print("\\n✅ 标注脚本执行完成")
    print("=" * 60)

if __name__ == "__main__":
    run()
'''
        
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        return {
            'success': True,
            'output_path': output_path,
            'binary_name': binary_name,
            'message': 'Ghidra脚本生成成功'
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
