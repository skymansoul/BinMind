import os
import re
import py_compile

def fix_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        lines = content.split("\n")
        modified = False
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Fix pattern: return ClassName() followed by indented arguments
            match = re.match(r"(\s+)return (\w+)\(\)", line)
            if match:
                indent = match.group(1)
                class_name = match.group(2)
                
                # Check next lines for indented arguments
                j = i + 1
                args_lines = []
                while j < len(lines):
                    next_line = lines[j]
                    # Check if next line is indented more than current
                    if next_line.strip() and len(next_line) - len(next_line.lstrip()) > len(indent):
                        args_lines.append(next_line)
                        j += 1
                    else:
                        break
                
                if args_lines:
                    # Fix: replace return ClassName() with return ClassName(
                    lines[i] = f"{indent}return {class_name}("
                    # Add closing parenthesis after args
                    lines[j-1] = lines[j-1].rstrip() + ")"
                    modified = True
                    i = j
                    continue
            
            i += 1
        
        if modified:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        
        return modified
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    modules_dir = "modules"
    fixed_count = 0
    
    for filename in os.listdir(modules_dir):
        if filename.endswith(".py"):
            filepath = os.path.join(modules_dir, filename)
            if fix_file(filepath):
                fixed_count += 1
    
    print(f"Fixed {fixed_count} files")
    
    errors = []
    for filename in os.listdir(modules_dir):
        if filename.endswith(".py"):
            filepath = os.path.join(modules_dir, filename)
            try:
                py_compile.compile(filepath, doraise=True)
            except py_compile.PyCompileError as e:
                errors.append((filepath, str(e).split(chr(10))[0]))
    
    print(f"Remaining errors: {len(errors)}")
    for filepath, error in errors[:5]:
        print(f"{filepath}: {error}")

if __name__ == "__main__":
    main()
