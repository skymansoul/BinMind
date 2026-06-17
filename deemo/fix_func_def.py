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
            
            # Fix function definition with trailing comma before newline
            match = re.match(r"(\s*def \w+\([^)]*),\s*$", line)
            if match:
                # Check if next line continues the function signature
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and not next_line.startswith(")"):
                        # Keep the comma for multi-line signature
                        pass
                    else:
                        # Remove trailing comma
                        lines[i] = line.rstrip().rstrip(",")
                        modified = True
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
    for filepath, error in errors[:10]:
        print(f"{filepath}: {error}")

if __name__ == "__main__":
    main()
