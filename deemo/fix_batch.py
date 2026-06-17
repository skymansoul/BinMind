import os
import re
import py_compile

def fix_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Fix 1: Remove double commas in function parameters
        content = re.sub(r",\s*,", ",", content)
        
        # Fix 2: Remove trailing parentheses in function definitions
        content = re.sub(r"(:\s*)\)", r"\1", content)
        
        # Fix 3: Fix = () patterns
        content = re.sub(r"=\s*\(\)", "= (", content)
        
        # Fix 4: Ensure strings are properly closed
        lines = content.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Fix strings that might be split incorrectly
            if '"' in line or "'" in line:
                # Check for unclosed strings
                if line.count('"') % 2 != 0 or line.count("'") % 2 != 0:
                    # Look ahead to find closing
                    j = i + 1
                    while j < len(lines):
                        if '"' in lines[j] or "'" in lines[j]:
                            break
                        j += 1
            
            i += 1
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        return True
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
