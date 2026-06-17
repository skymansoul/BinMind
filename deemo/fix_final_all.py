import os
import re
import py_compile

def fix_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Fix 1: Regular expression escape sequences
        lines = content.split("\n")
        for i in range(len(lines)):
            line = lines[i]
            # Fix \. to \\. in strings
            if '"' in line or "'" in line:
                line = line.replace("\.", "\\.").replace("\d", "\\d").replace("\s", "\\s")
                lines[i] = line
        
        content = "\n".join(lines)
        
        # Fix 2: Function definitions - ensure parentheses are balanced
        content = re.sub(r"(def \w+\([^)]*)\)\s*\n\s*([^#)\s].*)", r"\1, \2)", content)
        
        # Fix 3: Ensure all strings are properly closed at end of file
        if content.count('"') % 2 != 0:
            content += '"'
        if content.count("'") % 2 != 0:
            content += "'"
        
        # Fix 4: Remove trailing commas before ) in function definitions
        content = re.sub(r",\s*\)", ")", content)
        
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

if __name__ == "__main__":
    main()
