import os
import re
import py_compile

def fix_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Fix function definitions that are split incorrectly
        # Match pattern: def func(...) \n ... -> merge to single line
        lines = content.split("\n")
        i = 0
        modified = False
        
        while i < len(lines):
            line = lines[i]
            
            # Look for function definitions
            match = re.match(r"(\s*def \w+\()([^)]*)(\))(\s*->\s*\w+)?\s*$", line)
            if match:
                indent = match.group(1)
                params = match.group(2)
                return_type = match.group(4) or ""
                
                # Check if next line looks like continuation
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    # Check if next line is indented more than current
                    next_stripped = next_line.strip()
                    if next_stripped and not next_stripped.startswith(("#", "def ", "class ", ":")):
                        # This might be a continuation
                        # Count indentation
                        current_indent = len(line) - len(line.lstrip())
                        next_indent = len(next_line) - len(next_line.lstrip())
                        
                        if next_indent > current_indent:
                            # This is indented - likely continuation
                            if ":" in next_stripped or "=" in next_stripped:
                                # Move it up
                                new_line = line.rstrip()[:-1] + ", " + next_stripped + ")" + return_type
                                lines[i] = new_line
                                del lines[i + 1]
                                modified = True
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
    
    for _ in range(5):
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
