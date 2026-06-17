import os
import re
import py_compile

def fix_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        lines = content.split("\n")
        modified = False
        
        for i in range(len(lines)):
            line = lines[i]
            
            # Fix trailing comma before newline in function parameters
            if ", )" in line or ",\s*\)" in line:
                lines[i] = re.sub(r",\s*\)", ")", line)
                modified = True
            
            # Fix function signature split across lines
            if "(" in line and line.strip().endswith(",") and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line and not next_line.startswith(")"):
                    # Check if next line continues the parameter list
                    if not next_line.startswith(("def ", "class ", "return ", "#")):
                        # This is likely a multi-line function signature
                        # Ensure proper continuation
                        pass
            
            # Fix return statements with misplaced parentheses
            if line.strip().startswith("return ") and "()" in line:
                parts = line.split("()")
                if len(parts) > 1 and parts[1].strip():
                    # Move the content after () to be inside
                    lines[i] = line.replace("()", "(") + ")"
                    modified = True
        
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
