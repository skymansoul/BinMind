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
            
            # Fix function definitions
            if line.strip().startswith("def "):
                # Find matching closing paren
                open_parens = line.count("(")
                close_parens = line.count(")")
                
                if open_parens > close_parens:
                    # Need to find closing paren
                    j = i + 1
                    total_open = open_parens
                    total_close = close_parens
                    while j < len(lines) and total_open > total_close:
                        total_open += lines[j].count("(")
                        total_close += lines[j].count(")")
                        j += 1
                    
                    if total_open == total_close:
                        # Join lines
                        joined = " ".join(lines[i:j])
                        # Remove extra newlines/whitespace
                        joined = re.sub(r"\s+", " ", joined)
                        # Replace the lines
                        lines[i] = joined
                        del lines[i+1:j]
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
    
    for _ in range(3):
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
