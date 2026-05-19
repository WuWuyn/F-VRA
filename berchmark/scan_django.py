import os
import ast
import pandas as pd

class FastAPIClassVisitor(ast.NodeVisitor):
    """
    AST Visitor to traverse the abstract syntax tree and extract 
    function and method signatures within classes.
    """
    def __init__(self, module_fullname):
        self.module_fullname = module_fullname
        self.current_class = None
        self.extracted_functions = []

    def visit_ClassDef(self, node):
        """Track entry and exit of class definitions to maintain context."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node):
        """Handle standard function definitions."""
        self.register_function(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        """Handle asynchronous function definitions."""
        self.register_function(node.name)
        self.generic_visit(node)

    def register_function(self, func_name):
        """Format and store the fully qualified name of the function."""
        if self.current_class:
            fullname = f"{self.module_fullname}.{self.current_class}.{func_name}"
        else:
            fullname = f"{self.module_fullname}.{func_name}"
        self.extracted_functions.append(fullname)

def extract_functions_from_file(file_path, package_root, base_package="django"):
    """
    Parses a single Python file to extract all function and method signatures.
    Returns a list of fully qualified names.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=file_path)
            
        # Derive module path from file structure
        rel_path = os.path.relpath(file_path, package_root)
        mod_name = os.path.splitext(rel_path)[0].replace(os.sep, ".")
        
        # Build qualified module name
        module_fullname = f"{base_package}.{mod_name}"
        if module_fullname.endswith(".__init__"):
            module_fullname = module_fullname[:-9]

        visitor = FastAPIClassVisitor(module_fullname)
        visitor.visit(tree)
        return visitor.extracted_functions
    except Exception:
        # Silently skip files that cannot be parsed
        return []

def scan_directory(path):
    """
    Recursively scans the provided directory for Python files 
    and collects all discovered function signatures.
    """
    all_functions = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                all_functions.extend(extract_functions_from_file(file_path, path))
    
    # Return sorted unique function signatures
    return sorted(list(set(all_functions)))

if __name__ == "__main__":
    import django
    # Ensure we are targeting the actual library directory
    django_dir = os.path.dirname(django.__file__)
    
    print(f"[*] Scanning Django codebase at: {django_dir}")
    functions_list = scan_directory(django_dir)
    
    # Export the function signature registry to Excel
    df = pd.DataFrame(functions_list, columns=["Full Name (package.module.class.function)"])
    output_file = "django_functions_list.xlsx"
    df.to_excel(output_file, index=False)
    
    print(f"[SUCCESS] Exported {len(functions_list)} signatures to: {output_file}")