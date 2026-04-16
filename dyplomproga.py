import os
import argparse
import ast
import json

# --- ЯДРО АНАЛІЗАТОРА ---
class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    # 1. Шукаємо RCE та SQL-ін'єкції (аналіз викликів функцій)
    def visit_Call(self, node):
        # Перевірка на RCE (eval, exec)
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append({
                    'type': 'Критична (RCE)',
                    'message': f'Використання небезпечної функції {node.func.id}()',
                    'line': node.lineno
                })
        
        # Перевірка на SQL-ін'єкції (виклик методу .execute)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute':
                if node.args:
                    first_arg = node.args[0]
                    # Перевіряємо, чи є запит динамічним (f-рядок або зліплення рядків через + чи %)
                    is_dynamic_string = isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
                    # Перевіряємо, чи використовується метод .format()
                    is_format_call = isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format'
                    
                    if is_dynamic_string or is_format_call:
                        self.vulnerabilities.append({
                            'type': 'Висока (SQL Injection)',
                            'message': 'Динамічне формування SQL-запиту. Використовуйте параметризовані запити!',
                            'line': node.lineno
                        })

        self.generic_visit(node) # Продовжуємо йти по дереву

    # 2. Шукаємо захардкоджені секрети у змінних
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(secret in var_name for secret in ['password', 'secret', 'api_key', 'token']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.vulnerabilities.append({
                            'type': 'Середня (Hardcoded Secret)',
                            'message': f'Можливий захардкоджений секрет у змінній "{target.id}"',
                            'line': node.lineno
                        })
        self.generic_visit(node)

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        tree = ast.parse(code)
        analyzer = SecurityAnalyzer()
        analyzer.visit(tree)
        return analyzer.vulnerabilities
    except SyntaxError:
        return [{'type': 'Помилка парсингу', 'message': 'Синтаксична помилка у файлі (код невалідний)', 'line': 0}]
    except Exception as e:
        return [{'type': 'Помилка читання', 'message': str(e), 'line': 0}]

# --- НАВІГАЦІЯ ТА ЗАПУСК ---
def find_python_files(directory):
    py_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                py_files.append(os.path.join(root, file))
    return py_files

def main():
    parser = argparse.ArgumentParser(description="SAST Scanner - Дипломний проєкт")
    parser.add_argument("target_path", nargs="?", default=".", help="Шлях для сканування (за замовчуванням: поточна папка)")
    args = parser.parse_args()
    target = args.target_path

    if not os.path.exists(target):
        print(f"❌ Помилка: Шлях '{target}' не знайдено!")
        return

    print(f"🔍 Запуск сканування: {target}\n" + "="*60)

    files_to_scan = []
    if os.path.isfile(target) and target.endswith('.py'):
        files_to_scan.append(target)
    elif os.path.isdir(target):
        files_to_scan = find_python_files(target)

    total_vulns = 0
    report_data = [] #  збереження результатів у JSON

    for file in files_to_scan:
        vulns = analyze_file(file)
        
        if len(vulns) > 0:
            print(f"\n🚨 Файл: {file}")
            
            # Зберігаю дані 
            report_entry = {"file": file, "vulnerabilities": []}
            
            for v in vulns:
                if 'Помилка' in v['type']:
                    print(f"   [!] {v['type']}: {v['message']}")
                else:
                    print(f"   [Рядок {v['line']}] {v['type']}: {v['message']}")
                    total_vulns += 1
                report_entry["vulnerabilities"].append(v)
            
            report_data.append(report_entry)

    print("\n" + "="*60)
    print(f"✅ Сканування завершено! Знайдено вразливостей: {total_vulns}")

    # Генерація JSON-звіту
    if report_data:
        report_filename = "sast_report.json"
        with open(report_filename, "w", encoding="utf-8") as json_file:
            json.dump(report_data, json_file, ensure_ascii=False, indent=4)
        print(f"📄 Детальний звіт збережено у файл: {report_filename}")

if __name__ == "__main__":
    main()