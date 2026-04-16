from flask import Flask, render_template, request
import ast

app = Flask(__name__)

# --- ЯДРО АНАЛІЗАТОРА ---
class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        # 1. Перевірка на RCE
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append({
                    'type': 'Критична (RCE)',
                    'message': f'Використання небезпечної функції {node.func.id}()',
                    'line': node.lineno
                })
            # 2. Перевірка на XSS (Cross-Site Scripting)
            elif node.func.id == 'render_template_string':
                self.vulnerabilities.append({
                    'type': 'Висока (XSS)',
                    'message': 'Рендеринг HTML прямо з коду. Ризик ін\'єкції скриптів!',
                    'line': node.lineno
                })
        
        # 3. Перевірка на SQL-ін'єкції
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute' and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)) or \
                   (isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format'):
                    self.vulnerabilities.append({
                        'type': 'Висока (SQL Injection)',
                        'message': 'Динамічне формування запиту. Використовуйте параметри!',
                        'line': node.lineno
                    })

        self.generic_visit(node)

    # 4. Перевірка на захардкоджені секрети
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(secret in var_name for secret in ['password', 'secret', 'api_key', 'token']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.vulnerabilities.append({
                            'type': 'Середня (Hardcoded Secret)',
                            'message': f'Секрет у змінній "{target.id}"',
                            'line': node.lineno
                        })
        self.generic_visit(node)

def analyze_code(code_string):
    """Функція для аналізу тексту коду (замість файлу)"""
    try:
        tree = ast.parse(code_string)
        analyzer = SecurityAnalyzer()
        analyzer.visit(tree)
        return analyzer.vulnerabilities
    except SyntaxError as e:
        return [{'type': 'Помилка парсингу', 'message': f'Синтаксична помилка: {str(e)}', 'line': getattr(e, 'lineno', 0)}]
    except Exception as e:
        return [{'type': 'Системна помилка', 'message': str(e), 'line': 0}]

# --- ВЕБ-СЕРВЕР ---
@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    code_to_check = ""
    
    if request.method == 'POST':
        # Отримуємо код, який користувач вставив у форму
        code_to_check = request.form.get('code_input', '')
        if code_to_check.strip():
            results = analyze_code(code_to_check)
            
    return render_template('index.html', results=results, code_to_check=code_to_check)

if __name__ == '__main__':
    # Запускаємо сервер на локальному порту
    app.run(debug=True)