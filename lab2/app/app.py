from flask import Flask, render_template, request
import re

app = Flask(__name__)
application = app

def validate_phone_number(phone):
    allowed_chars_pattern = r'^[\d\s()\-+.]+$'
    if not re.match(allowed_chars_pattern, phone):
        return "Недопустимый ввод. В номере телефона встречаются недопустимые символы."
    
    digits = re.sub(r'\D', '', phone)
    
    if len(digits) == 11 and (digits.startswith("7") or digits.startswith("8")):
        formatted_phone = f"8-{digits[1:4]}-{digits[4:7]}-{digits[7:9]}-{digits[9:11]}"
        return formatted_phone
    elif len(digits) == 10:
        formatted_phone = f"8-{digits[0:3]}-{digits[3:6]}-{digits[6:8]}-{digits[8:10]}"
        return formatted_phone
    else:
        return "Недопустимый ввод. Неверное количество цифр."


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/params')
def params():
    return render_template('params.html', title='Параметры URL', request=request)

@app.route('/headers')
def headers():
    return render_template('headers.html', title='Заголовки запроса', request=request)

@app.route('/cookies')
def cookies():
    return render_template('cookies.html', title='Cookies', request=request)

@app.route('/form', methods=['GET', 'POST'])
def form():
    error = None
    formatted_phone = None
    
    if request.method == 'POST':
        phone_input = request.form.get('phone', '')
        result = validate_phone_number(phone_input)
        if "Недопустимый ввод" in result:
            error = result
        else:
            formatted_phone = result

    return render_template('form.html', title='Параметры формы', request=request, error=error, f_phone=formatted_phone)

if __name__ == '__main__':
    app.run(debug=True)
