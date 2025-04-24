from flask import Blueprint, render_template, send_file, request
from flask_login import login_required, current_user
from permission import check_rights
from models import db, VisitLog, User
from sqlalchemy import func
import csv
import io

visit_log_bp = Blueprint('visit_log', __name__, url_prefix='/visit-log')

@visit_log_bp.route('/')
@login_required
@check_rights('view_logs')  
def view_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if current_user.role.name == "Admin":
        logs = VisitLog.query.order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)
    else:
        logs = VisitLog.query.filter_by(user_id=current_user.id).order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)

    return render_template('visit_log.html', logs=logs, User=User)

@visit_log_bp.route('/by-page')
@login_required
@check_rights('view_stats') 
def report_by_page():
    page_stats = (
        db.session.query(VisitLog.path, func.count().label('count'))
        .group_by(VisitLog.path)
        .order_by(func.count().desc())
        .all()
    )
    return render_template('report_by_page.html', stats=page_stats)

@visit_log_bp.route('/by-user')
@login_required
@check_rights('view_stats') 
def report_by_user():
    user_stats = (
        db.session.query(VisitLog.user_id, func.count().label('count'))
        .group_by(VisitLog.user_id)
        .order_by(func.count().desc())
        .all()
    )
    return render_template('report_by_user.html', stats=user_stats, User=User)

@visit_log_bp.route('/by-page/export')
def export_by_page():
    page_stats = (
        db.session.query(VisitLog.path, func.count().label('count'))
        .group_by(VisitLog.path)
        .order_by(func.count().desc())
        .all()
    )

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Страница", "Количество посещений"])
    for path, count in page_stats:
        cw.writerow([path, count])

    output = io.BytesIO()
    output.write('\ufeff'.encode('utf-8')) 
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='report_by_page.csv')

@visit_log_bp.route('/by-user/export')
def export_by_user():
    user_stats = (
        db.session.query(VisitLog.user_id, func.count().label('count'))
        .group_by(VisitLog.user_id)
        .order_by(func.count().desc())
        .all()
    )

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Пользователь", "Количество посещений"])
    for user_id, count in user_stats:
        user = User.query.get(user_id)
        name = f"{user.last_name or ''} {user.first_name} {user.patronymic or ''}" if user else "Неаутентифицированный пользователь"
        cw.writerow([name, count])

    output = io.BytesIO()
    output.write('\ufeff'.encode('utf-8')) 
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='report_by_user.csv')



