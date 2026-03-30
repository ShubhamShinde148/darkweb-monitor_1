from flask import Blueprint, render_template
from app.models import User, Certificate

performance_bp = Blueprint('performance', __name__)

@performance_bp.route('/admin/performance')
def performance():
    top_users = User.query.order_by(User.score.desc()).limit(10).all()
    total_certificates = Certificate.query.count()
    return render_template('user_performance.html', top_users=top_users, total_certificates=total_certificates)