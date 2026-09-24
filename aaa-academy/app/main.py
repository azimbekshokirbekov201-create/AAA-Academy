from pathlib import Path
from datetime import date, datetime
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import engine, get_db
from app.auth import verify_password, hash_password, token, decode, COOKIE_NAME

BASE = Path(__file__).resolve().parent
app = FastAPI(title='AAA Academy')
app.mount('/static', StaticFiles(directory=str(BASE / 'static')), name='static')
templates = Jinja2Templates(directory=str(BASE / 'templates'))

def init():
    with engine.begin() as c:
        c.execute(text("""CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, username VARCHAR(64) UNIQUE NOT NULL, hashed_password VARCHAR(255) NOT NULL, role VARCHAR(16) NOT NULL, student_id INTEGER, teacher_name VARCHAR(128), full_name VARCHAR(128), is_active BOOLEAN DEFAULT 1, created_at DATETIME)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS teachers (id INTEGER PRIMARY KEY, full_name VARCHAR(128) NOT NULL, phone VARCHAR(32), username VARCHAR(64) UNIQUE, hashed_password VARCHAR(255), is_active BOOLEAN DEFAULT 1, created_at DATETIME)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS grades (id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, subject VARCHAR(128) NOT NULL, score NUMERIC(5,2) NOT NULL, max_score NUMERIC(5,2) DEFAULT 100, note TEXT, created_at DATETIME)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS homework (id INTEGER PRIMARY KEY, group_id INTEGER, title VARCHAR(200) NOT NULL, description TEXT, due_date DATE, created_at DATETIME)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS materials (id INTEGER PRIMARY KEY, group_id INTEGER, title VARCHAR(200) NOT NULL, url TEXT, created_at DATETIME)"""))
        try:
            rows = c.execute(text('select id,username,hashed_password,full_name,is_active from admins')).fetchall()
        except Exception:
            rows = []
        for r in rows:
            if not c.execute(text('select id from accounts where username=:u'), {'u': r.username}).fetchone():
                c.execute(text("insert into accounts(username,hashed_password,role,full_name,is_active,created_at) values(:u,:p,'admin',:n,:a,:d)"), {'u': r.username, 'p': r.hashed_password, 'n': r.full_name, 'a': r.is_active, 'd': datetime.utcnow()})
init()

def user(request):
    t = request.cookies.get(COOKIE_NAME)
    return decode(t) if t else None

def guard(request, role=None):
    u = user(request)
    if not u or (role and u.get('role') != role): return None
    return u

def render(request, name, **ctx):
    return templates.TemplateResponse(request=request, name=name, context={'request': request, 'user': user(request), **ctx})

@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse('/dashboard' if user(request) else '/login', 303)

@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request): return render(request, 'login.html')

@app.post('/login')
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    r = db.execute(text('select * from accounts where username=:u and is_active=1'), {'u': username.strip()}).mappings().first()
    if not r or not verify_password(password, r['hashed_password']):
        return render(request, 'login.html', error='Login yoki parol noto‘g‘ri.')
    resp = RedirectResponse('/dashboard', 303)
    resp.set_cookie(COOKIE_NAME, token({'sub': r['username'], 'role': r['role'], 'id': r['id'], 'student_id': r['student_id'], 'full_name': r['full_name']}), httponly=True, samesite='lax')
    return resp

@app.post('/logout')
def logout():
    r = RedirectResponse('/login', 303); r.delete_cookie(COOKIE_NAME); return r

@app.get('/dashboard', response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    u = guard(request)
    if not u: return RedirectResponse('/login', 303)
    if u['role'] == 'student': return RedirectResponse('/student', 303)
    if u['role'] == 'teacher': return RedirectResponse('/teacher', 303)
    students = db.execute(text('select count(*) from students where is_active=1')).scalar() or 0
    groups = db.execute(text('select count(*) from groups where is_active=1')).scalar() or 0
    teachers = db.execute(text('select count(*) from teachers where is_active=1')).scalar() or 0
    paid = db.execute(text('select coalesce(sum(amount_paid),0) from payments')).scalar() or 0
    due = db.execute(text('select coalesce(sum(amount_due-amount_paid),0) from payments where amount_due>amount_paid')).scalar() or 0
    recent = db.execute(text('select p.*,s.full_name from payments p join students s on s.id=p.student_id order by p.id desc limit 6')).mappings().all()
    return render(request, 'admin_dashboard.html', students=students, groups=groups, teachers=teachers, paid=paid, due=due, recent=recent)

@app.get('/groups', response_class=HTMLResponse)
def groups(request: Request, db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    gs = db.execute(text('select g.*, (select count(*) from students s where s.group_id=g.id and s.is_active=1) student_count from groups g order by g.id desc')).mappings().all()
    ts = db.execute(text('select full_name from teachers where is_active=1 order by full_name')).mappings().all()
    return render(request, 'groups.html', groups=gs, teachers=ts)

@app.get('/groups/{group_id}', response_class=HTMLResponse)
def group_detail(request: Request, group_id: int, db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    g = db.execute(text('select * from groups where id=:id'), {'id': group_id}).mappings().first()
    if not g: return RedirectResponse('/groups', 303)
    ss = db.execute(text('select * from students where group_id=:g and is_active=1 order by full_name'), {'g': group_id}).mappings().all()
    return render(request, 'group_detail.html', group=g, students=ss)

@app.post('/groups')
def add_group(request: Request, name: str = Form(...), teacher_name: str = Form(''), schedule: str = Form(''), monthly_fee: float = Form(0), db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    db.execute(text('insert into groups(name,teacher_name,schedule,monthly_fee,is_active,created_at) values(:n,:t,:s,:f,1,:d)'), {'n': name.strip(), 't': teacher_name.strip(), 's': schedule.strip(), 'f': monthly_fee, 'd': datetime.utcnow()}); db.commit()
    return RedirectResponse('/groups', 303)

@app.get('/students', response_class=HTMLResponse)
def students(request: Request, db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    ss = db.execute(text('''select s.*,g.name group_name,a.username account_username from students s left join groups g on g.id=s.group_id left join accounts a on a.student_id=s.id and a.role='student' order by s.id desc''')).mappings().all()
    gs = db.execute(text('select id,name from groups where is_active=1 order by name')).mappings().all()
    return render(request, 'students.html', students=ss, groups=gs)

@app.post('/students')
def add_student(request: Request, full_name: str = Form(...), phone: str = Form(''), parent_phone: str = Form(''), telegram_username: str = Form(''), group_id: int = Form(...), db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    db.execute(text('insert into students(full_name,phone,parent_phone,telegram_username,group_id,enrolled_date,is_active,created_at) values(:n,:p,:pp,:tg,:g,:d,1,:dt)'), {'n': full_name.strip(), 'p': phone.strip(), 'pp': parent_phone.strip(), 'tg': telegram_username.strip(), 'g': group_id, 'd': date.today(), 'dt': datetime.utcnow()}); db.commit()
    return RedirectResponse('/students', 303)

@app.post('/students/{student_id}/account')
def create_student_account(request: Request, student_id: int, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    st = db.execute(text('select * from students where id=:id'), {'id': student_id}).mappings().first()
    if not st: return RedirectResponse('/students', 303)
    username = username.strip()
    if not username or len(password) < 4: return RedirectResponse('/students?error=credentials', 303)
    existing = db.execute(text('select id from accounts where username=:u'), {'u': username}).first()
    linked = db.execute(text("select id from accounts where student_id=:s and role='student'"), {'s': student_id}).first()
    if existing or linked: return RedirectResponse('/students?error=exists', 303)
    hp = hash_password(password)
    db.execute(text("insert into accounts(username,hashed_password,role,student_id,full_name,is_active,created_at) values(:u,:h,'student',:s,:n,1,:d)"), {'u': username, 'h': hp, 's': student_id, 'n': st['full_name'], 'd': datetime.utcnow()}); db.commit()
    return RedirectResponse('/students', 303)

@app.get('/teachers', response_class=HTMLResponse)
def teachers(request: Request, db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    ts = db.execute(text('select * from teachers order by id desc')).mappings().all(); return render(request, 'teachers.html', teachers=ts)

@app.post('/teachers')
def add_teacher(request: Request, full_name: str = Form(...), phone: str = Form(''), username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    username = username.strip()
    if db.execute(text('select id from accounts where username=:u'), {'u': username}).first(): return RedirectResponse('/teachers?error=exists', 303)
    hp = hash_password(password)
    db.execute(text('insert into teachers(full_name,phone,username,hashed_password,is_active,created_at) values(:n,:p,:u,:h,1,:d)'), {'n': full_name.strip(), 'p': phone.strip(), 'u': username, 'h': hp, 'd': datetime.utcnow()})
    db.execute(text("insert into accounts(username,hashed_password,role,teacher_name,full_name,is_active,created_at) values(:u,:h,'teacher',:n,:n,1,:d)"), {'u': username, 'h': hp, 'n': full_name.strip(), 'd': datetime.utcnow()}); db.commit()
    return RedirectResponse('/teachers', 303)

@app.get('/payments', response_class=HTMLResponse)
def payments(request: Request, db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    ps = db.execute(text('select p.*,s.full_name,g.name group_name from payments p join students s on s.id=p.student_id left join groups g on g.id=s.group_id order by p.id desc')).mappings().all()
    ss = db.execute(text('select id,full_name from students where is_active=1 order by full_name')).mappings().all()
    return render(request, 'payments.html', payments=ps, students=ss)

@app.post('/payments')
def add_payment(request: Request, student_id: int = Form(...), period_label: str = Form(...), amount_due: float = Form(...), amount_paid: float = Form(0), due_date: str = Form(...), db: Session = Depends(get_db)):
    if not guard(request, 'admin'): return RedirectResponse('/login', 303)
    st = 'paid' if amount_paid >= amount_due else ('partial' if amount_paid > 0 else 'unpaid')
    db.execute(text('insert into payments(student_id,period_label,amount_due,amount_paid,due_date,status,created_at,updated_at) values(:s,:p,:d,:a,:dd,:st,:dt,:dt)'), {'s': student_id, 'p': period_label, 'd': amount_due, 'a': amount_paid, 'dd': due_date, 'st': st, 'dt': datetime.utcnow()}); db.commit()
    return RedirectResponse('/payments', 303)

@app.get('/attendance', response_class=HTMLResponse)
def attendance(request: Request, group_id: int | None = None, attendance_date: str | None = None, db: Session = Depends(get_db)):
    u = guard(request)
    if not u: return RedirectResponse('/login', 303)
    if u['role'] == 'student': return RedirectResponse('/student', 303)
    groups = db.execute(text('select * from groups where is_active=1 order by name')).mappings().all()
    selected_date = attendance_date or date.today().isoformat()
    if u['role'] == 'teacher':
        groups = [g for g in groups if g['teacher_name'] == (u.get('full_name') or u.get('sub'))]
    selected_group = group_id or (groups[0]['id'] if groups else None)
    students = []
    if selected_group:
        students = db.execute(text('''select s.id,s.full_name,coalesce(a.status,'present') status,coalesce(a.note,'') note from students s left join attendance a on a.student_id=s.id and a.group_id=:g and a.date=:d where s.group_id=:g and s.is_active=1 order by s.full_name'''), {'g': selected_group, 'd': selected_date}).mappings().all()
    recent = db.execute(text('select a.*,s.full_name,g.name group_name from attendance a join students s on s.id=a.student_id left join groups g on g.id=a.group_id order by a.date desc,a.id desc limit 100')).mappings().all()
    return render(request, 'attendance.html', groups=groups, selected_group=selected_group, selected_date=selected_date, students=students, rows=recent, role=u['role'])

@app.post('/attendance/mark')
def mark_attendance(request: Request, group_id: int = Form(...), attendance_date: str = Form(...), db: Session = Depends(get_db), **data):
    u = guard(request)
    if not u or u['role'] not in ('admin','teacher'): return RedirectResponse('/login', 303)
    if u['role'] == 'teacher':
        ok = db.execute(text('select id from groups where id=:g and teacher_name=:n'), {'g': group_id, 'n': u.get('full_name') or u.get('sub')}).first()
        if not ok: return RedirectResponse('/attendance', 303)
    # FastAPI Form fields with dynamic names are handled by reading form directly.
    # This endpoint is replaced below through Request-compatible helper.
    return RedirectResponse(f'/attendance?group_id={group_id}&attendance_date={attendance_date}', 303)

@app.post('/attendance/save')
async def save_attendance(request: Request, db: Session = Depends(get_db)):
    u = guard(request)
    if not u or u['role'] not in ('admin','teacher'): return RedirectResponse('/login', 303)
    form = await request.form()
    group_id = int(form.get('group_id'))
    attendance_date = str(form.get('attendance_date'))
    if u['role'] == 'teacher':
        ok = db.execute(text('select id from groups where id=:g and teacher_name=:n'), {'g': group_id, 'n': u.get('full_name') or u.get('sub')}).first()
        if not ok: return RedirectResponse('/attendance', 303)
    students = db.execute(text('select id from students where group_id=:g and is_active=1'), {'g': group_id}).fetchall()
    for (sid,) in students:
        status = str(form.get(f'status_{sid}', 'present'))
        note = str(form.get(f'note_{sid}', ''))
        exists = db.execute(text('select id from attendance where student_id=:s and group_id=:g and date=:d'), {'s': sid, 'g': group_id, 'd': attendance_date}).first()
        if exists:
            db.execute(text('update attendance set status=:st,note=:n where id=:id'), {'st': status, 'n': note, 'id': exists[0]})
        else:
            db.execute(text('insert into attendance(student_id,group_id,date,status,note,created_at) values(:s,:g,:d,:st,:n,:dt)'), {'s': sid, 'g': group_id, 'd': attendance_date, 'st': status, 'n': note, 'dt': datetime.utcnow()})
    db.commit()
    return RedirectResponse(f'/attendance?group_id={group_id}&attendance_date={attendance_date}', 303)

@app.get('/student', response_class=HTMLResponse)
def student_home(request: Request, db: Session = Depends(get_db)):
    u = guard(request, 'student')
    if not u: return RedirectResponse('/login', 303)
    sid = u.get('student_id')
    s = db.execute(text('select s.*,g.name group_name,g.schedule from students s left join groups g on g.id=s.group_id where s.id=:id'), {'id': sid}).mappings().first()
    if not s: return render(request, 'student.html', student=None, grades=[], payments=[])
    grades = db.execute(text('select * from grades where student_id=:id order by id desc limit 6'), {'id': sid}).mappings().all()
    pays = db.execute(text('select * from payments where student_id=:id order by id desc limit 4'), {'id': sid}).mappings().all()
    att = db.execute(text('select * from attendance where student_id=:id order by date desc limit 10'), {'id': sid}).mappings().all()
    return render(request, 'student.html', student=s, grades=grades, payments=pays, attendance=att)

@app.get('/teacher', response_class=HTMLResponse)
def teacher_home(request: Request, db: Session = Depends(get_db)):
    u = guard(request, 'teacher')
    if not u: return RedirectResponse('/login', 303)
    name = u.get('full_name') or u.get('sub')
    gs = db.execute(text('select * from groups where teacher_name=:n order by name'), {'n': name}).mappings().all()
    return render(request, 'teacher.html', teacher_name=name, groups=gs)
