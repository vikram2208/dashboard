from passlib.hash import pbkdf2_sha256
from dashboard.settings import JWT_TOKEN
import jwt
from django.http import JsonResponse
from django.db.utils import IntegrityError
import datetime
import json
from .auth import validate_user_email
from .auth import authenticate_user


def login_func(User, request_data):
    try:
        user_data = User.objects.get(email=request_data['email'])
        if pbkdf2_sha256.verify(request_data['password'], user_data.password):
            token = jwt.encode(payload={'email': user_data.email, 'user_type': user_data.usertype,
                                        'exp': datetime.datetime.now() + datetime.timedelta(days=1)}, algorithm='HS256',
                               key=JWT_TOKEN)
            response = JsonResponse({'message': 'Login success', 'token': token.decode('utf-8')})
        else:
            response = JsonResponse({'message': 'Invalid username or password'}, status=401)
        return response
    except User.DoesNotExist as error:
        return JsonResponse({'message': 'Invalid username or password'}, status=401)
    except:
        return JsonResponse({'message': 'Login not working'}, status=500)


def user_signup(request, User):
    if request.body.decode('utf-8') == '':
        return JsonResponse({'message': 'Invalid credentials'}, status=400)
    try:
        request_data = json.loads(request.body)
        password = request_data.get('password')
        if password:
            hashed_pass = pbkdf2_sha256.encrypt(password, rounds=100, salt_size=32)

        else:
            return JsonResponse({'message': 'Invalid arguments'})
        if not validate_user_email(request_data.get('email')):
            return JsonResponse({'message': 'Invalid email'})
        new_user = User(first_name=request_data.get('first_name'), last_name=request_data.get('last_name'),
                        phone_number=request_data.get('phone_number'), email=request_data.get('email'),
                        password=hashed_pass,
                        usertype=request_data.get('usertype')
                        )
        new_user.save()
        return JsonResponse({'message': 'user added'})
    except IntegrityError as e:
        return JsonResponse({'message': e.args[1]}, status=400)
    except:
        return JsonResponse({'message': 'Signup not working'}, status=500)


def add_new_project(Projects, request_data, User, Task):
    try:
        new_project = Projects(name=request_data.get('name'))
        new_project.save()
        if request_data.get('tasks'):
            add_all_tasks(request_data['tasks'], User, Task, new_project)
    except IntegrityError as e:
        return JsonResponse({'message': 'Invalid arguments'}, status=400)
    except:
        return JsonResponse({'message': 'Project cannot be added'}, status=500)
    return JsonResponse({'message': 'project added'})


def add_task(Projects, request_data, User, Task):
    try:
        project_data = Projects.objects.get(id=int(request_data['project']))
        add_all_tasks(request_data['tasks'], User, Task, project_data)
    except IntegrityError as e:
        return JsonResponse({'message': 'Invalid arguments'}, status=400)
    except:
        return JsonResponse({'message': 'Task cannot be added'}, status=500)
    return JsonResponse({'message': 'project added'})


def add_all_tasks(tasks, User, Task, project_data):
    try:
        for task in tasks:
            user_data = User.objects.get(id=task['assigned_to'])
            new_task = Task(name=task.get('name'), assigned_to=user_data, project=project_data, status="Not started")
            new_task.save()
    except:
        return JsonResponse({'message': 'Task cannot be added'}, status=500)


def update_all_tasks(tasks, User, Task, project_data, response):
    try:
        for task in tasks:
            if Task.objects.filter(id=task.get('id')).first():
                task_status = task.get('status')
                if task_status:
                    if task_status == 'not completed' and response['user_type'] == 'manager':
                        Task.objects.filter(id=task.get('id')).update(status=task_status)
                    elif response['user_type'] == 'developer':
                        # if task.get('id')
                        Task.objects.filter(id=task.get('id')).update(status=task_status)
                    else:
                        return JsonResponse({'message': 'Un Authorized task'}, status=401)

                else:
                    if response['user_type'] == 'admin':
                        user_data = User.objects.get(id=task['assigned_to'])
                        Task.objects.filter(id=task.get('id')).update(name=task.get('name'), assigned_to=user_data,
                                                                      project=project_data)
                    else:
                        return JsonResponse({'message': 'Un Authorized task'}, status=401)
        return JsonResponse({'message': 'task_updated'})
    except:
        return JsonResponse({'message': 'Task cannot be updated'}, status=500)


def all_project_data(request, Projects):
    try:
        request_data = dict(request.GET)
        project_details = Projects.objects.get(id=request_data['project_id'][0])
        response_data = {'project_name': project_details.name, 'tasks': list(project_details.task_set.all().values())}
        return JsonResponse(response_data)
    except:
        return JsonResponse({'message': 'No project found'}, status=400)


def update_task(Projects, request_data, User, Task, response):
    try:
        project_data = Projects.objects.get(id=int(request_data['project']))
        response = update_all_tasks(request_data['tasks'], User, Task, project_data, response)
    except IntegrityError as e:
        return JsonResponse({'message': 'Invalid arguments'}, status=400)
    except:
        return JsonResponse({'message': 'Task cannot be updated'}, status=500)
    return response


def get_task_details(request, Projects, User, Task):
    response = authenticate_user(request.META['HTTP_AUTHORIZATION'])
    if response.get('error'):
        final_response = JsonResponse(response, status=401)
    elif request.body.decode('utf-8') == '':
        final_response = JsonResponse({'message': 'Invalid credentials'}, status=400)
    elif request.method == 'POST':
        if response['user_type'] == 'manager':
            request_data = json.loads(request.body)
            final_response = add_task(Projects, request_data, User, Task)
        else:
            final_response = JsonResponse({'message': 'Unauthorized user'}, status=401)
    elif request.method == 'PUT':
        request_data = json.loads(request.body)
        final_response = update_task(Projects, request_data, User, Task, response)
    else:
        final_response = JsonResponse({'error': 'This method is not supported'})
    return final_response
