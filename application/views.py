import json
from .db_service import login_func, user_signup, add_new_project, all_project_data, add_task, update_task, \
    get_task_details
from .models import User, Projects, Task
from django.views.decorators.csrf import csrf_exempt
from .auth import authenticate_user
from django.http import JsonResponse


@csrf_exempt
def login(request):
    if request.body.decode('utf-8') == '':
        return JsonResponse({'message': 'Invalid credentials'}, status=400)
    request_data = json.loads(request.body)
    return login_func(User, request_data)


@csrf_exempt
def signup(request):
    return user_signup(request, User)


@csrf_exempt
def project(request):
    if request.body.decode('utf-8') == '':
        return JsonResponse({'message': 'Invalid credentials'}, status=400)
    if request.method == 'POST':
        request_data = json.loads(request.body)
        return add_new_project(Projects, request_data, User, Task)
    else:
        return all_project_data(request, Projects)


@csrf_exempt
def tasks(request):
    return get_task_details(request, Projects, User, Task)
