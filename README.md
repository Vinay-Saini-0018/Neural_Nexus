How to run :
s1 : pip install -r requirements.txt
s2 :  terminal 1 -> uvicorn main:app --reload     this will run on 3000 port
s3 : terminal 2 -> python -m http.server 8000   then in chrome localhost:8000/frontend/index.html