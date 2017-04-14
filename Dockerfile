FROM python:onbuild
ENTRYPOINT gunicorn -b 0.0.0.0:80 yo:app
EXPOSE 80
